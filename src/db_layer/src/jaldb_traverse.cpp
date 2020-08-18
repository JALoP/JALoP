/**
 * @file jaldb_traverse.cpp This file defines functions for traversing
 * the records in the database.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2013 Tresys Technology LLC, Columbia, Maryland, USA
 *
 * This software was developed by Tresys Technology LLC
 * with U.S. Government sponsorship.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <db.h>
#include <string.h>
#include <string>
#include <list>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#include "jaldb_context.hpp"
#include "jaldb_record_dbs.h"
#include "jaldb_serialize_record.h"
#include "jaldb_traverse.h"
#include "jaldb_utils.h"

using namespace std;

enum jaldb_status jaldb_iterate_by_timestamp(jaldb_context *ctx,
		enum jaldb_rec_type type,
		const char *timestamp,
		jaldb_iter_cb cb, void *up)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	struct tm target_time, record_time;
	memset(&target_time, 0, sizeof(target_time));
	memset(&record_time, 0, sizeof(record_time));
	int target_ms = 0;
	int record_ms = 0;
	char *tmp_time = NULL;
	struct jaldb_record *rec = NULL;
	int byte_swap = 0;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret = 0;
	DBT key;
	DBT pkey;
	DBT val;
	DBC *cursor = NULL;
	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	key.flags = DB_DBT_REALLOC;
	val.flags = DB_DBT_REALLOC;
	time_t target_secs = 0;

	tmp_time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S", &target_time);
	if (!tmp_time) {
		fprintf(stderr, "ERROR: Invalid time format specified.\n");
		ret = JALDB_E_INVAL_TIMESTAMP;
		goto out;
	}

	if (!sscanf(tmp_time,".%d-%*d:%*d", &target_ms)) {
		fprintf(stderr, "ERROR: Invalid time format specified.\n");
		ret = JALDB_E_INVAL_TIMESTAMP;
		goto out;
	}
	// Calculate the target time in secs once before we start looping
	target_secs = mktime(&target_time);

	if (!ctx || !cb) {
		ret = JALDB_E_UNINITIALIZED;
		goto out;
	}

	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		ret = JALDB_E_INVAL_RECORD_TYPE;
		goto out;
	}

	if (!rdbs) {
		ret = JALDB_E_UNINITIALIZED;
		goto out;
	}

	// Use the record creation time database
	db_ret = rdbs->timestamp_idx_db->get_byteswapped(rdbs->timestamp_idx_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->timestamp_idx_db->cursor(rdbs->timestamp_idx_db, NULL, &cursor, DB_DEGREE_2);
	if (0 != db_ret) {
		JALDB_DB_ERR(rdbs->timestamp_idx_db, db_ret);
		ret = JALDB_E_INVAL;
		goto out;
	}

	while(0 == db_ret) {
		db_ret = cursor->c_pget(cursor, &key, &pkey, &val, DB_NEXT);
		if (0 != db_ret) {
			if (DB_NOTFOUND == db_ret) {
				ret = JALDB_OK;
			} else {
				JALDB_DB_ERR(rdbs->timestamp_idx_db, db_ret);
				ret = JALDB_E_INVAL;
			}
			goto out;
		}

		// mktime() like to set things like timezone to system timezone - need to clean out the tm struct before each call
		memset(&record_time, 0, sizeof(record_time));

		tmp_time = strptime((char*) key.data, "%Y-%m-%dT%H:%M:%S", &record_time);
		if (!tmp_time) {
			fprintf(stderr, "ERROR: Cannot get strptime from record\n");
			ret = JALDB_E_INVAL_TIMESTAMP;
			goto out;
		}

		if (!sscanf(tmp_time,".%d-%*d:%*d", &record_ms)) {
			ret = JALDB_E_INVAL_TIMESTAMP;
			goto out;
		}

		double delta = difftime(target_secs,mktime(&record_time));
		if (delta < 0) {
			// record_time is > target_time, so break out
			goto out; 
		}
		
		if (delta == 0) {
			if (record_ms > target_ms) {
				goto out;
			}
		}

		ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
		if (ret != JALDB_OK) {
			goto out;
		}

		switch (cb((char*) pkey.data, rec, up)) {
		case JALDB_ITER_CONT:
			break;
		case JALDB_ITER_REM:
			// Need to close cursor before removing record
			cursor->c_close(cursor);
			cursor = NULL;

			ret = jaldb_remove_record(ctx, type, (char*) pkey.data);
			if (JALDB_OK == ret) {
				ret = jaldb_remove_segments_from_disk(ctx, rec);
			}
			if (ret != JALDB_OK) {
				// something went wrong...
				goto out;
			}

			db_ret = rdbs->timestamp_idx_db->cursor(rdbs->timestamp_idx_db, NULL, &cursor, DB_DEGREE_2);
			if (0 != db_ret) {
				JALDB_DB_ERR(rdbs->timestamp_idx_db, db_ret);
				ret = JALDB_E_INVAL;
				goto out;
			}
			break;
		default:
			goto out;
		}

		jaldb_destroy_record(&rec);
	}

out:
	if (cursor) {
		cursor->c_close(cursor);
	}

	jaldb_destroy_record(&rec);

	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_iterate_by_timestamp2(jaldb_context *ctx,
		enum jaldb_rec_type type,
		const char *timestamp,
		jaldb_iter_cb cb, void *up)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	struct tm target_time, record_time;
	memset(&target_time, 0, sizeof(target_time));
	memset(&record_time, 0, sizeof(record_time));
	int target_ms = 0;
	int record_ms = 0;
	char *tmp_time = NULL;
	struct jaldb_record *rec = NULL;
	int byte_swap = 0;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret = 0;
	DBT key;
	DBT pkey;
	DBT val;
	DBC *cursor = NULL;
	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	key.flags = DB_DBT_REALLOC;
	val.flags = DB_DBT_REALLOC;
	time_t target_secs = 0;
	list<string> purge_nonce_list;

	tmp_time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S", &target_time);
	if (!tmp_time) {
		fprintf(stderr, "ERROR: Invalid time format specified.\n");
		ret = JALDB_E_INVAL_TIMESTAMP;
		goto out;
	}

	if (!sscanf(tmp_time,".%d-%*d:%*d", &target_ms)) {
		fprintf(stderr, "ERROR: Invalid time format specified.\n");
		ret = JALDB_E_INVAL_TIMESTAMP;
		goto out;
	}
	// Calculate the target time in secs once before we start looping
	target_secs = mktime(&target_time);

	if (!ctx || !cb) {
		ret = JALDB_E_UNINITIALIZED;
		goto out;
	}

	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		ret = JALDB_E_INVAL_RECORD_TYPE;
		goto out;
	}

	if (!rdbs) {
		ret = JALDB_E_UNINITIALIZED;
		goto out;
	}

	// Use the record creation time database
	db_ret = rdbs->timestamp_idx_db->get_byteswapped(rdbs->timestamp_idx_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->timestamp_idx_db->cursor(rdbs->timestamp_idx_db, NULL, &cursor, DB_DEGREE_2);
	if (0 != db_ret) {
		JALDB_DB_ERR(rdbs->timestamp_idx_db, db_ret);
		ret = JALDB_E_INVAL;
		goto out;
	}

	while(0 == db_ret) {
		db_ret = cursor->c_pget(cursor, &key, &pkey, &val, DB_NEXT);
		if (0 != db_ret) {
			if (DB_NOTFOUND == db_ret) {
				ret = JALDB_OK;
			} else {
				JALDB_DB_ERR(rdbs->timestamp_idx_db, db_ret);
				ret = JALDB_E_INVAL;
			}
			goto out;
		}

		// mktime() like to set things like timezone to system timezone - need to clean out the tm struct before each call
		memset(&record_time, 0, sizeof(record_time));

		tmp_time = strptime((char*) key.data, "%Y-%m-%dT%H:%M:%S", &record_time);
		if (!tmp_time) {
			fprintf(stderr, "ERROR: Cannot get strptime from record\n");
			ret = JALDB_E_INVAL_TIMESTAMP;
			goto out;
		}

		if (!sscanf(tmp_time,".%d-%*d:%*d", &record_ms)) {
			ret = JALDB_E_INVAL_TIMESTAMP;
			goto out;
		}

		double delta = difftime(target_secs,mktime(&record_time));
		if (delta < 0) {
			// record_time is > target_time, so break out
			goto out; 
		}
		
		if (delta == 0) {
			if (record_ms > target_ms) {
				goto out;
			}
		}

		ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
		if (ret != JALDB_OK) {
			goto out;
		}

		switch (cb((char*) pkey.data, rec, up)) {
		case JALDB_ITER_CONT:
			break;
		case JALDB_ITER_REM:
			purge_nonce_list.push_back(string((const char*)(pkey.data)));
			break;
		default:
			goto out;
		}

		jaldb_destroy_record(&rec);
	}

out:
	if (cursor) {
		cursor->c_close(cursor);
	}
	cursor = NULL;

	// Remove records that are in the purge_nonce_list.
	if (!purge_nonce_list.empty()) {
		list<string>::iterator iter;
		for (iter = purge_nonce_list.begin(); iter != purge_nonce_list.end(); iter++) {
			ret = jaldb_remove_record(ctx, type, (char*)iter->c_str());
			if (JALDB_OK == ret) {
				fprintf(stdout, "NONCE: %s Deleted\n", iter->c_str());
			} else {
				fprintf(stderr, "ERROR: failed to remove record: %s\n", iter->c_str());
			}
		}
	}

	jaldb_destroy_record(&rec);

	free(key.data);
	free(val.data);
	purge_nonce_list.clear();
	return ret;
}
