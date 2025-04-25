/**
 * @file
 *
 * @brief This file implements the DB purge functions.
 *
 * ### LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <list>
#include <string.h>
#include <map>
#include "jal_asprintf_internal.h"
#include "jal_alloc.h"
#include "jaldb_record.h"
#include "jaldb_record_dbs.h"
#include "jaldb_serialize_record.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_segment.h"
#include "jaldb_utils.h"
#include "jaldb_context.hpp"
#include "jaldb_purge.hpp"

using namespace std;

enum jaldb_status jaldb_purge_unconfirmed_records(
		jaldb_context *ctx,
		const char *remote_host,
		enum jaldb_rec_type rtype)
{
	int db_ret = 0;
	jaldb_record_dbs *rdbs = NULL;
	DB_TXN *txn = NULL;
	enum jaldb_status ret = JALDB_E_UNKNOWN;

	if (!ctx || !remote_host ||
			0 == strcmp(remote_host, "localhost") ||
			0 == strcmp(remote_host, "127.0.0.1")) {
		return JALDB_E_INVAL;
	}

	db_ret = jaldb_get_primary_record_dbs(ctx,rtype,&rdbs);
	if (0 != db_ret) {
		return JALDB_E_INVAL;
	}

	if (!rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	DBT key;
	memset(&key, 0, sizeof(DBT));
	key.size = sizeof(int);
	key.data = jal_malloc(sizeof(int));
	*((int*)key.data) = 0;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		// If a secondary index supports duplicates, one delete will delete all records with that value
		db_ret = rdbs->record_confirmed_db->del(rdbs->record_confirmed_db, txn, &key, 0);
		if (0 == db_ret) {
			txn->commit(txn,0);
			break;
		}
		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			// If there weren't any unconfirmed records, we're good
			ret = JALDB_OK;
			goto out;
		}
		ret = JALDB_E_DB;
		goto out;

	}
	ret = JALDB_OK;
out:
	free(key.data);
	return ret;
}

enum jaldb_status jaldb_iterate_by_timestamp_purge(
	jaldb_context *ctx,
	 enum jaldb_rec_type type,
	const char *timestamp,
	jaldb_iter_cb cb,
	void *up, int& exiting)
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
	std::map<std::string, std::string> purge_map;
	char *path = NULL;

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

			// mktime() like to set things like timezone to system timezone -
			// need to clean out the tm struct before each call
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
				if (JALDB_RTYPE_JOURNAL == type) {
					jaldb_segment *segment = rec->payload;
					if (segment && segment->on_disk) {
						jal_asprintf(&path, "%s/%s", ctx->journal_root, (char*)segment->payload);
					}
				}
				// Insert record nonce and payload path into purge map.
				if (path) {
					purge_map[std::string((const char*)(pkey.data))] = std::string((const char*)(path));
					free(path);
					path = NULL;
				} else {
					purge_map[std::string((const char*)(pkey.data))] = std::string("");
				}
				break;
			default:
					goto out;
			}

			jaldb_destroy_record(&rec);

	if (exiting) {
		break;
	}
}

out:
	if (cursor) {
			cursor->c_close(cursor);
	}
	cursor = NULL;

		// Remove records that are in the purge_map.
	std::map<std::string, std::string>::iterator iter;
	for (iter = purge_map.begin(); iter != purge_map.end(); iter++) {
		if (exiting) {
			break;
		}

		ret = jaldb_remove_record(ctx, type, (char*)iter->first.c_str());
		if (JALDB_OK == ret) {
			// Remove any on-disk payload file.
			std::string currPath = iter->second;
			if (!currPath.empty() && 0 < currPath.length()) {
				unlink((char*)currPath.c_str());
			}
			fprintf(stdout, "NONCE: %s Deleted\n", iter->first.c_str());
		} else {
			fprintf(stderr, "ERROR: failed to remove record: %s\n", iter->first.c_str());
		}
	}

	jaldb_destroy_record(&rec);

	free(key.data);
	free(val.data);
	purge_map.clear();
	return ret;
}

enum jaldb_status jaldb_purge_log_by_nonce(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *nonce,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_log_by_uuid(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *uuid,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_audit_by_nonce(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *nonce,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_audit_by_uuid(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *uuid,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_journal_by_nonce(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *nonce,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_journal_by_uuid(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *uuid,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}
