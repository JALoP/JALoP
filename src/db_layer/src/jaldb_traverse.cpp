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

#include <openssl/bn.h>
#include <db.h>
#include <string.h>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#include "jaldb_context.hpp"
#include "jaldb_record_dbs.h"
#include "jaldb_serialize_record.h"
#include "jaldb_traverse.h"
#include "jaldb_utils.h"

enum jaldb_status jaldb_iterate_by_sid_range(jaldb_context *ctx,
		enum jaldb_rec_type type,
		const char *hex_start_sid,
		const char *hex_end_sid,
		jaldb_iter_cb cb, void *up)
{
	return JALDB_E_NOT_IMPL;
}
/*
enum jaldb_status jaldb_iterate_by_sid_range(jaldb_context *ctx,
		enum jaldb_rec_type type,
		const char *hex_start_sid,
		const char *hex_end_sid,
		jaldb_iter_cb cb, void *up)
{

	enum jaldb_status ret = JALDB_E_INVAL;
	char *current_sid_hex = NULL;
	struct jaldb_record *rec = NULL;
	int byte_swap;
	BIGNUM *current_sid = NULL;
	BIGNUM *zero = NULL;
	BIGNUM *end_sid = NULL;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	char keep_going = 1;
	DBT key;
	DBT val;
	DBT empty_val;
	DBC *cursor = NULL;
	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));
	memset(&empty_val, 0, sizeof(empty_val));
	key.flags = DB_DBT_REALLOC;
	val.flags = DB_DBT_REALLOC;
	empty_val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;

	if (!ctx || !cb) {
		ret = JALDB_E_INVAL;
		goto out;
	}
	zero = BN_new();
	BN_zero(zero);

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
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (hex_start_sid) {
		db_ret = BN_hex2bn(&current_sid, hex_start_sid);
		if ((0 == db_ret) || (NULL == current_sid)) {
			ret = JALDB_E_INVAL;
			goto out;
		}
		if (0 == BN_cmp(zero, current_sid)) {
			key.size = 1;
			key.data = jal_malloc(key.size);
			*((char*)(key.data)) = 0;
		} else {
			key.size = BN_num_bytes(current_sid);
			key.data = jal_malloc(key.size);
			BN_bn2bin(current_sid, (unsigned char*)key.data);
		}
		BN_free(current_sid);
		current_sid = NULL;
	}

	if (hex_end_sid) {
		db_ret = BN_hex2bn(&end_sid, hex_end_sid);
		if ((0 == db_ret) || (NULL == end_sid)) {
			ret = JALDB_E_INVAL;
			goto out;
		}
	}

	db_ret = rdbs->primary_db->cursor(rdbs->primary_db, NULL, &cursor, DB_DEGREE_2);
	if (0 != db_ret) {
		JALDB_DB_ERR(rdbs->primary_db, db_ret);
		goto out;
	}

	if (key.data) {
		db_ret = cursor->c_get(cursor, &key, &val, DB_SET_RANGE);
	} else {
		db_ret = cursor->c_get(cursor, &key, &val, DB_FIRST);
	}

	while(keep_going && (0 == db_ret)) {
		current_sid = BN_bin2bn((unsigned char*)key.data, key.size, NULL);
		if (NULL == current_sid) {
			ret = JALDB_E_NO_MEM;
			goto out;
		}

		// current_sid is > end_sid, so break out
		if (end_sid && (1 == BN_cmp(current_sid, end_sid))) {
			goto out;
		}

		current_sid_hex = BN_bn2hex(current_sid);
		if (NULL == current_sid_hex) {
			ret = JALDB_E_NO_MEM;
			goto out;
		}

		ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
		if (ret != JALDB_OK) {
			goto out;
		}

		// get the key for the next element.
		db_ret = cursor->c_get(cursor, &key, &empty_val, DB_NEXT);
		if (0 != db_ret) {
			keep_going = 0;
			if (DB_NOTFOUND == db_ret) {
				ret = JALDB_OK;
			} else {
				JALDB_DB_ERR(rdbs->primary_db, db_ret);
			}
		}
		cursor->c_close(cursor);
		cursor = NULL;

		// execute callback, figure out what to do next.
		switch (cb(current_sid_hex, rec, up)) {
		case JALDB_ITER_CONT:
			break;
		case JALDB_ITER_REM:
			ret = jaldb_remove_record(ctx, type, current_sid_hex);
			if (JALDB_OK == ret) {
				ret = jaldb_remove_segments_from_disk(ctx, rec);
			}
			if (ret != JALDB_OK) {
				// something went wrong...
				goto out;
			}
			break;
		default:
			goto out;
		}

		// current_sid == end_sid, so stop processing
		if (end_sid && (0 == BN_cmp(current_sid, end_sid))) {
			goto out;
		}

		free(current_sid_hex);
		current_sid_hex = NULL;

		BN_free(current_sid);
		current_sid = NULL;

		jaldb_destroy_record(&rec);

		db_ret = rdbs->primary_db->cursor(rdbs->primary_db, NULL, &cursor, DB_DEGREE_2);
		if (0 != db_ret) {
			JALDB_DB_ERR(rdbs->primary_db, db_ret);
			goto out;
		}
		db_ret = cursor->c_get(cursor, &key, &val, DB_SET_RANGE);
	}

out:
	if (cursor) {
		cursor->c_close(cursor);
	}

	jaldb_destroy_record(&rec);
	if (current_sid) {
		BN_free(current_sid);
		current_sid = NULL;
	}

	if (zero) {
		BN_free(zero);
	}
	if (end_sid) {
		BN_free(end_sid);
		end_sid = NULL;
	}
	free(current_sid_hex);
	free(key.data);
	free(val.data);
	free(empty_val.data);
	return ret;
}

*/
