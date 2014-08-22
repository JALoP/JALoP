/**
 * @file jaldb_purge.cpp This file implements the DB purge functions.
 *
 * @section LICENSE
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
#include "jal_asprintf_internal.h"
#include "jal_alloc.h"
#include "jaldb_record.h"
#include "jaldb_record_dbs.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
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

enum jaldb_status jaldb_purge_log_by_nonce(jaldb_context *ctx,
					const char *nonce,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_log_by_uuid(jaldb_context *ctx,
					const char *uuid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_audit_by_nonce(jaldb_context *ctx,
					const char *nonce,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_audit_by_uuid(jaldb_context *ctx,
					const char *uuid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_journal_by_nonce(jaldb_context *ctx,
					const char *nonce,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_journal_by_uuid(jaldb_context *ctx,
					const char *uuid,
					list<jaldb_doc_info> &docs,
					int force,
					int del)
{
	return JALDB_E_NOT_IMPL;
}
