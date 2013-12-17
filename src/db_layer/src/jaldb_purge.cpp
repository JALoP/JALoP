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
	u_int32_t db_flags = DB_THREAD | DB_CREATE | DB_AUTO_COMMIT;
	jaldb_record_dbs *rdbs = NULL;
	char *filename = NULL;
	DB *temp_handle = NULL;

	if (!ctx || !remote_host ||
			0 == strcmp(remote_host, "localhost") ||
			0 == strcmp(remote_host, "127.0.0.1")) {
		return JALDB_E_INVAL;
	}

	switch (rtype) {
	case JALDB_RTYPE_JOURNAL:
		jal_asprintf(&filename, "%s_%s", remote_host, "journal");
		break;
	case JALDB_RTYPE_AUDIT:
		jal_asprintf(&filename, "%s_%s", remote_host, "audit");
		break;
	case JALDB_RTYPE_LOG:
		jal_asprintf(&filename, "%s_%s", remote_host, "log");
		break;
	default:
		return JALDB_E_INVAL;
	}

	db_ret = jaldb_get_dbs(ctx,remote_host,rtype,&rdbs);
	if (0 != db_ret) {
		return JALDB_E_INVAL;
	}

	if (!rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	db_ret = rdbs->primary_db->close(rdbs->primary_db, 0);
	if (0 != db_ret) {
		return JALDB_E_DB;
	}

	/* Need to re-create handle after calling close or remove */
	db_ret = db_create(&temp_handle, NULL, 0);
	if (0 != db_ret) {
		return JALDB_E_INVAL;
	}

	db_ret = temp_handle->remove(temp_handle, filename, "primary", 0);
	if ((0 != db_ret) && (2 != db_ret)) {
		return JALDB_E_DB;
	}

	db_ret = jaldb_open_dbs_for_temp(ctx, remote_host, rtype, rdbs, db_flags);
	if (0 != db_ret) {
		return JALDB_E_INVAL;
	}

	free(filename);
	return JALDB_OK;

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
