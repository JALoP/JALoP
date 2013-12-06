/**
 * @file jaldb_context.cpp This file implements the DB context management
 * functions.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#define __STDC_FORMAT_MACROS

#include <fcntl.h>
#include <jalop/jal_status.h>
#include <inttypes.h> // For PRIu64
#include <list>
#include <openssl/bn.h>
#include <sstream>
#include <string.h>
#include <sys/stat.h>

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"
#include "jal_asprintf_internal.h"

#include "jaldb_context.hpp"
#include "jaldb_record.h"
#include "jaldb_record_dbs.h"
#include "jaldb_record_xml.h"
#include "jaldb_segment.h"
#include "jaldb_serialize_record.h"
#include "jaldb_serial_id.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"

using namespace std;

#define DEFAULT_DB_ROOT "/var/lib/jalop/db"
#define DEFAULT_SCHEMAS_ROOT "/usr/local/share/jalop-v1.0/schemas"

static void jaldb_destroy_string_to_rdbs_map(string_to_rdbs_map *temp);
static enum jaldb_status jaldb_remove_record_from_db(jaldb_context *ctx, jaldb_record_dbs *rdbs, char *hex_sid);

jaldb_context *jaldb_context_create()
{
	jaldb_context *context = (jaldb_context *)jal_calloc(1, sizeof(*context));
	return context;
}

enum jaldb_status jaldb_context_init(
	jaldb_context *ctx,
	const char *db_root,
	const char *schemas_root,
	int db_rdonly_flag)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}

	// Make certain that the context is not already initialized.
	if (ctx->env || ctx->journal_root || ctx->schemas_root) {
		return JALDB_E_INITIALIZED;
	}

	if (!db_root) {
		db_root = DEFAULT_DB_ROOT;
	}

	if (!schemas_root) {
		schemas_root = DEFAULT_SCHEMAS_ROOT;
	}
	ctx->schemas_root = jal_strdup(schemas_root);

	if (-1 == jal_asprintf(&ctx->journal_root, "%s%s", db_root, JALDB_JOURNAL_ROOT_NAME)) {
		return JALDB_E_NO_MEM;
	}

	// set readonly flag if specified
	ctx->db_read_only = db_rdonly_flag;

	uint32_t env_flags = DB_CREATE |
		DB_INIT_LOCK |
		DB_INIT_LOG |
		DB_INIT_MPOOL |
		DB_INIT_TXN |
		DB_THREAD;

	DB_ENV *env = NULL;
	int db_err = db_env_create(&env, 0);
	if (0 != db_err) {
		return JALDB_E_INVAL;
	}

	db_err = env->set_lk_detect(env, DB_LOCK_DEFAULT);
	if (0 != db_err) {
		return JALDB_E_INVAL;
	}
	db_err = env->set_flags(env, DB_TXN_NOSYNC, 1);
	if (0 != db_err) {
		return JALDB_E_INVAL;
	}

	db_err = env->open(env, db_root, env_flags, 0);
	if (0 != db_err) {
		return JALDB_E_INVAL;
	}

	DB_TXN *db_txn = NULL;

	db_err = env->txn_begin(env, NULL, &db_txn, DB_DIRTY_READ);
	if (db_err != 0) {
		return JALDB_E_INVAL;
	}

	uint32_t db_flags = DB_THREAD;
	if (db_rdonly_flag) {
		db_flags |= DB_RDONLY;
	} else {
		db_flags |= DB_CREATE;
	}
	enum jaldb_status ret;
	ret = jaldb_create_primary_dbs_with_indices(env, db_txn, "log", db_flags, &ctx->log_dbs);
	if (ret != JALDB_OK) {
		db_txn->abort(db_txn);
		return JALDB_E_INVAL;
	}

	ret = jaldb_create_primary_dbs_with_indices(env, db_txn, "audit", db_flags, &ctx->audit_dbs);
	if (ret != JALDB_OK) {
		db_txn->abort(db_txn);
		return JALDB_E_INVAL;
	}

	ret = jaldb_create_primary_dbs_with_indices(env, db_txn, "journal", db_flags, &ctx->journal_dbs);
	if (ret != JALDB_OK) {
		db_txn->abort(db_txn);
		return JALDB_E_INVAL;
	}

	if (!ctx->db_read_only) {
		db_err = jaldb_initialize_serial_id(ctx->journal_dbs->sid_db, db_txn);
		if (0 != db_err) {
			db_txn->abort(db_txn);
			return JALDB_E_INVAL;
		}
		db_err = jaldb_initialize_serial_id(ctx->audit_dbs->sid_db, db_txn);
		if (0 != db_err) {
			db_txn->abort(db_txn);
			return JALDB_E_INVAL;
		}
		db_err = jaldb_initialize_serial_id(ctx->log_dbs->sid_db, db_txn);
		if (0 != db_err) {
			db_txn->abort(db_txn);
			return JALDB_E_INVAL;
		}

	}


	db_err = db_create(&ctx->journal_conf_db, env, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->journal_conf_db), db_err);
		return JALDB_E_DB;
	}
	db_err = ctx->journal_conf_db->open(ctx->journal_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_JOURNAL_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->journal_conf_db), db_err);
		return JALDB_E_DB;
	}

	db_err = db_create(&ctx->audit_conf_db, env, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->audit_conf_db), db_err);
		return JALDB_E_DB;
	}
	db_err = ctx->audit_conf_db->open(ctx->audit_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_AUDIT_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->audit_conf_db), db_err);
		return JALDB_E_DB;
	}

	db_err = db_create(&ctx->log_conf_db, env, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);;
		JALDB_DB_ERR((ctx->log_conf_db), db_err);
		return JALDB_E_DB;
	}
	db_err = ctx->log_conf_db->open(ctx->log_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_LOG_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);;
		JALDB_DB_ERR((ctx->log_conf_db), db_err);
		return JALDB_E_DB;
	}

	db_txn->commit(db_txn, 0);
	ctx->env = env;

	ctx->journal_temp_dbs = new string_to_rdbs_map;
	ctx->audit_temp_dbs = new string_to_rdbs_map;
	ctx->log_temp_dbs = new string_to_rdbs_map;

	ctx->seen_journal_records = new std::set<string>();
	ctx->seen_audit_records = new std::set<string>();
	ctx->seen_log_records = new std::set<string>();

	return JALDB_OK;
}

void jaldb_context_destroy(jaldb_context **ctx)
{
	if (!ctx || !(*ctx)) {
		return;
	}
	jaldb_context *ctxp = *ctx;

	free(ctxp->journal_root);
	free(ctxp->schemas_root);

	if (ctxp->journal_conf_db) {
		(*ctx)->journal_conf_db->close((*ctx)->journal_conf_db, 0);
	}

	if (ctxp->audit_conf_db) {
		(*ctx)->audit_conf_db->close((*ctx)->audit_conf_db, 0);
	}

	if (ctxp->log_conf_db) {
		(*ctx)->log_conf_db->close((*ctx)->log_conf_db, 0);
	}

	jaldb_destroy_record_dbs(&(ctxp->journal_dbs));
	jaldb_destroy_record_dbs(&(ctxp->audit_dbs));
	jaldb_destroy_record_dbs(&(ctxp->log_dbs));

	jaldb_destroy_string_to_rdbs_map(ctxp->journal_temp_dbs);
	jaldb_destroy_string_to_rdbs_map(ctxp->audit_temp_dbs);
	jaldb_destroy_string_to_rdbs_map(ctxp->log_temp_dbs);

	delete ctxp->seen_journal_records;
	delete ctxp->seen_audit_records;
	delete ctxp->seen_log_records;

	if (ctxp->env) {
		ctxp->env->close(ctxp->env, 0);
	}
	ctxp->env = NULL;
	free(ctxp);
	*ctx = NULL;
}

static void jaldb_destroy_string_to_rdbs_map(string_to_rdbs_map *temp)
{
	if (temp) {
		for (string_to_rdbs_map::iterator iter = temp->begin();
				iter != temp->end();
				iter++) {
			jaldb_destroy_record_dbs(&(iter->second));
		}
		free(temp);
	}
}

std::string jaldb_make_temp_db_name(const string &id, const string &suffix)
{
	stringstream o;
	o << "__" << id << "_" << suffix;
	return o.str();
}

enum jaldb_status jaldb_xfer_audit(
	jaldb_context *ctx,
	std::string &source,
	const std::string &sid,
	std::string &next_sid)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_insert_audit_record_into_temp(
	jaldb_context *ctx,
	std::string &source,
	const void *sys_doc,
	const void *app_doc,
	const void *audit_doc,
	const std::string &sid)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_xfer_log(
	jaldb_context *ctx,
	std::string &source,
	const std::string &sid,
	std::string &next_sid)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_insert_log_record_into_temp(
	jaldb_context *ctx,
	string &source,
	const void *sys_meta_doc,
	const void *app_meta_doc,
	uint8_t *log_buf,
	const size_t log_len,
	const string &sid,
	int *db_err)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_xfer_journal(
	jaldb_context *ctx,
	const std::string &source,
	const std::string &sid,
	std::string &next_sid)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_insert_journal_metadata_into_temp(
	jaldb_context *ctx,
	const std::string &source,
	const void *sys_meta_doc,
	const void *app_meta_doc,
	const std::string &path,
	const std::string &sid)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_mark_sent(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *nonce)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;

	struct jaldb_record_dbs *rdbs = NULL;

	int byte_swap;

	struct jaldb_serialize_record_headers *header_ptr = NULL;
	size_t header_bytes = sizeof(jaldb_serialize_record_headers);
	DB_TXN *txn = NULL;
	DBT key;
	DBT val;

	if (!ctx || !type || !nonce) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	switch (type) {
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

	if (!rdbs || !rdbs->record_id_idx_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.flags = DB_DBT_REALLOC;
	key.size = strlen(nonce)+1;
	key.data = jal_malloc(key.size);
	key.data = jal_strdup(nonce);

	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.dlen = header_bytes;
	val.size = header_bytes;
	val.doff = 0;
	val.data = jal_malloc(header_bytes);

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret){
		ret = JALDB_E_INVAL;
		goto out;
	}

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->primary_db->get(rdbs->primary_db, txn, &key, &val, DB_DEGREE_2);
		if (0 == db_ret) {
			header_ptr = (struct jaldb_serialize_record_headers *)val.data;
			if (header_ptr->version != JALDB_DB_LAYOUT_VERSION) {
				txn->abort(txn);
				ret = JALDB_E_INVAL;
				goto out;

			} else if (header_ptr->flags & JALDB_RFLAGS_SENT) {
				txn->abort(txn);
				goto out;

			} else {
				header_ptr->flags |= JALDB_RFLAGS_SENT;
				db_ret = rdbs->primary_db->put(rdbs->primary_db, txn, &key, &val, 0);

				if (0 == db_ret) {
					db_ret = txn->commit(txn, 0);
					if (0 == db_ret) {
						break;
					} else {
						continue;
					}
				}
			}
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}

		/* Something else went wrong... */
		ret = JALDB_E_DB;
		goto out;
	}

out:
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_mark_synced(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *nonce)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;

	struct jaldb_record_dbs *rdbs = NULL;

	int byte_swap;

	struct jaldb_serialize_record_headers *header_ptr = NULL;
	size_t header_bytes = sizeof(jaldb_serialize_record_headers);
	DB_TXN *txn = NULL;
	DBT key;
	DBT val;

	if (!ctx || !type || !nonce) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	switch (type) {
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

	if (!rdbs || !rdbs->record_id_idx_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.flags = DB_DBT_REALLOC;
	key.size = strlen(nonce)+1;
	key.data = jal_malloc(key.size);
	key.data = jal_strdup(nonce);

	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.dlen = header_bytes;
	val.size = header_bytes;
	val.doff = 0;
	val.data = jal_malloc(header_bytes);

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret){
		ret = JALDB_E_INVAL;
		goto out;
	}

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->primary_db->get(rdbs->primary_db, txn, &key, &val, DB_DEGREE_2);
		if (0 == db_ret) {
			header_ptr = (struct jaldb_serialize_record_headers *)val.data;
			if (header_ptr->version != JALDB_DB_LAYOUT_VERSION) {
				txn->abort(txn);
				ret = JALDB_E_INVAL;
				goto out;

			} else if (!(header_ptr->flags & JALDB_RFLAGS_SENT)) {
				txn->abort(txn);
				ret = JALDB_E_INVAL;
				goto out;

			} else if (header_ptr->flags & JALDB_RFLAGS_SYNCED) {
				txn->abort(txn);
				goto out;

			} else {
				header_ptr->flags |= JALDB_RFLAGS_SYNCED;
				db_ret = rdbs->primary_db->put(rdbs->primary_db, txn, &key, &val, 0);

				if (0 == db_ret) {
					db_ret = txn->commit(txn, 0);
					if (0 == db_ret) {
						break;
					} else {
						continue;
					}
				}
			}
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}

		/* Something else went wrong... */
		ret = JALDB_E_DB;
		goto out;
	}

out:
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_store_confed_sid_temp(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		char* source,
		char* sid)
{
	int byte_swap;
	enum jaldb_status ret = JALDB_OK;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DBT key;
	DBT val;
	DB_TXN *txn;

	if (!ctx || !source || !sid) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	db_ret = jaldb_get_dbs(ctx, source, type, &rdbs);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->metadata_db->get_byteswapped(rdbs->metadata_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	val.size = strlen(sid) + 1;
	val.data = jal_strdup(sid);

	key.flags = DB_DBT_REALLOC;
	key.data = jal_strdup(JALDB_LAST_CONFED_SID_NAME);
	key.size = strlen(JALDB_LAST_CONFED_SID_NAME);

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_INVAL;
			break;
		}

		db_ret = rdbs->metadata_db->put(rdbs->metadata_db, txn, &key, &val, 0);

		if (0 == db_ret) {
			db_ret = txn->commit(txn, 0);
		} else {
			ret = JALDB_E_DB;
			txn->abort(txn);
		}
		if (0 == db_ret) {
			break;
		}
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else {
			ret = JALDB_E_DB;
			break;
		}
	}

out:
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_store_confed_journal_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		const char *sid,
		int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_store_confed_audit_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		const char *sid,
		int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_store_confed_log_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		const char *sid,
		int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_last_confed_sid_temp(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *source,
		char **sid)
{
	int byte_swap;
	enum jaldb_status ret = JALDB_OK;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DB_TXN *txn = NULL;
	DBT key;
	DBT val;

	if (!ctx || !source) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	db_ret = jaldb_get_dbs(ctx, source, type, &rdbs);
	if (0 != db_ret || !rdbs || !rdbs->metadata_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.flags = DB_DBT_REALLOC;
	key.data = jal_strdup(JALDB_LAST_CONFED_SID_NAME);
	key.size = strlen(JALDB_LAST_CONFED_SID_NAME);

	db_ret = rdbs->metadata_db->get_byteswapped(rdbs->metadata_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	val.flags = DB_DBT_REALLOC;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->metadata_db->get(rdbs->metadata_db, txn, &key, &val, DB_DEGREE_2);
		if (0 == db_ret) {
			txn->commit(txn, 0);
			break;
		}

		txn->abort(txn);

		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}
		// some other error
		ret = JALDB_E_DB;
		goto out;
	}

	*sid = jal_strdup((char*)val.data);

out:
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_get_last_confed_journal_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		std::string &sid,
		int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_last_confed_audit_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		std::string &sid,
		int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_last_confed_log_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		std::string &sid,
		int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_store_journal_resume(
		jaldb_context *ctx,
		const char *remote_host,
		const char *path,
		uint64_t offset)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_journal_resume(
		jaldb_context *ctx,
		const char *remote_host,
		char **path,
		uint64_t &offset)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_journal_document_list(
	jaldb_context *ctx,
	list<string> **doc_list)
{
	enum jaldb_status ret = JALDB_OK;
	ret = jaldb_get_all_records(ctx, doc_list, JALDB_RTYPE_JOURNAL);
	return ret;
}

enum jaldb_status jaldb_get_audit_document_list(
		jaldb_context *ctx,
		list<string> **doc_list)
{
	enum jaldb_status ret = JALDB_OK;
	ret = jaldb_get_all_records(ctx, doc_list, JALDB_RTYPE_AUDIT);
	return ret;
}

enum jaldb_status jaldb_get_log_document_list(
		jaldb_context *ctx,
		list<string> **doc_list)
{
	enum jaldb_status ret = JALDB_OK;
	ret = jaldb_get_all_records(ctx, doc_list, JALDB_RTYPE_LOG);
	return ret;
}

enum jaldb_status jaldb_get_last_k_records(
		jaldb_context *ctx,
		int k,
		list<string> &nonce_list,
		enum jaldb_rec_type type,
		bool get_all)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;
	struct jaldb_record_dbs *rdbs = NULL;
	int byte_swap;
	DBC *cursor = NULL;
	DBT key;
	DBT val;
	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));
	key.flags = DB_DBT_REALLOC;
	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.doff = 0;
	val.dlen = 0; //Only interested in the key at this point
	char *current_nonce = NULL;
	int count = 0;

	if (!ctx) {
		ret = JALDB_E_INVAL;
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
		return JALDB_E_INVAL;
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

	db_ret = rdbs->primary_db->cursor(rdbs->primary_db, NULL, &cursor, DB_DEGREE_2);
	if (0 != db_ret) {
		JALDB_DB_ERR(rdbs->primary_db, db_ret);
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = cursor->c_get(cursor, &key, &val, DB_LAST);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	while((count < k || get_all) && (0 == db_ret)) {
		current_nonce = jal_strdup((const char*)key.data);
		if (NULL == current_nonce) {
			ret = JALDB_E_NO_MEM;
			goto out;
		}

		nonce_list.push_front(current_nonce);

		free(current_nonce);
		current_nonce = NULL;

		db_ret = cursor->c_get(cursor, &key, &val, DB_PREV);

		if(0 != db_ret) {
			break;
		}

		count++;
	}

out:
	if (cursor) {
		cursor->c_close(cursor);
	}

	if (current_nonce) {
		free(current_nonce);
		current_nonce = NULL;
	}

	free(key.data);
	free(val.data);
	return ret;

}

enum jaldb_status jaldb_get_all_records(
		jaldb_context *ctx,
		list<string> **nonce_list,
		enum jaldb_rec_type type)
{
	if (!ctx || !nonce_list || *nonce_list) {
		return JALDB_E_INVAL;
	}

	enum jaldb_status ret = JALDB_OK;
	*nonce_list = new list<string>;
	ret = jaldb_get_last_k_records(ctx, 0, **nonce_list, type, true);
	return ret;
}

enum jaldb_status jaldb_get_records_since_last_nonce(
		jaldb_context *ctx,
		char *last_nonce,
		list<string> &nonce_list,
		enum jaldb_rec_type type)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;
	struct jaldb_record_dbs *rdbs = NULL;
	int byte_swap;
	DBC *cursor = NULL;
	DBT key;
	DBT val;
	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));
	key.flags = DB_DBT_REALLOC;
	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.doff = 0;
	val.dlen = 0; //Only interested in the key at this point
	char *current_nonce = NULL;

	if (!ctx) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!last_nonce || 0 == strlen(last_nonce)) {
		ret = JALDB_E_INVAL;
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
		return JALDB_E_INVAL;
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

	key.size = strlen(last_nonce)+1;
	key.data = jal_strdup(last_nonce);

	db_ret = rdbs->primary_db->cursor(rdbs->primary_db, NULL, &cursor, DB_DEGREE_2);
	if (0 != db_ret) {
		JALDB_DB_ERR(rdbs->primary_db, db_ret);
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = cursor->c_get(cursor, &key, &val, DB_SET_RANGE);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	while(0 == db_ret) {
		db_ret = cursor->c_get(cursor, &key, &val, DB_NEXT);

		if(0 != db_ret) {
			break;
		}

		current_nonce = jal_strdup((const char *)key.data);
		if (NULL == current_nonce) {
			ret = JALDB_E_NO_MEM;
			goto out;
		}

		nonce_list.push_back(current_nonce);

		free(current_nonce);
		current_nonce = NULL;
	}

out:
	if (cursor) {
		cursor->c_close(cursor);
	}

	free(current_nonce);
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_insert_record(jaldb_context *ctx, struct jaldb_record *rec, char **local_nonce)
{
	int byte_swap;
	enum jaldb_status ret;
	size_t buf_size = 0;
	struct jaldb_record_dbs *rdbs = NULL;
	uint8_t* buffer = NULL;
	int db_ret;
	int update_network_nonce = 0;
	DBT key;
	DBT val;
	DB_TXN *txn;

	if (!ctx || !rec || !local_nonce || *local_nonce) {
		return JALDB_E_INVAL;
	}
	if (!rec->source) {
		rec->source = jal_strdup("localhost");
	}
	if (!rec->network_nonce) {
		update_network_nonce = 1;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));	

	ret = jaldb_record_sanity_check(rec);
	if (ret != JALDB_OK) {
		goto out;
	}

	switch(rec->type) {
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

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			break;
		}

		char *primary_key = jaldb_gen_primary_key(rec->uuid);
		if (NULL == primary_key) {
			ret = JALDB_E_INVAL;
			goto out;
		}

		key.data = primary_key;
		key.size = strlen(primary_key) + 1;
		key.flags = DB_DBT_REALLOC;

		if (update_network_nonce) {
			free(rec->network_nonce);
			rec->network_nonce = jal_strdup(primary_key);
		}

		ret = jaldb_serialize_record(byte_swap, rec, &buffer, &buf_size);
		if (ret != JALDB_OK) {
			goto out;
		}
		val.data = buffer;
		val.size = buf_size;

		db_ret = rdbs->primary_db->put(rdbs->primary_db, txn, &key, &val, DB_NOOVERWRITE);
		if (0 == db_ret) {
			db_ret = txn->commit(txn, 0);
		} else {
			txn->abort(txn);
		}
		if (0 == db_ret) {
			ret = JALDB_OK;
			break;
		}
		if (DB_LOCK_DEADLOCK == db_ret || DB_KEYEXIST == db_ret) {
			free(buffer);
			buffer = NULL;
			continue;
		} else {
			ret = JALDB_E_DB;
			break;
		}
	}

out:
	*local_nonce = jal_strdup((const char *)key.data);
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_insert_record_into_temp(
		jaldb_context *ctx,
		struct jaldb_record *rec,
		char* source,
		char* nonce)
{
	int byte_swap;
	enum jaldb_status ret;
	size_t buf_size = 0;
	struct jaldb_record_dbs *rdbs = NULL;
	uint8_t* buffer = NULL;
	int db_ret;
	DBT key;
	DBT val;
	DB_TXN *txn;

	if (!ctx || !rec) {
		return JALDB_E_INVAL;
	}
	if (!rec->source) {
		rec->source = jal_strdup("localhost");
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	ret = jaldb_record_sanity_check(rec);
	if (ret != JALDB_OK) {
		goto out;
	}

	db_ret = jaldb_get_dbs(ctx, source, rec->type, &rdbs);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	ret = jaldb_serialize_record(byte_swap, rec, &buffer, &buf_size);
	if (ret != JALDB_OK) {
		goto out;
	}
	val.data = buffer;
	val.size = buf_size;

	key.flags = DB_DBT_REALLOC;
	key.data = jal_strdup(nonce);
	key.size = strlen(nonce)+1;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			break;
		}

		db_ret = rdbs->primary_db->put(rdbs->primary_db, txn, &key, &val, 0);

		if (0 == db_ret) {
			db_ret = txn->commit(txn, 0);
		} else {
			txn->abort(txn);
		}
		if (0 == db_ret) {
			ret = JALDB_OK;
			break;
		}
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else {
			ret = JALDB_E_DB;
			break;
		}
	}

out:
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_get_record(jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *nonce,
		struct jaldb_record **recpp)
{
	struct jaldb_record *rec = NULL;
	int byte_swap;
	enum jaldb_status ret;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DB_TXN *txn = NULL;
	DBT key;
	DBT val;

	if (!ctx || !nonce || !recpp || *recpp) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

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

	if (!rdbs || !rdbs->primary_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.flags = DB_DBT_REALLOC;
	key.size = strlen(nonce)+1;
	key.data = jal_strdup(nonce);

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	val.flags = DB_DBT_REALLOC;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->primary_db->get(rdbs->primary_db, txn, &key, &val, DB_DEGREE_2);
		if (0 == db_ret) {
			txn->commit(txn, 0);
			break;
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}
		// some other error
		ret = JALDB_E_DB;
		goto out;
	}
	ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
	if (ret != JALDB_OK) {
		goto out;
	}
	rec->type = type;
	if (!rec->sys_meta) {
		rec->sys_meta = jaldb_create_segment();
		char *doc = NULL;
		size_t doc_len = 0;
		ret = jaldb_record_to_system_metadata_doc(rec, &doc, &doc_len);
		if (ret != JALDB_OK) {
			goto out;
		}
		rec->sys_meta->payload = (uint8_t*)doc;
		rec->sys_meta->length = doc_len;
	}

	*recpp = rec;
	rec = NULL;
	ret = JALDB_OK;
out:
	jaldb_destroy_record(&rec);
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_get_record_from_temp(jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *nonce,
		char *source,
		struct jaldb_record **recpp)
{
	struct jaldb_record *rec = NULL;
	int byte_swap;
	enum jaldb_status ret;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DB_TXN *txn = NULL;
	DBT key;
	DBT val;

	if (!ctx || !nonce || !recpp || *recpp) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	db_ret = jaldb_get_dbs(ctx, source, type, &rdbs);
	if (0 != db_ret || !rdbs || !rdbs->primary_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.flags = DB_DBT_REALLOC;
	key.data = jal_strdup(nonce);
	key.size = strlen(nonce)+1;

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	val.flags = DB_DBT_REALLOC;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->primary_db->get(rdbs->primary_db, txn, &key, &val, DB_DEGREE_2);
		if (0 == db_ret) {
			txn->commit(txn, 0);
			break;
		}

		txn->abort(txn);

		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}
		// some other error
		ret = JALDB_E_DB;
		goto out;
	}
	ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
	if (ret != JALDB_OK) {
		goto out;
	}
	rec->type = type;
	if (!rec->sys_meta) {
		rec->sys_meta = jaldb_create_segment();
		char *doc = NULL;
		size_t doc_len = 0;
		ret = jaldb_record_to_system_metadata_doc(rec, &doc, &doc_len);
		if (ret != JALDB_OK) {
			goto out;
		}
		rec->sys_meta->payload = (uint8_t*)doc;
		rec->sys_meta->length = doc_len;
	}

	*recpp = rec;
	rec = NULL;
	ret = JALDB_OK;
out:
	jaldb_destroy_record(&rec);
	free(key.data);
	free(val.data);
	return ret;
}


enum jaldb_status jaldb_get_record_by_uuid(jaldb_context *ctx,
		enum jaldb_rec_type type,
		uuid_t uuid,
		char **nonce,
		struct jaldb_record **recpp)
{
	struct jaldb_record *rec = NULL;
	int byte_swap;
	enum jaldb_status ret;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DB_TXN *txn = NULL;
	DBT key;
	DBT pkey;
	DBT val;

	if (!ctx || !nonce || *nonce || !recpp || *recpp) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));

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

	if (!rdbs || !rdbs->record_id_idx_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.flags = DB_DBT_USERMEM;
	key.data = uuid;
	key.size = 16; // UUIDs are always 16 bytes

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	val.flags = DB_DBT_REALLOC;
	pkey.flags = DB_DBT_REALLOC;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->record_id_idx_db->pget(rdbs->record_id_idx_db, txn, &key, &pkey, &val, 0);
		if (0 == db_ret) {
			txn->commit(txn, 0);
			break;
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}
		// some other error
		ret = JALDB_E_DB;
		goto out;
	}
	ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
	if (ret != JALDB_OK) {
		goto out;
	}
	rec->type = type;
	if (!rec->sys_meta) {
		rec->sys_meta = jaldb_create_segment();
		char *doc = NULL;
		size_t doc_len = 0;
		ret = jaldb_record_to_system_metadata_doc(rec, &doc, &doc_len);
		if (ret != JALDB_OK) {
			goto out;
		}
		rec->sys_meta->payload = (uint8_t*)doc;
		rec->sys_meta->length = doc_len;
	}

	*nonce = jal_strdup((char*)pkey.data);
	if (!nonce) {
		ret = JALDB_E_NO_MEM;
		goto out;
	}

	*recpp = rec;
	rec = NULL;
	ret = JALDB_OK;
out:
	jaldb_destroy_record(&rec);
	free(pkey.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_open_segment_for_read(jaldb_context *ctx, struct jaldb_segment *s)
{
	char *path = NULL;
	int fd = -1;
	if (!ctx || !s || !s->on_disk || !s->payload || (0 == strlen((char*)s->payload))) {
		return JALDB_E_INVAL;
	}
	if (s->fd != -1) {
		return JALDB_OK;
	}
	jal_asprintf(&path, "%s/%s", ctx->journal_root, (char*)s->payload);
	fd = open(path, O_RDONLY);
	if (-1 == fd) {
		return JALDB_E_UNKNOWN;
	}
	s->fd = fd;
	return JALDB_OK;
}

enum jaldb_status jaldb_remove_record(jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *nonce)
{
	int db_ret;
	enum jaldb_status ret;
	struct jaldb_record_dbs *rdbs = NULL;

	db_ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (0 != db_ret || !rdbs || !rdbs->primary_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	ret = jaldb_remove_record_from_db(ctx, rdbs, nonce);

out:
	return ret;
}

enum jaldb_status jaldb_remove_record_from_temp(jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *source,
		char *hex_sid)
{
	enum jaldb_status ret;
	int db_ret;
	struct jaldb_record_dbs *rdbs = NULL;

	db_ret = jaldb_get_dbs(ctx, source, type, &rdbs);
	if (0 != db_ret || !rdbs || !rdbs->primary_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	ret = jaldb_remove_record_from_db(ctx, rdbs, hex_sid);

out:
	return ret;
}

enum jaldb_status jaldb_remove_record_from_db(jaldb_context *ctx,
		jaldb_record_dbs *rdbs,
		char *nonce)
{
	enum jaldb_status ret;
	int db_ret;
	DB_TXN *txn = NULL;
	DBT key;

	if (!ctx || !nonce || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));

	key.flags = DB_DBT_REALLOC;
	key.data = jal_malloc(strlen(nonce)+1);
	key.size = strlen(nonce)+1;
	key.data = jal_strdup(nonce);

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->primary_db->del(rdbs->primary_db, txn, &key, 0);
		if (0 == db_ret) {
			txn->commit(txn, 0);
			break;
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}
		// some other error
		ret = JALDB_E_DB;
		goto out;
	}
	ret = JALDB_OK;
out:
	free(key.data);
	return ret;
}

enum jaldb_status jaldb_remove_segments_from_disk(jaldb_context *ctx, struct jaldb_record *rec)
{
	enum jaldb_status ret = JALDB_OK;
	enum jaldb_status tmp = JALDB_OK;
	tmp = jaldb_remove_segment_from_disk(ctx, rec->sys_meta);
	if (tmp != JALDB_OK) {
		ret = tmp;
	}
	tmp = jaldb_remove_segment_from_disk(ctx, rec->app_meta);
	if (tmp != JALDB_OK) {
		ret = tmp;
	}
	tmp = jaldb_remove_segment_from_disk(ctx, rec->payload);
	if (tmp != JALDB_OK) {
		ret = tmp;
	}
	return ret;
}

enum jaldb_status jaldb_remove_segment_from_disk(jaldb_context *ctx, struct jaldb_segment *segment)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}
	if (!segment) {
		return JALDB_OK;
	}
	if (!segment->on_disk) {
		return JALDB_OK;
	}
	char *path = NULL;
	jal_asprintf(&path, "%s/%s", ctx->journal_root, (char*)segment->payload);
	unlink(path);
	free(path);
	return JALDB_OK;
}

enum jaldb_status jaldb_next_unsynced_record(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	char **network_nonce,
	struct jaldb_record **rec_out)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	struct jaldb_record *rec = NULL;
	int byte_swap;
	struct jaldb_serialize_record_headers *headers = NULL;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DBT skey;
	DBT pkey;
	DBT val;
	memset(&skey, 0, sizeof(skey));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));

	if (!ctx || !network_nonce || *network_nonce || *rec_out || !rec_out) {
		ret = JALDB_E_INVAL;
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
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs || !rdbs->primary_db || !rdbs->record_sent_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	skey.size = sizeof(uint32_t);
	skey.data = jal_malloc(skey.size);
	*((uint32_t*)(skey.data)) = 0;// Not sent
	skey.flags = DB_DBT_REALLOC;

	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.dlen = sizeof(*headers);
	val.size = sizeof(*headers);
	val.doff = 0;
	val.data = jal_malloc(val.size);

	pkey.flags = DB_DBT_REALLOC;

	db_ret = rdbs->record_sent_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	while (1) {
		
		val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
		db_ret = rdbs->record_sent_db->pget(rdbs->record_sent_db, NULL, &skey, &pkey, &val, 0);
		val.flags = DB_DBT_REALLOC;
		
		if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		} else if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (0 != db_ret) {
			ret = JALDB_E_DB;
			JALDB_DB_ERR(rdbs->primary_db, db_ret);
			goto out;
		}

		headers = ((struct jaldb_serialize_record_headers *)val.data);
		if (headers->flags & JALDB_RFLAGS_SYNCED) {
			// already synced, so skip
			continue;
		}
		// not synced, get the full record.
		val.flags = DB_DBT_REALLOC;
		val.dlen = 0;
		db_ret = rdbs->record_sent_db->pget(rdbs->record_sent_db, NULL, &skey, &pkey, &val, 0);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		}

		if (0 != db_ret) {
			JALDB_DB_ERR(rdbs->primary_db, db_ret);
			ret = JALDB_E_DB;
			goto out;
		}

		break;
	}

	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto out;
	}

	ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
	if (ret != JALDB_OK) {
		goto out;
	}
	rec->type = type;
	if (!rec->sys_meta) {
		rec->sys_meta = jaldb_create_segment();
		char *doc = NULL;
		size_t doc_len = 0;
		ret = jaldb_record_to_system_metadata_doc(rec, &doc, &doc_len);
		if (ret != JALDB_OK) {
			goto out;
		}
		rec->sys_meta->payload = (uint8_t*)doc;
		rec->sys_meta->length = doc_len;
	}

	*network_nonce = jal_strdup(rec->network_nonce);
	if (NULL == network_nonce) {
		ret = JALDB_E_NO_MEM;
		goto out;
	}

	*rec_out = rec;
	rec = NULL;
	ret = JALDB_OK;
out:
	free(skey.data);
	free(pkey.data);
	free(val.data);
	jaldb_destroy_record(&rec);

	return ret;
}

enum jaldb_status jaldb_next_chronological_record(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	char **network_nonce,
	struct jaldb_record **rec_out,
	char **timestamp)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	struct jaldb_record *rec = NULL;
	struct tm search_time, current_time;
	int search_microseconds, cur_microseconds;
	memset(&search_time,0,sizeof(search_time));
	memset(&current_time,0,sizeof(current_time));
	int byte_swap;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	std::set <std::string> *seen_records = NULL;
	std::string nonce_string;
	DBT key;
	DBT pkey;
	DBT val;
	DBC *cursor = NULL;
	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	key.flags = DB_DBT_REALLOC;
	val.flags = DB_DBT_REALLOC;

	char *end_timestamp = strptime(*timestamp, "%Y-%m-%dT%H:%M:%S", &search_time);

	if (!end_timestamp) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!sscanf(end_timestamp,".%d-%*d:%*d",&search_microseconds)) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!ctx || !network_nonce || *network_nonce || !rec_out || *rec_out) {
		ret = JALDB_E_INVAL;
		goto out;
	}
	
	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		seen_records = ctx->seen_journal_records;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		seen_records = ctx->seen_audit_records;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		seen_records = ctx->seen_log_records;
		break;
	default:
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.size = strlen(*timestamp) + 1;
	key.data = jal_strdup(*timestamp);

	db_ret = rdbs->nonce_timestamp_db->get_byteswapped(rdbs->nonce_timestamp_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->nonce_timestamp_db->cursor(rdbs->nonce_timestamp_db, NULL, &cursor, DB_DEGREE_2);
	if (0 != db_ret) {
		JALDB_DB_ERR(rdbs->nonce_timestamp_db, db_ret);
		goto out;
	}

	db_ret = cursor->c_pget(cursor, &key, &pkey, &val, DB_SET_RANGE);
	if (0 != db_ret) {
		if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
		} else {
			JALDB_DB_ERR(rdbs->nonce_timestamp_db, db_ret);
		}
		goto out;
	}

	end_timestamp = strptime((char*) key.data, "%Y-%m-%dT%H:%M:%S", &current_time);

	if (!end_timestamp) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!sscanf(end_timestamp,".%d-%*d:%*d",&cur_microseconds)) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	nonce_string = (char *)pkey.data;

	while (difftime(mktime(&search_time), mktime(&current_time)) == 0 &&
			search_microseconds == cur_microseconds) {
		// Check to see if we already got a record at this time
		if (seen_records->count(nonce_string) == 0) {
			//Haven't seen it
			seen_records->insert(nonce_string);
			break;
		} else {
			db_ret = cursor->c_pget(cursor, &key, &pkey, &val, DB_NEXT);
			if (0 != db_ret) {
				if (DB_NOTFOUND == db_ret) {
					ret = JALDB_E_NOT_FOUND;
				} else {
					JALDB_DB_ERR(rdbs->nonce_timestamp_db, db_ret);
				}
				goto out;
			}
			nonce_string = (char *)pkey.data;
		}
		end_timestamp = strptime((char*) key.data, "%Y-%m-%dT%H:%M:%S", &current_time);
		if (!end_timestamp) {
			ret = JALDB_E_INVAL;
			goto out;
		}
		if (!sscanf(end_timestamp,".%d-%*d:%*d",&cur_microseconds)) {
			ret = JALDB_E_INVAL;
			goto out;
		}
	}

	if (difftime(mktime(&search_time), mktime(&current_time)) != 0 ||
			search_microseconds != cur_microseconds) {
		free(*timestamp);
		*timestamp = jal_strdup((char*)key.data);
		seen_records->clear();
		seen_records->insert(nonce_string);
	}

	ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
	if (ret != JALDB_OK) {
		goto out;
	}

	rec->type = type;
	if (!rec->sys_meta) {
		rec->sys_meta = jaldb_create_segment();
		char *doc = NULL;
		size_t doc_len = 0;
		ret = jaldb_record_to_system_metadata_doc(rec, &doc, &doc_len);
		if (ret != JALDB_OK) {
			goto out;
		}
		rec->sys_meta->payload = (uint8_t*)doc;
		rec->sys_meta->length = doc_len;
	}

	*network_nonce = jal_strdup(rec->network_nonce);
	if (NULL == network_nonce) {
		ret = JALDB_E_NO_MEM;
		goto out;
	}

	*rec_out = rec;
	rec = NULL;
	ret = JALDB_OK;

out:
	if (cursor) {
		cursor->c_close(cursor);
	}

	free(key.data);
	free(val.data);
	jaldb_destroy_record(&rec);
	return ret;


}

enum jaldb_status jaldb_get_primary_record_dbs(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		struct jaldb_record_dbs **rdbs)
{
	if (!ctx || !rdbs) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	switch (type) {
	case JALDB_RTYPE_JOURNAL:
		*rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		*rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		*rdbs = ctx->log_dbs;
		break;
	default:
		return JALDB_E_INVAL;
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_lookup_rdbs_in_map(
		jaldb_context *ctx,
		const char *source,
		enum jaldb_rec_type type,
		struct jaldb_record_dbs **rdbs)
{
	string_to_rdbs_map::iterator iter;
	std::string source_str(source);

	if (!ctx || !source) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	if (!ctx->journal_temp_dbs || !ctx->audit_temp_dbs || !ctx->log_temp_dbs) {
		return JALDB_E_UNINITIALIZED;
	}
	switch (type) {
	case JALDB_RTYPE_JOURNAL:
		iter = ctx->journal_temp_dbs->find(source_str);
		if (iter == ctx->journal_temp_dbs->end()) {
			*rdbs = NULL;
			return JALDB_OK;
		}
		break;
	case JALDB_RTYPE_AUDIT:
		iter = ctx->audit_temp_dbs->find(source_str);
		if (iter == ctx->audit_temp_dbs->end()) {
			*rdbs = NULL;
			return JALDB_OK;
		}
		break;
	case JALDB_RTYPE_LOG:
		iter = ctx->log_temp_dbs->find(source_str);
		if (iter == ctx->log_temp_dbs->end()) {
			*rdbs = NULL;
			return JALDB_OK;
		}
		break;
	default:
		return JALDB_E_INVAL;
	}

	*rdbs = iter->second;

	return JALDB_OK;
}
enum jaldb_status jaldb_store_rdbs_in_map(
		jaldb_context *ctx,
		const char *source,
		enum jaldb_rec_type type,
		struct jaldb_record_dbs *rdbs)
{
	std::string source_str(source);
	if (!ctx || !source) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	if (!ctx->journal_temp_dbs || !ctx->audit_temp_dbs || !ctx->log_temp_dbs) {
		return JALDB_E_UNINITIALIZED;
	}
	switch (type){
	case JALDB_RTYPE_JOURNAL:
		(*ctx->journal_temp_dbs)[source_str] = rdbs;
		break;
	case JALDB_RTYPE_AUDIT:
		(*ctx->audit_temp_dbs)[source_str] = rdbs;
		break;
	case JALDB_RTYPE_LOG:
		(*ctx->log_temp_dbs)[source_str] = rdbs;
		break;
	default:
		return JALDB_E_INVAL;
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_open_dbs_for_temp(
		jaldb_context *ctx,
		const char *source,
		enum jaldb_rec_type rtype,
		jaldb_record_dbs *rdbs,
		const u_int32_t db_flags)
{
	int db_ret;
	jaldb_status ret = JALDB_OK;
	char *filename;

	switch (rtype) {
	case JALDB_RTYPE_JOURNAL:
		jal_asprintf(&filename, "%s_%s",source,"journal");
		break;
	case JALDB_RTYPE_AUDIT:
		jal_asprintf(&filename, "%s_%s",source,"audit");
		break;
	case JALDB_RTYPE_LOG:
		jal_asprintf(&filename, "%s_%s",source,"log");
		break;
	default:
		return JALDB_E_INVAL;
	}

	db_ret = db_create(&(rdbs->primary_db), ctx->env, 0);
	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->primary_db->open(rdbs->primary_db, NULL,
			filename, "primary", DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->primary_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}
	db_ret = db_create(&(rdbs->metadata_db), ctx->env, 0);
	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto err_out;
	}
	db_ret = rdbs->metadata_db->open(rdbs->metadata_db, NULL,
			filename, "metadata", DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->metadata_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}
	goto out;
err_out:
	jaldb_destroy_record_dbs(&rdbs);
out:
	free(filename);
	return ret;
}

enum jaldb_status jaldb_xfer(jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *source,
		char *nonce_in,
		char **nonce_out)
{
	enum jaldb_status ret = JALDB_OK;
	struct jaldb_record_dbs *rdbs = NULL;
	struct jaldb_record *rec = NULL;

	if(!ctx || !source || 0 == strcmp(source,"localhost") ||
			0 == strcmp(source,"127.0.0.1")) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (0 != ret || !rdbs || !rdbs->primary_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	ret = jaldb_get_record_from_temp(ctx, type, nonce_in, source, &rec);
	if (0 != ret) {
		goto out;
	}

	ret = jaldb_insert_record(ctx, rec, nonce_out);
	if (0 != ret) {
		goto out;
	}

	ret = jaldb_remove_record_from_temp(ctx, type, source, nonce_in);
	if (0 != ret) {
		goto out;
	}
out:
	jaldb_destroy_record(&rec);
	return ret;
}

