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
 * Copyright (c) 2012-2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <list>
#include <string.h>
#include <sstream>
#include <sys/stat.h>
#include <inttypes.h> // For PRIu64
#include <list>
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jaldb_context.hpp"
#include "jaldb_serial_id.hpp"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"

using namespace std;

#define DEFAULT_DB_ROOT "/var/lib/jalop/db"
#define DEFAULT_SCHEMAS_ROOT "/usr/local/share/jalop-v1.0/schemas"

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
	env->txn_begin(env, NULL, &db_txn, DB_DIRTY_READ);
	db_err = env->open(env, db_root, env_flags, 0);
	if (0 != db_err) {
		return JALDB_E_INVAL;
	}
	int db_ret = 0;

	uint32_t db_flags = DB_THREAD;
	if (db_rdonly_flag) {
		db_flags |= DB_RDONLY;
	} else {
		db_flags |= DB_CREATE;
	}

	db_ret = db_create(&ctx->journal_conf_db, env, 0);
	if (db_ret != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->journal_conf_db), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->journal_conf_db->open(ctx->journal_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_JOURNAL_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->journal_conf_db), db_ret);
		return JALDB_E_DB;
	}

	db_ret = db_create(&ctx->audit_conf_db, env, 0);
	if (db_ret != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->audit_conf_db), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->audit_conf_db->open(ctx->audit_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_AUDIT_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->audit_conf_db), db_ret);
		return JALDB_E_DB;
	}

	db_ret = db_create(&ctx->log_conf_db, env, 0);
	if (db_ret != 0) {
		db_txn->abort(db_txn);;
		JALDB_DB_ERR((ctx->log_conf_db), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->log_conf_db->open(ctx->log_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_LOG_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		db_txn->abort(db_txn);;
		JALDB_DB_ERR((ctx->log_conf_db), db_ret);
		return JALDB_E_DB;
	}

	db_ret = db_create(&ctx->log_dbp, env, 0);
	if (db_ret != 0) {
		db_txn->abort(db_txn);;
		JALDB_DB_ERR((ctx->log_dbp), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->log_dbp->open(ctx->log_dbp, db_txn,
			JALDB_LOG_DB_NAME, NULL, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		db_txn->abort(db_txn);;
		JALDB_DB_ERR((ctx->log_dbp), db_ret);
		return JALDB_E_DB;
	}
	db_txn->commit(db_txn, 0);

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

	if (ctxp->log_dbp) {
		ctxp->log_dbp->close((*ctx)->log_dbp, 0);
	}

	if (ctxp->temp_dbs) {
		for (string_to_db_map::iterator iter = ctxp->temp_dbs->begin();
				iter != ctxp->temp_dbs->end();
				iter++) {
			iter->second->close(iter->second, 0);
		}
		delete ctxp->temp_dbs;
	}

	free(*ctx);
	*ctx = NULL;
}
std::string jaldb_make_temp_db_name(const string &id, const string &suffix)
{
	stringstream o;
	o << "__" << id << "_" << suffix;
	return o.str();
}

enum jaldb_status jaldb_open_temp_db(jaldb_context *ctx, const string& db_name, DB **db_out, int *db_err_out)
{
	if (!ctx || !ctx->temp_dbs || !db_out || *db_out || !db_err_out) {
		return JALDB_E_INVAL;
	}
	if (db_name.length() == 0) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	DB *db;
	int db_err = 0;
	uint32_t db_flags = DB_AUTO_COMMIT | DB_THREAD;
	enum jaldb_status ret = JALDB_E_DB;
	string_to_db_map::iterator iter = ctx->temp_dbs->find(db_name);
	if (iter == ctx->temp_dbs->end()) {
		DB_ENV *env = ctx->env;
		db_err = db_create(&db, env, 0);
		if (db_err != 0) {
			db = NULL;
			goto out;
		}
		if (ctx->db_read_only) {
			db_flags |= DB_RDONLY;
		} else {
			db_flags |= DB_CREATE;
		}
		db_err = db->open(db, NULL, db_name.c_str(), NULL, DB_BTREE, db_flags, 0);
		if (db_err != 0) {
			db->close(db, 0);
			db = NULL;
			goto out;
		}
		(*ctx->temp_dbs)[db_name] = db;
	} else {
		db = iter->second;
	}
	ret = JALDB_OK;
out:
	*db_err_out = db_err;
	*db_out = db;
	return ret;
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

enum jaldb_status jaldb_insert_audit_record(
	jaldb_context *ctx,
	std::string &source,
	const void *sys_meta_doc,
	const void *app_meta_doc,
	const void *audit_doc,
	std::string &sid)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_insert_log_record(
	jaldb_context *ctx,
	const string &source,
	const void *sys_meta_doc,
	const void *app_meta_doc,
	uint8_t *log_buf,
	const size_t log_len,
	string &sid,
	int *db_err)
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

enum jaldb_status jaldb_create_journal_file(
	jaldb_context *ctx,
	char **path,
	int *fd)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
	}
	return jaldb_create_file(ctx->journal_root, path, fd);
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

enum jaldb_status jaldb_insert_journal_metadata(
	jaldb_context *ctx,
	const std::string &source,
	const void *sys_meta_doc,
	const void *app_meta_doc,
	const std::string &path,
	std::string &sid)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_lookup_audit_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **audit_buf,
	size_t *audit_len)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_mark_audit_sent_ok(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_mark_journal_sent_ok(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_mark_log_sent_ok(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_mark_journal_synced(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_mark_audit_synced(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_mark_log_synced(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_lookup_log_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **log_buf,
	size_t *log_len,
	int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_lookup_journal_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	int *fd, size_t *journal_size)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_store_confed_journal_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
}
enum jaldb_status jaldb_store_confed_audit_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
}
enum jaldb_status jaldb_store_confed_log_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_next_journal_record(
	jaldb_context *ctx,
	const char *last_sid,
	char **next_sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	int *fd, size_t *journal_size)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_next_audit_record(
	jaldb_context *ctx,
	const char *last_sid,
	char **next_sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **audit_buf,
	size_t *audit_len)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_next_log_record(
	jaldb_context *ctx,
	const char *last_sid,
	char **next_sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **log_buf,
	size_t *log_len,
	int *db_err_out)
{
	return JALDB_E_NOT_IMPL;
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
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_audit_document_list(
		jaldb_context *ctx,
		list<string> **doc_list)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_log_document_list(
		jaldb_context *ctx,
		list<string> **doc_list)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_last_k_records_journal(
		jaldb_context *ctx,
		int k,
		list<string> &doc_list)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_last_k_records_audit(
		jaldb_context *ctx,
		int k,
		list<string> &doc_list)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_last_k_records_log(
		jaldb_context *ctx,
		int k,
		list<string> &doc_list)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_records_since_last_sid_journal(
		jaldb_context *ctx,
		char *last_sid,
		list<string> &doc_list)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_records_since_last_sid_audit(
		jaldb_context *ctx,
		char *last_sid,
		list<string> &doc_list)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_get_records_since_last_sid_log(
		jaldb_context *ctx,
		char *last_sid,
		list<string> &doc_list)
{
	return JALDB_E_NOT_IMPL;
}

