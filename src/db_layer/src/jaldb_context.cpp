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
 * Copyright (c) 2011 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <string.h>
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jaldb_context.hpp"
#include "jaldb_serial_id.hpp"
#include "jaldb_strings.h"
#include "jaldb_status.h"
#include "jaldb_utils.h"

using namespace std;

#define DEFAULT_DB_ROOT "/var/lib/jalop/db"
#define DEFAULT_SCHEMAS_ROOT "/usr/local/share/jalop-v1.0/schemas"
using namespace DbXml;

jaldb_context *jaldb_context_create()
{
	jaldb_context *context = (jaldb_context *)jal_calloc(1, sizeof(*context));
	return context;
}

enum jaldb_status jaldb_context_init(
	jaldb_context *ctx,
	const char *db_root,
	const char *schemas_root,
	int db_recover_flag)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}

	// Make certain that the context is not already initialized.
	if ((ctx->manager) || (ctx->journal_root) ||
		(ctx->schemas_root)) {
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

	uint32_t env_flags = DB_CREATE |
		DB_INIT_LOCK |
		DB_INIT_LOG |
		DB_INIT_MPOOL |
		DB_INIT_TXN |
		DB_THREAD;
	if (db_recover_flag) {
		env_flags |= DB_RECOVER;
	}

	DB_ENV *env = NULL;
	db_env_create(&env, 0);
	int db_err = env->open(env, db_root, env_flags, 0);
	if (db_err != 0) {
		return JALDB_E_INVAL;
	}
	env->set_lk_detect(env, DB_LOCK_DEFAULT);

	XmlManager *mgr = new XmlManager(env, DBXML_ADOPT_DBENV);

	ctx->manager = mgr;
	XmlContainerConfig cfg;
	cfg.setAllowCreate(true);
	cfg.setThreaded(true);
	cfg.setTransactional(true);

	XmlTransaction txn = ctx->manager->createTransaction();

	XmlContainer cont = ctx->manager->openContainer(txn, JALDB_AUDIT_SYS_META_CONT_NAME, cfg);
	ctx->audit_sys_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_AUDIT_APP_META_CONT_NAME, cfg);
	ctx->audit_app_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_AUDIT_CONT_NAME, cfg);
	ctx->audit_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_JOURNAL_SYS_META_CONT_NAME, cfg);
	ctx->journal_sys_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_JOURNAL_APP_META_CONT_NAME, cfg);
	ctx->journal_app_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_LOG_SYS_META_CONT_NAME, cfg);
	ctx->log_sys_cont = new XmlContainer(cont);

	cont = ctx->manager->openContainer(txn, JALDB_LOG_APP_META_CONT_NAME, cfg);
	ctx->log_app_cont = new XmlContainer(cont);

	jaldb_initialize_serial_id(txn, *ctx->journal_sys_cont, &db_err);
	jaldb_initialize_serial_id(txn, *ctx->audit_sys_cont, &db_err);
	jaldb_initialize_serial_id(txn, *ctx->log_sys_cont, &db_err);
	DB_TXN *db_txn = txn.getDB_TXN();
	int db_ret = 0;

	db_ret = db_create(&ctx->journal_conf_db, env, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->journal_conf_db), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->journal_conf_db->open(ctx->journal_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_JOURNAL_CONF_NAME, DB_BTREE, DB_CREATE, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->journal_conf_db), db_ret);
		return JALDB_E_DB;
	}

	db_ret = db_create(&ctx->audit_conf_db, env, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->audit_conf_db), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->audit_conf_db->open(ctx->audit_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_AUDIT_CONF_NAME, DB_BTREE, DB_CREATE, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->audit_conf_db), db_ret);
		return JALDB_E_DB;
	}

	db_ret = db_create(&ctx->log_conf_db, env, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->log_conf_db), db_ret);
		return JALDB_E_DB;
	}
	db_ret = ctx->log_conf_db->open(ctx->log_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_LOG_CONF_NAME, DB_BTREE, DB_CREATE, 0);
	if (db_ret != 0) {
		txn.abort();
		JALDB_DB_ERR((ctx->log_conf_db), db_ret);
		return JALDB_E_DB;
	}

	txn.commit();

	return JALDB_OK;
}

void jaldb_context_destroy(jaldb_context **ctx)
{
	if (!ctx || !(*ctx)) {
		return;
	}
	jaldb_context *ctxp = *ctx;
	if (ctxp->audit_sys_cont) {
		delete (ctxp->audit_sys_cont);
	}
	if (ctxp->audit_app_cont) {
		delete (ctxp->audit_app_cont);
	}
	if (ctxp->audit_cont) {
		delete (ctxp->audit_cont);
	}
	if (ctxp->journal_sys_cont) {
		delete (ctxp->journal_sys_cont);
	}
	if (ctxp->journal_app_cont) {
		delete (ctxp->journal_app_cont);
	}
	if (ctxp->log_sys_cont) {
		delete (ctxp->log_sys_cont);
	}
	if (ctxp->log_app_cont) {
		delete (ctxp->log_app_cont);
	}

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

	delete (*ctx)->manager;


	free(*ctx);
	*ctx = NULL;
}

enum jaldb_status jaldb_insert_audit_record(
	jaldb_context *ctx,
	const char *source,
	const uint8_t *sys_meta_buf,
	const size_t sys_meta_len,
	const uint8_t *app_meta_buf,
	const size_t app_meta_len,
	const uint8_t *audit_buf,
	const size_t audit_len)
{
		

	return JALDB_OK;
}

enum jaldb_status jaldb_insert_audit_record_into_temp(
	jaldb_context *ctx,
	char *db_name,
	const uint8_t *sys_meta_buf,
	const size_t sys_meta_len,
	const uint8_t *app_meta_buf,
	const size_t app_meta_buf_len,
	const uint8_t *audit_buf,
	const size_t audit_len)
{

	return JALDB_OK;
}

enum jaldb_status jaldb_insert_log_record(
	jaldb_context *ctx,
	const char *source,
	const uint8_t *sys_meta_buf,
	const size_t sys_meta_len,
	const uint8_t *app_meta_buf,
	const size_t app_meta_buf_len,
	const uint8_t *log_buf,
	const size_t log_len)
{
	return JALDB_OK;
}

enum jaldb_status jaldb_create_journal_file(
	jaldb_context *ctx,
	char *path,
	int *fd)
{


	return JALDB_OK;
}

enum jaldb_status jaldb_insert_journal_record(
	jaldb_context *ctx,
	const char *source,
	const char *path,
	const uint8_t *sys_meta_buf,
	const size_t sys_meta_len,
	const uint8_t *app_meta_buf,
	const size_t app_meta_buf_len)
{


	return JALDB_OK;
}

enum jaldb_status jaldb_get_audit_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **audit_buf,
	size_t *audit_len)
{


	return JALDB_OK;
}

enum jaldb_status jaldb_get_log_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **log_buf,
	size_t *log_len)
{


	return JALDB_OK;
}

enum jaldb_status jaldb_get_journal_record(
	jaldb_context *ctx,
	const char *sid,
	const char *path,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len)
{

	return JALDB_OK;
}

enum jaldb_status jaldb_store_confed_journal_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out)
{
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	
	return jaldb_store_confed_sid_helper(ctx->journal_sys_cont,
			ctx->journal_conf_db, remote_host, sid, db_err_out);
}
enum jaldb_status jaldb_store_confed_audit_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out)
{
	if (!ctx || !ctx->manager || !ctx->audit_sys_cont) {
		return JALDB_E_INVAL;
	}
	return jaldb_store_confed_sid_helper(ctx->audit_sys_cont,
			ctx->audit_conf_db, remote_host, sid, db_err_out);
}
enum jaldb_status jaldb_store_confed_log_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out)
{
	if (!ctx || !ctx->manager) {
		return JALDB_E_INVAL;
	}
	return jaldb_store_confed_sid_helper(ctx->log_sys_cont,
			ctx->log_conf_db, remote_host, sid, db_err_out);
	
}
enum jaldb_status jaldb_store_confed_sid_helper(XmlContainer *cont, DB *db,
		const char *remote_host, const char *sid, int *db_err_out)
{
	if (!cont || !sid || !db_err_out) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status ret = JALDB_E_INVAL;
	while (1) {
		XmlTransaction txn = cont->getManager().createTransaction();
		try {
			XmlDocument doc = cont->getDocument(txn,
						JALDB_SERIAL_ID_DOC_NAME,
						DB_READ_COMMITTED);
			XmlValue val;
			if (!doc.getMetaData(JALDB_NS, JALDB_SERIAL_ID_NAME, val)) {
				// something is horribly wrong, there is no serial
				// ID in the database
				txn.abort();
				ret = JALDB_E_CORRUPTED;
				break;
			}
			if (!val.isString()) {
				txn.abort();
				ret = JALDB_E_CORRUPTED;
				break;
			}
			std::string next_sid = val.asString();
			if (jaldb_sid_cmp(next_sid.c_str(), next_sid.length(),
						sid, strlen(sid)) <= 0) {
				txn.abort();
				ret = JALDB_E_SID;
				break;
			}
			ret = jaldb_store_confed_sid(db, txn.getDB_TXN(),
					remote_host, sid, db_err_out);
			if (ret != JALDB_OK) {
				txn.abort();
				if (*db_err_out == DB_LOCK_DEADLOCK) {
					continue;
				}
				break;
			}
			txn.commit();
			break;
		} catch (XmlException &e) {
			txn.abort();
			if (e.getExceptionCode() == XmlException::DATABASE_ERROR) {
				if (e.getDbErrno() == DB_LOCK_DEADLOCK) {
					continue;
				}
			}
			throw e;
		}
	}
	return ret;
}

