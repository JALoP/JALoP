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
#include "jaldb_strings.h"
#include "jaldb_status.h"

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
	const char *schemas_root)
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
	if (-1 == jal_asprintf(&ctx->journal_root, "%s%s", db_root, JALDB_JOURNAL_ROOT_NAME)) {
		return JALDB_E_NO_MEM;
	}

	ctx->schemas_root = jal_strdup(schemas_root);

	uint32_t env_flags = DB_CREATE |
		DB_INIT_LOCK |
		DB_INIT_LOG |
		DB_INIT_MPOOL |
		DB_INIT_TXN |
		DB_THREAD;

	DB_ENV *env = NULL;
	db_env_create(&env, 0);
	int db_err = env->open(env, db_root, env_flags, 0);
	if (db_err != 0) {
		return JALDB_E_INVAL;
	}

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
