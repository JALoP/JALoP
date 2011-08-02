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

#define DEFAULT_DB_ROOT "/var/lib/jalop/db"
#define DEFAULT_SCHEMAS_ROOT "/usr/local/share/jalop-v1.0/schemas"

jaldb_context *jaldb_context_create()
{
	jaldb_context *context = (jaldb_context *)jal_malloc(sizeof(*context));

	context->manager = NULL;
	context->audit_sys_meta_container = NULL;
	context->audit_app_meta_container = NULL;
	context->audit_container = NULL;
	context->log_sys_meta_container = NULL;
	context->log_app_meta_container = NULL;
	context->log_db = NULL;
	context->journal_sys_meta_container = NULL;
	context->journal_app_meta_container = NULL;
	context->journal_root = NULL;
	context->schemas_root = NULL;

	return context;
}

enum jal_status jaldb_context_init(
	jaldb_context *ctx,
	const char *db_root,
	const char *schemas_root)
{
	if (!ctx) {
		return JAL_E_INVAL;
	}

	// Make certain that the context is not already initialized.
	if ((ctx->manager) || (ctx->audit_sys_meta_container) ||
		(ctx->audit_app_meta_container) || (ctx->audit_container) ||
		(ctx->log_sys_meta_container) ||
		(ctx->log_app_meta_container) || (ctx->log_db) ||
		(ctx->journal_sys_meta_container) ||
		(ctx->journal_app_meta_container) || (ctx->journal_root) ||
		(ctx->schemas_root)) {

		return JAL_E_INITIALIZED;
	}

	XmlManager *mgr = new XmlManager();

	ctx->manager = mgr;

	if (!db_root) {
		db_root = DEFAULT_DB_ROOT;
	}

	if (!schemas_root) {
		schemas_root = DEFAULT_SCHEMAS_ROOT;
	}

	// *** TBD: ASSOCIATE THE SCHEMAS ROOT WITH THE DOCUMENT CONTAINERS. ***

	char *path = NULL;

	jal_asprintf(&path, "%s/%s", db_root, AUDIT_SYS_META_CONT_NAME);
	ctx->audit_sys_meta_container = path;

	jal_asprintf(&path, "%s/%s", db_root, AUDIT_APP_META_CONT_NAME);
	ctx->audit_app_meta_container = path;

	jal_asprintf(&path, "%s/%s", db_root, AUDIT_CONT_NAME);
	ctx->audit_container = path;

	jal_asprintf(&path, "%s/%s", db_root, LOG_SYS_META_CONT_NAME);
	ctx->log_sys_meta_container = path;

	jal_asprintf(&path, "%s/%s", db_root, LOG_APP_META_CONT_NAME);
	ctx->log_app_meta_container = path;

	jal_asprintf(&path, "%s/%s", db_root, LOG_DB_NAME);
	ctx->log_db = path;

	jal_asprintf(&path, "%s/%s", db_root, JOURNAL_SYS_META_CONT_NAME);
	ctx->journal_sys_meta_container = path;

	jal_asprintf(&path, "%s/%s", db_root, JOURNAL_APP_META_CONT_NAME);
	ctx->journal_app_meta_container = path;

	jal_asprintf(&path, "%s/%s", db_root, JOURNAL_ROOT_NAME);
	ctx->journal_root = path;

	ctx->schemas_root = jal_strdup(schemas_root);

	return JAL_OK;
}

void jaldb_context_destroy(jaldb_context **ctx)
{
	if (!ctx || !(*ctx)) {
		return;
	}

	delete (*ctx)->manager;

	free((*ctx)->audit_sys_meta_container);
	free((*ctx)->audit_app_meta_container);
	free((*ctx)->audit_container);
	free((*ctx)->log_sys_meta_container);
	free((*ctx)->log_app_meta_container);
	free((*ctx)->log_db);
	free((*ctx)->journal_sys_meta_container);
	free((*ctx)->journal_app_meta_container);
	free((*ctx)->journal_root);
	free((*ctx)->schemas_root);

	free(*ctx);
	*ctx = NULL;
}

enum jal_status jaldb_insert_audit_record(
	jaldb_context *ctx,
	const char *source,
	const uint8_t *sys_meta_buf,
	const size_t sys_meta_len,
	const uint8_t *app_meta_buf,
	const size_t app_meta_len,
	const uint8_t *audit_buf,
	const size_t audit_len)
{
		

	return JAL_OK;
}

enum jal_status jaldb_insert_audit_record_into_temp(
	jaldb_context *ctx,
	char *db_name,
	const uint8_t *sys_meta_buf,
	const size_t sys_meta_len,
	const uint8_t *app_meta_buf,
	const size_t app_meta_buf_len,
	const uint8_t *audit_buf,
	const size_t audit_len)
{

	return JAL_OK;
}

enum jal_status jaldb_insert_log_record(
	jaldb_context *ctx,
	const char *source,
	const uint8_t *sys_meta_buf,
	const size_t sys_meta_len,
	const uint8_t *app_meta_buf,
	const size_t app_meta_buf_len,
	const uint8_t *log_buf,
	const size_t log_len)
{


	return JAL_OK;
}

enum jal_status jaldb_create_journal_file(
	jaldb_context *ctx,
	char *path,
	int *fd)
{


	return JAL_OK;
}

enum jal_status jaldb_insert_journal_record(
	jaldb_context *ctx,
	const char *source,
	const char *path,
	const uint8_t *sys_meta_buf,
	const size_t sys_meta_len,
	const uint8_t *app_meta_buf,
	const size_t app_meta_buf_len)
{


	return JAL_OK;
}

enum jal_status jaldb_get_audit_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **audit_buf,
	size_t *audit_len)
{


	return JAL_OK;
}

enum jal_status jaldb_get_log_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **log_buf,
	size_t *log_len)
{


	return JAL_OK;
}

enum jal_status jaldb_get_journal_record(
	jaldb_context *ctx,
	const char *sid,
	const char *path,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len)
{


	return JAL_OK;
}
