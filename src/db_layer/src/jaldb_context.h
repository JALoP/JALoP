/**
 * @file jaldb_context.h This file defines the DB context management functions.
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

#ifndef _JALDB_CONTEXT_H_
#define _JALDB_CONTEXT_H_

#include "jaldb_status.h"

#ifdef __cplusplus
extern "C" {
#endif

struct jaldb_record;
struct jaldb_record_dbs;
struct jaldb_context_t;
typedef struct jaldb_context_t jaldb_context;

/**
 * Creates an empty DB context.
 *
 * @return The created empty DB context.
 *
 */
jaldb_context *jaldb_context_create();

/**
 * Initializes a DB context.
 * @param[in] ctx The context to initialize.
 * @param[in] db_root The root path of the DB Layer's files. If db_root is
 * NULL, then the default is /var/lib/jalop/db.
 * @param[in] schemas_root The path to the directory containing JALoP related
 * schemas. If schemas_root is NULL, then the default is
 * /usr/share/jalop/schemas.
 * @param[in] db_rdonly_flag A flag which indicates whether DB_RDONLY should
 * be passed to the DB open function.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_context_init(
	jaldb_context *ctx,
	const char *db_root,
	const char *schemas_root,
	int db_rdonly_flag);

/**
 * Destroys a DB context.
 * Release all resources associated with this context. This should remove any
 * temporary databases that were created.
 *
 * @param ctx[in,out] The context to destroy. *ctx will be set to NULL.
 */
void jaldb_context_destroy(jaldb_context **ctx);

/**
 * Inserts an audit record into a temporary container.
 * @param[in] ctx The context.
 * @param[in] db_name A name to associate with the container.
 * @param[in] sys_meta_buf A buffer containing the system metadata.
 * @param[in] sys_meta_len The size (in bytes) of sys_meta_buf.
 * @param[in] app_meta_buf A buffer containing the application metadata.
 * @param[in] app_meta_len The size (in bytes) of app_meta_buf.
 * @param[in] audit_buf A buffer containing the audit data.
 * @param[in] audit_len The size (in bytes) of audit_buf.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_insert_audit_record_into_temp(
	jaldb_context *ctx,
	char *db_name,
	const uint8_t *sys_meta_buf,
	const size_t sys_meta_len,
	const uint8_t *app_meta_buf,
	const size_t app_meta_buf_len,
	const uint8_t *audit_buf,
	const size_t audit_len);
/**
 * Creates a journal file.
 * @param[in] ctx The context.
 * @param[out] path The path (relative to the db_root) of the new file.
 * @param[out] fd An open file descriptor for the new file. It is the caller's
 * responsibility to close the file descriptor.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_create_journal_file(
	jaldb_context *ctx,
	char **path,
	int *fd);

/**
 * Retrieves an audit record by serial ID.
 *
 * @param[in] ctx The context.
 * @param[in] sid The serial ID of the record being retrieved.
 * @param[out] sys_meta_buf A buffer containing the system metadata.
 * @param[in] sys_meta_len The size (in bytes) of sys_meta_buf.
 * @param[in,out] app_meta_buf A buffer containing the application metadata.
 * @param[in] app_meta_len The size (in bytes) of app_meta_buf.
 * @param[in,out] audit_buf A buffer containing the audit data.
 * @param[in] audit_len The size (in bytes) of audit_buf.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_lookup_audit_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **audit_buf,
	size_t *audit_len);

/**
 * Retrieves the next record from the database.
 *
 * @param[in] ctx The context.
 * @param[in] last_sid The last serial ID, i.e. where to start looking.
 * @param[out] next_sid The serial ID for the returned record.
 * @param[out] sys_meta_buf A buffer containing the system metadata.
 * @param[in] sys_meta_len The size (in bytes) of sys_meta_buf.
 * @param[in,out] app_meta_buf A buffer containing the application metadata.
 * @param[in] app_meta_len The size (in bytes) of app_meta_buf.
 * @param[in,out] audit_buf A buffer containing the audit data.
 * @param[in] audit_len The size (in bytes) of audit_buf.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_next_audit_record(
	jaldb_context *ctx,
	const char *last_sid,
	char **next_sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **audit_buf,
	size_t *audit_len);

/**
 * Retrieves a log record by serial ID.
 *
 * @param[in] ctx The context.
 * @param[in] sid The serial ID of the record being retrieved.
 * @param[out] sys_meta_buf A buffer containing the system metadata.
 * @param[out] sys_meta_len The size (in bytes) of sys_meta_buf.
 * @param[out] app_meta_buf A buffer containing the application metadata.
 * @param[out] app_meta_len The size (in bytes) of app_meta_buf.
 * @param[out] log_buf A buffer containing the log data.
 * @param[out] log_len The size (in bytes) of log_buf.
 * @param[out] db_err_ou The error code (if any) from the underlying Berkeley
 * DB. This is only valid when the function returns JALDB_E_DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if there is a problem with one of the parameters
 *  - JALDB_E_NOT_FOUND if the record could not be located
 *  - JALDB_E_CORRUPTED if there is a problem with the database
 *  - JALDB_E_DB if there was an unexpected error accessing the log DB.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_lookup_log_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	uint8_t **log_buf,
	size_t *log_len,
	int *db_err_out);

/**
 * Retrieves the next record base on serial ID.
 *
 * @param[in] ctx The context.
 * @param[in] last_sid The last serial ID, i.e. where to start looking from.
 * @param[out] next_sid The serial ID of the record being returned.
 * @param[out] sys_meta_buf A buffer containing the system metadata.
 * @param[out] sys_meta_len The size (in bytes) of sys_meta_buf.
 * @param[out] app_meta_buf A buffer containing the application metadata.
 * @param[out] app_meta_len The size (in bytes) of app_meta_buf.
 * @param[out] log_buf A buffer containing the log data.
 * @param[out] log_len The size (in bytes) of log_buf.
 * @param[out] db_err_ou The error code (if any) from the underlying Berkeley
 * DB. This is only valid when the function returns JALDB_E_DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if there is a problem with one of the parameters
 *  - JALDB_E_NOT_FOUND if the record could not be located
 *  - JALDB_E_CORRUPTED if there is a problem with the database
 *  - JALDB_E_DB if there was an unexpected error accessing the log DB.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
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
	int *db_err_out);


/**
 * Retrieves a journal record by serial ID.
 *
 * @param[in] ctx The context.
 * @param[in] sid The serial ID of the record being retrieved.
 * @param[in] path The path of the file that is journal data.
 * @param[in,out] sys_meta_buf A buffer containing the system metadata.
 * @param[in] sys_meta_len The size (in bytes) of sys_meta_buf.
 * @param[in,out] app_meta_buf A buffer containing the application metadata.
 * @param[in] app_meta_len The size (in bytes) of app_meta_buf.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails
 */
enum jaldb_status jaldb_lookup_journal_record(
	jaldb_context *ctx,
	const char *sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	int *fd, size_t *fd_sz);

/**
 * Retrieves the next journal record.
 *
 * @param[in] ctx The context.
 * @param[in] last_sid The last serial ID, i.e. where to start looking from.
 * @param[out] next_sid The serial ID of the record being returned.
 * @param[in] path The path of the file that is journal data.
 * @param[in,out] sys_meta_buf A buffer containing the system metadata.
 * @param[in] sys_meta_len The size (in bytes) of sys_meta_buf.
 * @param[in,out] app_meta_buf A buffer containing the application metadata.
 * @param[in] app_meta_len The size (in bytes) of app_meta_buf.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails
 */
enum jaldb_status jaldb_next_journal_record(
	jaldb_context *ctx,
	const char *last_sid,
	char **next_sid,
	uint8_t **sys_meta_buf,
	size_t *sys_meta_len,
	uint8_t **app_meta_buf,
	size_t *app_meta_len,
	int *fd, size_t *fd_sz);

/**
 * Utility to insert any JALoP record
 * @param[in] ctx the DB context.
 * @param[in] rec The record to insert.
 *
 * @return JALDB_OK on success, or an error code.
 */
enum jaldb_status jaldb_insert_record(jaldb_context *ctx, struct jaldb_record *rec);

#ifdef __cplusplus
}
#endif

#endif // _JALDB_CONTEXT_H_
