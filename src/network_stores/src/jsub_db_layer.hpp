/**
 * @file jsub_db_layer.hpp This file provides the function calls to the DB
 * Layer.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#ifndef _JSUB_DB_LAYER_HPP_
#define _JSUB_DB_LAYER_HPP_

#include <string>
#include <openssl/pem.h>
#include <jalop/jaln_network_types.h>
#include "jaldb_status.h"
#include "jaldb_context.h"
#include "jaldb_context.hpp"
#include "jaldb_purge.hpp"

/**
 * Initializes the interface to the database.
 * @param[in] db_root The root location of the database.
 * @param[in] schemas_root The root location of the schemas.
 *
 * @return
 *  - A pointer to the context if it was created and initialized successfully
 *	NULL if the process failed.
 */
jaldb_context *jsub_setup_db_layer(
		const char *db_root,
		const char *schemas_root);

/**
 * Destroys the database interface.
 * @param[in] db_ctx The database context.
 */
void jsub_teardown_db_layer(jaldb_context **db_ctx);

/**
 * Inserts an audit record into the temporary database container.
 * @param[in] db_ctx The database context.
 * @param[in] c_source The name of the source of the record.
 * @param[in] sys_meta The system metadata to insert.
 * @param[in] sys_len The length of \p sys_meta.
 * @param[in] app_meta The application metadata to insert.
 * @param[in] app_len The length of \p app_meta.
 * @param[in] audit The audit data to insert.
 * @param[in] audit_len The length of \p audit.
 * @param[in] nonce_in The nonce to use for inserting the record.
 * @param[in] debug A flag to denote if debugging information should be
 *			printed to stderr.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_insert_audit(
		jaldb_context *db_ctx,
		char *c_source,
		uint8_t *sys_meta,
		size_t sys_len,
		uint8_t *app_meta,
		size_t app_len,
		uint8_t *audit,
		size_t audit_len,
		char *nonce_in,
		int debug);

/**
 * Inserts a log record into the temporary database container.
 * @param[in] db_ctx The database context.
 * @param[in] c_source The name of the source of the record.
 * @param[in] sys_meta The system metadata to insert.
 * @param[in] sys_len The length of \p sys_meta.
 * @param[in] app_meta The application metadata to insert.
 * @param[in] app_len The length of \p app_meta.
 * @param[in] log The log data to insert.
 * @param[in] log_len The length of \p log.
 * @param[in] nonce_in The nonce to use for inserting the record.
 * @param[in] debug A flag to denote if debugging information should be
 *			printed to stderr.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_insert_log(
		jaldb_context *db_ctx,
		char *c_source,
		uint8_t *sys_meta,
		size_t sys_len,
		uint8_t *app_meta,
		size_t app_len,
		uint8_t *log,
		size_t log_len,
		char *nonce_in,
		int debug);

/**
 * Inserts a journal record's metadata into the temporary database
 * container.
 * @param[in] db_ctx The database context.
 * @param[in] c_source The name of the source of the record.
 * @param[in] sys_meta The system metadata to insert.
 * @param[in] sys_len The length of \p sys_meta.
 * @param[in] app_meta The application metadata to insert.
 * @param[in] app_len The length of \p app_meta.
 * @param[in] db_payload_path The path to the journal payload on disk.
 * @param[in] payload_len The length of the journal payload.
 * @param[in] nonce_in The nonce to use for inserting the record.
 * @param[in] debug A flag to denote if debugging information should be
 *			printed to stderr.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_insert_journal_metadata(
		jaldb_context *db_ctx,
		char *c_source,
		uint8_t *sys_meta,
		size_t sys_len,
		uint8_t *app_meta,
		size_t app_len,
		char *db_payload_path,
		uint64_t payload_len,
		char *nonce_in,
		int debug);

/**
 * Transfer an audit record from the temporary
 * container to the permanent container.
 * @param[in] db_ctx The database context.
 * @param[in] c_source The name of the source of the record.
 * @param[in] tmp_nonce The nonce of the record located
 * 		      in the temporary container.
 * @param[out] perm_nonce The nonce of the record saved
 *		       to the permanent container.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_transfer_audit(
		jaldb_context *db_ctx,
		std::string &source,
		std::string &tmp_nonce,
		std::string &perm_nonce);

/**
 * Transfer a log record from the temporary 
 * container to the permanent container.
 * @param[in] db_ctx The database context.
 * @param[in] c_source The name of the source of the record.
 * @param[in] tmp_nonce The nonce of the record located
 * 		      in the temporary container.
 * @param[out] perm_nonce The nonce of the record saved
 *		       to the permanent container.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_transfer_log(
		jaldb_context *db_ctx,
		std::string &source,
		std::string &tmp_nonce,
		std::string &perm_nonce);

/**
 * Transfer a journal record from the temporary 
 * container to the permanent container.
 * @param[in] db_ctx The database context.
 * @param[in] c_source The name of the source of the record.
 * @param[in] tmp_nonce The nonce of the record located
 * 	in the temporary container.
 * @param[out] perm_nonce The nonce of the record saved
 *	to the permanent container.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_transfer_journal(
		jaldb_context *db_ctx,
		std::string &source,
		std::string &tmp_nonce,
		std::string &perm_nonce);

/**
 * Write journal buffer data to a file.
 * @param[in] db_ctx The database context.
 * @param[in,out] db_payload_path The name of the source of the record.
 * @param[in,out] db_payload_fd The file descriptor used to create/write
 *	to the file.
 * @param[in] buffer The \pbuffer data of the journal payload to write to file.
 * @param[in] buffer_len The length/size of \p buffer.
 * @param[in] processed_len The length/size of the data processed for the 
 * \p payload so far.  Or 0 if the record is complete and the journal resume
 * data should be cleared
 * @param[in] hostname The \p hostname we are receiving the journal from.
 * @param[in] nonce The \p nonce of the record we are receiving.
 * @param[in] debug A flag indicating whether or not debug
 *	information is written to stdout. 0 False, 1 True.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_write_journal(
		jaldb_context *db_ctx,
		char **db_payload_path,
		int *db_payload_fd,
		uint8_t *buffer,
		size_t buffer_len,
		size_t proccessed_len,
		const char *hostname,
		const char *nonce,
		int debug);

/**
 * Stores the last confirmed nonce for a record type to
 * the temp database.
 * @param[in] db_ctx The database context.
 * @param[in] nonce The nonce of the record.
 * @param[in] type The record type. (Journal, Audit or Log)
 * @param[in] source The hostname or IP as a string.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_store_confed_nonce(
		jaldb_context *db_ctx,
		const std::string &nonce,
		enum jaln_record_type type,
		const std::string &source);

/**
 * Retrieves the last confirmed nonce for a record type
 * from the temp database.
 * @param[in] db_ctx The database context.
 * @param[in] nonce The nonce of the record.
 * @param[in] type The record type. (Journal, Audit or Log)
 * @param[in] source The hostname or IP as a string.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_get_last_confed_nonce(
		jaldb_context *db_ctx,
		std::string &nonce,
		enum jaln_record_type type,
		const std::string &source);

/**
 * Store journal_resume data in the journal temporary system container.
 * Data stored consists of the path to the journal file and the offset.
 *
 * @param[in] db_ctx the context to use
 * @param[in] remote_host a string to identify where the record came from.
 * @param[in] nonce the nonce of the record.
 * @param[in] path the path to the journal file (should be obtained using to
 *                 jaldb_create_file).
 * @param[in] offset the file offset.
 *
 *@return JALDB_OK - Success, an error on failure.
 */
int jsub_store_journal_resume(
		jaldb_context *db_ctx,
		const char *remote_host,
		const char *nonce,
		const char *path,
		uint64_t offset);

/**
 * Delete journal_resume data in the journal temporary system container.
 * This should be called between records to clear out the resume data
 *
 * @param[in] ctx the context to use
 * @param[in] remote_host a string to identify where the last record came from.
 *
 *@return JALDB_OK - Success, an error on failure.
 */
int jsub_clear_journal_resume(
		jaldb_context *ctx,
		const char *remote_host);

/**
 * Retrieve journal_resume data from the journal temporary system container.
 * Data retrieved consists of the path to the journal file and the offset.
 * If the journal_resume data is not found, path and offset are not altered.
 *
 * @param[in] db_ctx the context to use
 * @param[in] remote_host a string to identify where the record came from.
 * @param[out] nonce the nonce to the journal record.
 * @param[out] path the path to the journal file (should be obtained using to
 *                 jaldb_create_file).
 * @param[out] offset the file offset.
 *
 *@return JALDB_OK - Success, an error on failure.
 */
int jsub_get_journal_resume(
		jaldb_context *db_ctx,
		const char *remote_host,
		char **nonce,
		char **path,
		uint64_t &offset);

/**
 * Returns the offset of the file referenced by \p file_descriptor.
 * @param[in] file_descriptor The file descriptor.
 *
 * @return
 *  - The offset value or -1 if \p file_descriptor was invalid.
 */
off_t jsub_get_offset(int file_descriptor);

/**
 * Prints jaldb_status to a char*.
 * @param[in] db_status The status of the database after an operation.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
const char* jsub_db_status_to_string(jaldb_status db_status);

/**
* Writes jaldb_status and an error message to stderr.
* @param[in] db_status The status of the database after an operation.
* @param[in] err_msg The message to be written.
*
* @return
*  - JALDB_OK if the function succeeds or a JAL error code if the function
* fails.
*/
void jsub_write_to_stderr_db_status(jaldb_status db_status, char *err_msg);

/**
 * Flush stale data from the temporary databases
 * @param[in] db_ctx The context to use
 * @param[in] hsot The host to flush
 * @param[in] record_types The record types to purge, must be an or'ed
 * @param[in] debug_flag Flag to indicate if log messages should be outputted
 * combination of #jaln_record_type
 */
void jsub_flush_stale_data(jaldb_context *db_ctx, const char *host, int record_types, int debug_flag);

#endif // _JSUB_DB_LAYER_HPP_
