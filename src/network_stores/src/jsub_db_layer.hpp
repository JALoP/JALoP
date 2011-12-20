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

#ifndef _JSUB_DB_LAYER_HPP_
#define _JSUB_DB_LAYER_HPP_

#include <string>
#include <xercesc/dom/DOM.hpp>
#include <openssl/pem.h>
#include <jalop/jaln_network_types.h>
#include "jaldb_status.h"
#include "jaldb_context.h"
#include "jaldb_context.hpp"

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
 * @param[in] sid_in The serial ID to use for inserting the record.
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
		char *sid_in,
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
 * @param[in] sid_in The serial ID to use for inserting the record.
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
		char *sid_in,
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
 * @param[in] sid_in The serial ID to use for inserting the record.
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
		char *sid_in,
		int debug);

/**
 * Transfer an audit record from the temporary
 * container to the permanent container.
 * @param[in] db_ctx The database context.
 * @param[in] c_source The name of the source of the record.
 * @param[in] tmp_sid The serial ID of the record located
 * 		      in the temporary container.
 * @param[out] perm_sid The serial ID of the record saved
 *		       to the permanent container.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_transfer_audit(
		jaldb_context *db_ctx,
		std::string &source,
		std::string &tmp_sid,
		std::string &perm_sid);

/**
 * Transfer a log record from the temporary 
 * container to the permanent container.
 * @param[in] db_ctx The database context.
 * @param[in] c_source The name of the source of the record.
 * @param[in] tmp_sid The serial ID of the record located
 * 		      in the temporary container.
 * @param[out] perm_sid The serial ID of the record saved
 *		       to the permanent container.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_transfer_log(
		jaldb_context *db_ctx,
		std::string &source,
		std::string &tmp_sid,
		std::string &perm_sid);

/**
 * Transfer a journal record from the temporary 
 * container to the permanent container.
 * @param[in] db_ctx The database context.
 * @param[in] c_source The name of the source of the record.
 * @param[in] tmp_sid The serial ID of the record located
 * 	in the temporary container.
 * @param[out] perm_sid The serial ID of the record saved
 *	to the permanent container.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_transfer_journal(
		jaldb_context *db_ctx,
		std::string &source,
		std::string &tmp_sid,
		std::string &perm_sid);

/**
 * Write journal buffer data to a file.
 * @param[in] db_ctx The database context.
 * @param[in,out] db_payload_path The name of the source of the record.
 * @param[in,out] db_payload_fd The file descriptor used to create/write
 *	to the file.
 * @param[in] payload The buffer data to write to file.
 * @param[in] payload_len The length/size of \p payload.
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
		uint8_t *payload,
		size_t payload_len,
		int debug);

/**
 * Stores the last confirmed serial_id for a record type to
 * the temp database.
 * @param[in] db_ctx The database context.
 * @param[in] sid The serial ID of the record.
 * @param[in] type The record type. (Journal, Audit or Log)
 * @param[in] source The hostname or IP as a string.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_store_confed_sid(
		jaldb_context *db_ctx,
		const std::string &sid,
		enum jaln_record_type type,
		const std::string &source);

/**
 * Retrieves the last confirmed serial_id for a record type
 * from the temp database.
 * @param[in] db_ctx The database context.
 * @param[in] sid The serial ID of the record.
 * @param[in] type The record type. (Journal, Audit or Log)
 * @param[in] source The hostname or IP as a string.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
int jsub_get_last_confed_sid(
		jaldb_context *db_ctx,
		std::string &sid,
		enum jaln_record_type type,
		const std::string &source);

/**
 * Store journal_resume data in the journal temporary system container.
 * Data stored consists of the path to the journal file and the offset.
 *
 * @param[in] db_ctx the context to use
 * @param[in] remote_host a string to identify where the record came from.
 * @param[in] path the path to the journal file (should be obtained using to
 *                 jaldb_create_journal_file).
 * @param[in] offset the file offset.
 *
 *@return JALDB_OK - Success, an error on failure.
 */
int jsub_store_journal_resume(
		jaldb_context *db_ctx,
		const char *remote_host,
		const char *path,
		uint64_t offset);

/**
 * Retrieve journal_resume data from the journal temporary system container.
 * Data retrieved consists of the path to the journal file and the offset.
 * If the journal_resume data is not found, path and offset are not altered.
 *
 * @param[in] db_ctx the context to use
 * @param[in] remote_host a string to identify where the record came from.
 * @param[out] path the path to the journal file (should be obtained using to
 *                 jaldb_create_journal_file).
 * @param[out] offset the file offset.
 *
 *@return JALDB_OK - Success, an error on failure.
 */
int jsub_get_journal_resume(
		jaldb_context *db_ctx,
		const char *remote_host,
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
char* jsub_db_status_to_string(jaldb_status db_status);

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

#endif // _JSUB_DB_LAYER_HPP_
