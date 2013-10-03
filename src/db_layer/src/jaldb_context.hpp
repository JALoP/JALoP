/**
 * @file jaldb_context.hpp This file provides the DB context structure and
 * constants for use by the DB Layer.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#ifndef _JALDB_CONTEXT_HPP_
#define _JALDB_CONTEXT_HPP_

#include <list>
#include <string>
#include <map>
#include <db.h>
#include "jaldb_context.h"

typedef std::map<std::string, jaldb_record_dbs*> string_to_rdbs_map;

struct jaldb_record_dbs;

struct jaldb_context_t {
	char *journal_root; //<! The journal record root path.
	char *schemas_root; //<! The schemas root path.
	DB_ENV *env; //<! The Berkeley DB Environment.
	struct jaldb_record_dbs *log_dbs; //<! The DBs associated with log records
	struct jaldb_record_dbs *audit_dbs; //<! The DBs associated with audit records
	struct jaldb_record_dbs *journal_dbs; //<! The DBs associated with journal records
	DB *journal_conf_db; //<! The database for conf'ed journal records
	DB *audit_conf_db; //<! The database for conf'ed audit records
	DB *log_conf_db; //<! The database for conf'ed log records
	string_to_rdbs_map *journal_temp_dbs;
	string_to_rdbs_map *audit_temp_dbs;
	string_to_rdbs_map *log_temp_dbs;
	int db_read_only; //<! Whether or not to open the databases read only
};

/**
* Store a confirmed serial_id in the journal temp container.
* @param[in] ctx The jaldb_context to use.
* @param[in] remote_host The host that we received the record from.
* @param[in] sid The serial ID of the confirmed record
* @param[out] db_err_out A flag indicating a specific DB error.
* @return
*  - JALDB_OK on success
*  - JALDB_E_INVAL if one of the parameters was invalid.
*  - JALDB_E_READONLY if the database is read-only.
*  - JALDB_E_NOT_FOUND if the record was not found.
*  - JALDB_E_SID if their already exists a record with this \p sid.
* @throw XmlException
*/
enum jaldb_status jaldb_store_confed_journal_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		const char *sid,
		int *db_err_out);

/**
* Store a confirmed serial_id in the audit temp container.
* @param[in] ctx The jaldb_context to use.
* @param[in] remote_host The host that we received the record from.
* @param[in] sid The serial ID of the confirmed record
* @param[out] db_err_out A flag indicating a specific DB error.
* @return
*  - JALDB_OK on success
*  - JALDB_E_INVAL if one of the parameters was invalid.
*  - JALDB_E_READONLY if the database is read-only.
*  - JALDB_E_NOT_FOUND if the record was not found.
*  - JALDB_E_SID if their already exists a record with this \p sid.
* @throw XmlException
*/
enum jaldb_status jaldb_store_confed_audit_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		const char *sid,
		int *db_err_out);

/**
* Store a confirmed serial_id in the log temp container.
* @param[in] ctx The jaldb_context to use.
* @param[in] remote_host The host that we received the record from.
* @param[in] sid The serial ID of the confirmed record
* @param[out] db_err_out A flag indicating a specific DB error.
* @return
*  - JALDB_OK on success
*  - JALDB_E_INVAL if one of the parameters was invalid.
*  - JALDB_E_READONLY if the database is read-only.
*  - JALDB_E_NOT_FOUND if the record was not found.
*  - JALDB_E_SID if their already exists a record with this \p sid.
* @throw XmlException
*/
enum jaldb_status jaldb_store_confed_log_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		const char *sid,
		int *db_err_out);

/**
* Retrieve the last confirmed serial_id from the given source.
* @param[in] ctx the jaldb_context
* @param[in] type The type of record (journal, audit, log).
* @param[in] source the host to find the last serial id from
* @param[out] sid the last confirmed serial id
*
* @return JALDB_OK on success, or a different JALDB error code on failure.
*/
enum jaldb_status jaldb_get_last_confed_sid_temp(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *source,
		char **sid);

/**
* Retrieve a confirmed serial_id from the journal temp container.
* @param[in] ctx The jaldb_context to use.
* @param[in] remote_host The host that we received the record from.
* @param[in] sid The serial ID of the confirmed record
* @param[out] db_err_out A flag indicating a specific DB error.
* @return
*  - JALDB_OK on success
*  - JALDB_E_INVAL if one of the parameters was invalid.
*  - JALDB_E_READONLY if the database is read-only.
*  - JALDB_E_NOT_FOUND if the record was not found.
*  - JALDB_E_SID if their already exists a record with this \p sid.
* @throw XmlException
*/
enum jaldb_status jaldb_get_last_confed_journal_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		std::string &sid,
		int *db_err_out);

/**
* Retrieve a confirmed serial_id from the audit temp container.
* @param[in] ctx The jaldb_context to use.
* @param[in] remote_host The host that we received the record from.
* @param[in] sid The serial ID of the confirmed record
* @param[out] db_err_out A flag indicating a specific DB error.
* @return
*  - JALDB_OK on success
*  - JALDB_E_INVAL if one of the parameters was invalid.
*  - JALDB_E_READONLY if the database is read-only.
*  - JALDB_E_NOT_FOUND if the record was not found.
*  - JALDB_E_SID if their already exists a record with this \p sid.
* @throw XmlException
*/
enum jaldb_status jaldb_get_last_confed_audit_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		std::string &sid,
		int *db_err_out);

/**
* Retrieve a confirmed serial_id from the log temp container.
* @param[in] ctx The jaldb_context to use.
* @param[in] remote_host The host that we received the record from.
* @param[in] sid The serial ID of the confirmed record
* @param[out] db_err_out A flag indicating a specific DB error.
* @return
*  - JALDB_OK on success
*  - JALDB_E_INVAL if one of the parameters was invalid.
*  - JALDB_E_READONLY if the database is read-only.
*  - JALDB_E_NOT_FOUND if the record was not found.
*  - JALDB_E_SID if their already exists a record with this \p sid.
* @throw XmlException
*/
enum jaldb_status jaldb_get_last_confed_log_sid_tmp(
		jaldb_context *ctx,
		const char *remote_host,
		std::string &sid,
		int *db_err_out);

/**
 * Transfer audit records from the temporary db container to the
 * permanent container.
 * @param[in] ctx The jaldb_context to use
 * @param[in] source The host that we received the record from
 * @param[in] sid The serial ID of the record to be transferred
 * @param[out] next_sid The new serial ID of the record transferred to
 * the permanent container.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_READONLY if the database is read-only.
 *  - JALDB_E_NOT_FOUND if the record was not found.
 *  - JALDB_E_SID if their already exists a record with this \p sid.
 * @throw XmlException
 */
enum jaldb_status jaldb_xfer_audit(
	jaldb_context *ctx,
	std::string &source,
	const std::string &sid,
	std::string &next_sid);

/**
 * Transfer log records from the temporary db container to the
 * permanent container.
 * @param[in] ctx The jaldb_context to use
 * @param[in] source The host that we received the record from
 * @param[in] sid The serial ID of the record to be transferred
 * @param[out] next_sid The new serial ID of the record transferred to
 * the permanent container.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_READONLY if the database is read-only.
 *  - JALDB_E_NOT_FOUND if the record was not found.
 *  - JALDB_E_SID if their already exists a record with this \p sid.
 *  - JALDB_E_CORRUPTED if the record did not contain 
 *    application or log data.
 *  - JALDB_E_DB if there was an error updating the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 */
enum jaldb_status jaldb_xfer_log(
	jaldb_context *ctx,
	std::string &source,
	const std::string &sid,
	std::string &next_sid);

/**
 * Transfer journal records from the temporary db container to the 
 * permanent container.
 * @param[in] ctx The jaldb_context to use
 * @param[in] source The host that we received the record from
 * @param[in] sid The serial ID of the record to be transferred
 * @param[out] next_sid The new serial ID of the record transferred to
 * the permanent container.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_READONLY if the database is read-only.
 *  - JALDB_E_NOT_FOUND if the record was not found.
 *  - JALDB_E_SID if their already exists a record with this \p sid.
 * @throw XmlException
 */
enum jaldb_status jaldb_xfer_journal(
	jaldb_context *ctx,
	const std::string &source,
	const std::string &sid,
	std::string &next_sid);

/**
* Store the last confirmed serial_id from the given source.
* @param[in] ctx the jaldb_context
* @param[in] type The type of record (journal, audit, log).
* @param[in] source the host the last serial id is from
* @param[in] sid the last confirmed serial id
*
* @return JALDB_OK on success, or a different JALDB error code on failure.
*/
enum jaldb_status jaldb_store_confed_sid_temp(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	char* source,
	char* sid);

/**
 * Store the most recently confirmed journal record for a particular host.
 * @param[in] ctx The jaldb_context to use
 * @param[in] remote_host The host that we received a digest conf for
 * @param[in] sid The serial ID that was 'confirmed'
 * @param[out] db_err_out The error code (if any) returned by Berkeley DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_SID if the Serial is sequentially after the next available
 *  Serial ID
 *  - JALDB_E_ALREADY_CONFED if the current mapping in the database is
 *    the same as \p sid or sequentially later.
 *  - JALDB_E_CORRUPTED is the latest serial ID cannot be found. This
 *  indicates an internal problem with the database.
 *  - JALDB_E_DB if there was an error updating the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 */
enum jaldb_status jaldb_store_confed_journal_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out);

/**
 * Store the most recently confirmed audit record for a particular host.
 * @param[in] ctx The jaldb_context to use
 * @param[in] remote_host The host that we received a digest conf for
 * @param[in] sid The serial ID that was 'confirmed'
 * @param[out] db_err_out The error code (if any) returned by Berkeley DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_ALREADY_CONFED if the current mapping in the database is
 *    the same as \p sid or sequentially later.
 *  - JALDB_E_SID if the Serial is sequentially after the next available
 *  Serial ID
 *  - JALDB_E_CORRUPTED is the latest serial ID cannot be found. This
 *  indicates an internal problem with the database.
 *  - JALDB_E_DB if there was an error updating the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 */
enum jaldb_status jaldb_store_confed_audit_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out);

/**
 * Store the most recently confirmed log record for a particular host.
 * @param[in] ctx The jaldb_context to use
 * @param[in] remote_host The host that we received a digest conf for
 * @param[in] sid The serial ID that was 'confirmed'
 * @param[out] db_err_out The error code (if any) returned by Berkeley DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_ALREADY_CONFED if the current mapping in the database is
 *    the same as \p sid or sequentially later.
 *  - JALDB_E_SID if the Serial is sequentially after the next available
 *  Serial ID
 *  - JALDB_E_CORRUPTED is the latest serial ID cannot be found. This
 *  indicates an internal problem with the database.
 *  - JALDB_E_DB if there was an error updating the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 */
enum jaldb_status jaldb_store_confed_log_sid(jaldb_context *ctx,
		const char *remote_host, const char *sid, int *db_err_out);

/**
 * Insert an audit record into a temporary database. This caches the record
 * for a network store until they receive a digest-conf message back from the
 * remote local store.
 * @param[in] ctx The context that the temporary database should be associated
 * with.
 * @param[in] source Where the record came from
 * @param[in] sys_doc The system metadata document, must not be NULL;
 * @param[in] app_doc The application metadata document, this may be NULL
 * @param[in] auditdoc The audit document metadata document, this may not be
 * NULL.
 * @param[in] sid The serial ID as identified by the remote network store.
 *
 * @return JALDB_OK on success
 * JALDB_E_INVAL if any of the parameters are invalid.
 */
enum jaldb_status jaldb_insert_audit_record_into_temp(
	jaldb_context *ctx,
	std::string &source,
	const void *sys_doc,
	const void *app_doc,
	const void *audit_doc,
	const std::string &sid);

/**
 * Helper utility to generate a name for a temporary database used by the
 * network store.
 *
 * @param[in] An identifier for the database
 * @param[suffix] A suffix to use (i.e. '_audit_meta.dbxml')
 *
 * @return a string to use as the database name.
 */
std::string jaldb_make_temp_db_name(const std::string &id, const std::string &suffix);

/**
 * Inserts a log record into a temporary database for use when communicating
 * with a network store.
 * @param[in] ctx The context.
 * @param[in] source The source of the record. If NULL, then this is set to the
 * string 'localhost'.
 * @param[in] sys_meta_doc The system metadata document
 * @param[in] app_meta_doc The application  metadata document
 * @param[in] log_buf A buffer containing the audit data.
 * @param[in] log_len The size (in bytes) of audit data.
 * @param[out] sid The serial ID for the record.
 * @param[out] db_err Set to the Berkeley DB error when this function returns
 * JALDB_E_DB
 *
 * @return JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 * @throw XmlException if there was an error inserting the record.
 */
enum jaldb_status jaldb_insert_log_record_into_temp(
	jaldb_context *ctx,
	std::string &source,
	const void *sys_meta_doc,
	const void *app_meta_doc,
	uint8_t *log_buf,
	const size_t log_len,
	const std::string &sid,
	int *db_err);

/**
 * Open a temporary database for storing log records while communicating with a network
 * store.
 * The DB is cached within the context for quicker access later.
 * @param[in] ctx the context to associate with
 * @param[in] db_name The name of the database
 * @param[out] db_out Once the database is opened, the new DB is assigned to \p
 * db_out;
 * @param[out] db_err_out set to the Berkeley DB error (if any). This is only
 * valid when the function returns JALDB_E_DB
 * assigned to \p cont.
 *
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if ctx is invalid
 *  - JALDB_E_DB if there was an error create the database, check db_err_out
 *  for more information
 *
 */
enum jaldb_status jaldb_open_temp_db(jaldb_context *ctx, const std::string& db_name,
		DB **db_out, int *db_err_out);

/**
 * Store journal metadata information about a record into a temporary database.
 *
 * @param[in] ctx the context to use
 * @param[in] source a string to identify where the record came from.
 * @param[in] sys_meta_doc a document that contains the system metadata.
 * @param[in] app_meta_doc a document that contains the app metadata (if any).
 * @param[in] path the path to the journal file (should be obtained using to
 *                 jaldb_create_file).
 * @param[in] sid the serial ID as identified by the remote peer.
 */
enum jaldb_status jaldb_insert_journal_metadata_into_temp(
	jaldb_context *ctx,
	const std::string &source,
	const void *sys_meta_doc,
	const void *app_meta_doc,
	const std::string &path,
	const std::string &sid);

/**
 * Store journal_resume data in the journal temporary system container.
 * Data stored consists of the path to the journal file and the offset.
 *
 * @param[in] ctx the context to use
 * @param[in] remote_host a string to identify where the record came from.
 * @param[in] path the path to the journal file (should be obtained using to
 *                 jaldb_create_file).
 * @param[in] offset the file offset.
 *
 *@return JALDB_OK - Success, an error on failure.
 */
enum jaldb_status jaldb_store_journal_resume(
		jaldb_context *ctx,
		const char *remote_host,
		const char *path,
		uint64_t offset);

/**
 * Retrieve journal_resume data from the journal temporary system container.
 * Data retrieved consists of the path to the journal file and the offset.
 * If the journal_resume data is not found, path and offset are not altered.
 *
 * @param[in] ctx the context to use
 * @param[in] remote_host a string to identify where the record came from.
 * @param[out] path the path to the journal file (should be obtained using to
 *                 jaldb_create_file).
 * @param[out] offset the file offset.
 *
 *@return JALDB_OK - Success, an error on failure.
 */
enum jaldb_status jaldb_get_journal_resume(
		jaldb_context *ctx,
		const char *remote_host,
		char **path,
		uint64_t &offset);

/**
 * Retrieve a list of document names present in the journal system container.
 *
 * @param[in] ctx the context to use
 * @param[out] doc_list A pointer to a list returned by the function.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_journal_document_list(
	jaldb_context *ctx,
	std::list<std::string> **doc_list);

 /**
 * Retrieve a list of document names present in the audit system container.
 *
 * @param[in] ctx the context to use
 * @param[out] doc_list A pointer to a list returned by the function.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_audit_document_list(
		jaldb_context *ctx,
		std::list<std::string> **doc_list);

 /**
 * Retrieve a list of document names present in the log system container.
 *
 * @param[in] ctx the context to use
 * @param[out] doc_list A pointer to a list returned by the function.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_log_document_list(
		jaldb_context *ctx,
		std::list<std::string> **doc_list);

/**
* Retrieve a list of the last \p k records of the given type.
*
* @param[in] ctx the context to use.
* @param[in] k the number of records to retrieve.
* @param[out] nonce_list the list of nonces.
* @param[in] type the record type.
* @param[in] get all records of given type.
*
* @return  JALDB_OK - success
*      JALDB_E_INVAL - invalid parameter.
*      JALDB_E_DB - Error occurred in database.
*/
enum jaldb_status jaldb_get_last_k_records(
		jaldb_context *ctx,
		int k,
		std::list<std::string> &nonce_list,
		enum jaldb_rec_type type,
		bool get_all=false);

/**
* Retrieve a list of the all records of the given type.
*
* @param[in] ctx the context to use.
* @param[out] nonce_list the list of nonces.
* @param[in] type the record type.
*
* @return  JALDB_OK - success
*      JALDB_E_INVAL - invalid parameter.
*      JALDB_E_DB - Error occurred in database.
*/
enum jaldb_status jaldb_get_all_records(
		jaldb_context *ctx,
		std::list<std::string> **nonce_list,
		enum jaldb_rec_type type);


 /**
 * Retrieve a list of the records with the given type received
 * after the record denoted by \p last_nonce.
 *
 * @param[in] ctx the context to use.
 * @param[in] nonce the nonce of the last record retrieved.
 * @param[out] nonce_list the list of nonces.
 * @param[in] type the record type.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_records_since_last_nonce(
		jaldb_context *ctx,
		char *last_nonce,
		std::list<std::string> &nonce_list,
		enum jaldb_rec_type type);
		
#endif // _JALDB_CONTEXT_HPP_
