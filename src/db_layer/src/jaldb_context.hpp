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

#ifndef _JALDB_CONTEXT_HPP_
#define _JALDB_CONTEXT_HPP_

#include <list>
#include <string>
#include <map>
#include <dbxml/DbXml.hpp>
#include <dbxml/XmlContainer.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include "jaldb_context.h"

typedef std::map<std::string, DbXml::XmlContainer> string_to_container_map;
typedef std::map<std::string, DB*> string_to_db_map;

struct jaldb_context_t {
	DbXml::XmlManager *manager; //<! The manager associated with the context.
	DbXml::XmlContainer *audit_sys_cont; //<! Container for the audit System Metadata
	DbXml::XmlContainer *audit_app_cont; //<! Container for the audit Application Metadata
	DbXml::XmlContainer *audit_cont; //<! Container for the audit data
	DbXml::XmlContainer *journal_sys_cont; //<! Container for the journal System Metadata
	DbXml::XmlContainer *journal_app_cont; //<! Container for the journal Application Metadata
	DbXml::XmlContainer *log_sys_cont; //<! Container for the log System Metadata
	DbXml::XmlContainer *log_app_cont; //<! Container for the log Application Metadata
	char *journal_root; //<! The journal record root path.
	char *schemas_root; //<! The schemas root path.
	DB *journal_conf_db; //<! The database for conf'ed journal records
	DB *audit_conf_db; //<! The database for conf'ed audit records
	DB *log_conf_db; //<! The database for conf'ed log records
	DB *log_dbp; //<! The log database.
	string_to_container_map *temp_containers; //<! a map from strings to XmlContainers that identifies temporary databases for use by the network stores.
	string_to_db_map *temp_dbs; //<! a map from strings to Berkeley DBs that identifies temporary databases for use by the network stores.
	int db_read_only; //<! Whether or not to open the databases read only
};

/**
* Enum used to distinguish between record types
*/
enum jaldb_record_type {
	/** Indicates a Journal Record */
	JALDB_RTYPE_JOURNAL = 1 << 0,
	/** Indicates an Audit Record */
	JALDB_RTYPE_AUDIT = 1 << 1,
	/** Indicates a Log Record */
	JALDB_RTYPE_LOG = 1 << 2,
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
* Store a confirmed serial_id in the temp container.
* @param[in] ctx The jaldb_context to use.
* @param[in] cont The container to store the confirmed \p sid in.
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
enum jaldb_status jaldb_store_confed_sid_tmp_helper(
		jaldb_context *ctx,
		DbXml::XmlContainer *cont,
		const char *remote_host,
		const char *sid,
		int *db_err_out);

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
* Retrieve a confirmed serial_id from the container.
* @param[in] ctx The jaldb_context to use.
* @param[in] cont The database container to retrieve the \p sid from.
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
enum jaldb_status jaldb_get_last_confed_sid_tmp_helper(
		jaldb_context *ctx,
		DbXml::XmlContainer *cont,
		const std::string &remote_host,
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
 * Delete log records from the application and system containers.
 * @param[in] txn The transaction to use.
 * @param[in] uc The update context to use.
 * @param[in] sys_cont The system metadata container.
 * @param[in] app_cont The application metadata container.
 * @param[in] log_db The database holding the log payload.
 * @param[in] sid The serial ID of the record to be deleted.
 * @param[in] sys_doc The system metadata document to be deleted.
 * @param[in] app_doc The application metadata document to be deleted.
 * @param[out] db_err_out The error code (if any) returned by Berkeley DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_NOT_FOUND if the document with \p sid was not found.
 *  - JALDB_E_CORRUPTED if the record did not contain 
 *    application or log data.
 *  - JALDB_E_DB if there was an error updating the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 */
enum jaldb_status jaldb_delete_log(
	DbXml::XmlTransaction &txn, 
	DbXml::XmlUpdateContext &uc,
	DbXml::XmlContainer &sys_cont,
	DbXml::XmlContainer &app_cont,
	DB *log_db,
	const std::string &sid,
	DbXml::XmlDocument *sys_doc,
	DbXml::XmlDocument *app_doc,
	int *db_err_out);

/**
 * Save log records to the application and system containers.
 * @param[in] txn The transaction to use.
 * @param[in] uc The update context to use.
 * @param[in] sys_cont The system metadata container.
 * @param[in] app_cont The application metadata container.
 * @param[in] log_db The database holding the log payload.
 * @param[in] sid The serial ID of the record to be saved.
 * @param[in] sys_doc The system metadata document to be saved.
 * @param[in] app_doc The application metadata document to be saved.
 * @param[in] log_buf The log payload.
 * @param[in] log_len The length of the data referenced by \p log_buf.
 * @param[out] db_err_out The error code (if any) returned by Berkeley DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_SID if a record with this \p sid already exists.
 *  - JALDB_E_CORRUPTED if the record did not contain 
 *    application or log data.
 *  - JALDB_E_DB if there was an error updating the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 */
enum jaldb_status jaldb_save_log(
	DbXml::XmlTransaction &txn, 
	DbXml::XmlUpdateContext &uc,
	DbXml::XmlContainer &sys_cont,
	DbXml::XmlContainer &app_cont,
	DB *log_db,
	const std::string &sid,
	DbXml::XmlDocument *sys_doc,
	DbXml::XmlDocument *app_doc,
	uint8_t *log_buf,
	size_t  log_len,
	int *db_err_out);

/**
 * Retrieve log records to the application and system containers.
 * @param[in] txn The transaction to use.
 * @param[in] uc The update context to use.
 * @param[in] sys_cont The system metadata container.
 * @param[in] app_cont The application metadata container.
 * @param[in] log_db The database holding the log payload.
 * @param[in] sid The serial ID of the record to be retrieved.
 * @param[out] sys_doc The system metadata document to be retrieved.
 * @param[out] app_doc The application metadata document to be retrieved.
 * @param[out] log_buf The log payload \p log_buf.
 * @param[out] log_len The length of the data referenced by \p log_buf.
 * @param[out] db_err_out The error code (if any) returned by Berkeley DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_NOT_FOUND if a document was not found with \p sid.
 *  - JALDB_E_CORRUPTED if the record did not contain 
 *    application or log data.
 *  - JALDB_E_DB if there was an error updating the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 */
enum jaldb_status jaldb_retrieve_log(
	DbXml::XmlTransaction &txn, 
	DbXml::XmlUpdateContext &uc,
	DbXml::XmlContainer &sys_cont,
	DbXml::XmlContainer &app_cont,
	DB *log_db,
	const std::string &sid,
	DbXml::XmlDocument *sys_doc,
	DbXml::XmlDocument *app_doc,
	uint8_t **log_buf,
	size_t *log_len,
	int *db_err_out);

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
 * Helper function for storing conf'ed serial IDs
 *
 * This first verifies that \p sid is a valid Serial ID (i.e. it comes
 * sequentially before the next available Serial ID).
 *
 * @param[int] cont The DbXml container to check \p sid against.
 * @param[in] db The Berkeley DB object to store the conf'ed Serial ID in
 * @param[in] remote_host The host (IP address, domain name, or whatever) to
 * associate with the serial ID.
 * @param[in] sid The actual Serial ID
 * @param[out] db_err_out Will be set to a Berkeley DB error code if there was a
 * problem updating the database. This is only valid when the function returns
 * JALDB_E_DB.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_ALREADY_CONFED if the current mapping in the database is
 *    the same as \p sid or sequentially later.
 *  - JALDB_E_SID if the Serial is sequentially after the next available
 *  Serial ID
 *  - JALDB_E_CORRUPTED is the latest serial ID cannot be found. This
 *  indicates an internal problem with the database.
 *  - JALDB_E_DB if there was an error updated the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 *
 */
enum jaldb_status jaldb_store_confed_sid_helper(DbXml::XmlContainer *cont, DB *db,
		const char *remote_host, const char *sid, int *db_err_out);

/**
 * Helper utility for inserting and audit record into the appropriate
 * containers
 * The caller will need to commit the transaction.
 *
 * @param[in] source The 'source' identifier to use. If empty, this will be set
 * to 'localhost'
 * @param[in] txn The transaction to use.
 * @param[in] manager The manager that owns the containers
 * @param[in] uc The update context to use.
 * @param[in] sys_cont The container that holds the system metadata
 * @param[in] app_cont The container that holds the application metadata
 * @param[in] audit_cont The container that holds the audit documents
 * @param[in] sys_doc The DOMDocument that contains the System Metadata for
 * this record.
 * @param[in] app_doc The DOMDocument (if any) that contains the application Metadata for
 * this record (may be NULL).
 * @param[in] audit_doc The DOMDocument that contains the audit data for this record.
 * @param[in,out] sid The serial ID to use. If sid is empty, then this function
 * will attempt to get the next serial ID from \p sys_cont
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters is bad
 */
enum jaldb_status jaldb_insert_audit_helper(
		const std::string &source,
		DbXml::XmlTransaction &txn,
		DbXml::XmlManager &manager,
		DbXml::XmlUpdateContext &uc,
		DbXml::XmlContainer &sys_cont,
		DbXml::XmlContainer &app_cont,
		DbXml::XmlContainer &audit_cont,
		const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_doc,
		const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_doc,
		const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *audit_doc,
		const std::string &sid);

/**
 * Inserts an audit record.
 * @param[in] ctx The context.
 * @param[in] source The source of the record. If NULL, then this is set to the
 * string 'localhost'.
 * @param[in] sys_meta_doc The document containing the System Metadata for the record
 * @param[in] app_meta_doc The document containing the Application Metadata (if any) for the record
 * @param[in] audit_doc The audit document
 * @param[out] sid The serial ID assigned to the record
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters is bad
 *  - JALDB_E_CORRUPTED if there is an internal problem with the database
 */
enum jaldb_status jaldb_insert_audit_record(
	jaldb_context *ctx,
	std::string &source,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_meta_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_meta_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *audit_doc,
	std::string &sid);

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
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *audit_doc,
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
 * Open a temporary database for storing records while communicating with a network
 * store.
 * The container is cached within the context for quicker access later.
 * @param[in] ctx the context to associate with
 * @param[in] db_name The name of the database
 * @param[out] cont Once the database is opened, the new XmlContainer is
 * assigned to \p cont.
 *
 * @return JALDB_OK on success
 * JALDB_E_INVAL if ctx is invalid
 */
enum jaldb_status jaldb_open_temp_container(jaldb_context *ctx, const std::string& db_name, DbXml::XmlContainer &cont);

/**
 * Inserts a log record.
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
enum jaldb_status jaldb_insert_log_record(
	jaldb_context *ctx,
	const std::string &source,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_meta_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_meta_doc,
	uint8_t *log_buf,
	const size_t log_len,
	std::string &sid,
	int *db_err);

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
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_meta_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_meta_doc,
	uint8_t *log_buf,
	const size_t log_len,
	const std::string &sid,
	int *db_err);

/**
 * Helper utility for inserting log records into various containers.
 *
 * Although either app_meta_doc or log_buf may be NULL, it is an error to
 * specify NULL for both. It is also an error to specify NULL for app_meta_doc
 * and specify the log_len as 0.
 * @param[in] source Where the record came from. If length == 0, this will be
 * set to localhost
 * @param[in] txn The transaction to use
 * @param[in] manager The manager to use
 * @param[in] uc The update context to use
 * @param[in] sys_cont The container to insert the system metadata into
 * @param[in] app_cont The container to insert the application metadata into
 * @param[in] log_db The database to store the log record in
 * @param[in] sys_meta_doc The DOMDocument that is the system metadata, may
 * not be NULL
 * @param[in] app_meta_doc The DOMDocument that is the application metadata,
 * @param[in] log_buf The byte buffer that contains the log entry
 * @param[in] log_len The length (in bytes) of \p log_buf.
 * may be NULL
 * @param[in] sid The serial ID to associate with this record.
 * @param[out] db_err Error code from Berkeley DB. This will only have a valid
 * value if the function returns JALDB_E_DB
 * @return
 *   - JALDB_OK on success
 *   - JALDB_E_DB if there was an error inserting into the log DB
 *   - JALDB_E_INVAL if any of the parameters are invalid
 */
enum jaldb_status jaldb_insert_log_record_helper(const std::string &source,
		DbXml::XmlTransaction &txn,
		DbXml::XmlManager &manager,
		DbXml::XmlUpdateContext &uc,
		DbXml::XmlContainer &sys_cont,
		DbXml::XmlContainer &app_cont,
		DB *log_db,
		const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_meta_doc,
		const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_meta_doc,
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
 * Helper utility for inserting journal metadata.
 * @param[in] source The source of the record. If NULL, then this is set to the
 * string 'localhost'.
 * obtained via a call to jaldb_create_journal_file.
 * @param[in] txn The transaction to use
 * @param[in] manager The manager to use
 * @param[in] uc The update context to use.
 * @param[in] sys_cont The container to insert the system metadata into
 * @param[in] app_cont The container to insert the application metadata into
 * @param[in] sys_meta_doc The DOMDocument that is the system metadata, must
 * not be NULL.
 * @param[in] app_meta_doc The DOMDocument that is the application metadata,
 * may be NULL.
 * @param[in] path The path of the file that is journal data. This should be
 * @param[in] sid The serial ID for the record, this must be non-zero in
 * length
 *
 * @return JALDB_OK if the function succeeds or a JAL error code if the function
 */
enum jaldb_status jaldb_insert_journal_metadata_helper(
	const std::string &source,
	DbXml::XmlTransaction &txn,
	DbXml::XmlManager &manager,
	DbXml::XmlUpdateContext &uc,
	DbXml::XmlContainer &sys_cont,
	DbXml::XmlContainer &app_cont,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_meta_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_meta_doc,
	const std::string &path,
	const std::string &sid);

/**
 * Inserts journal metadata.
 * @param[in] ctx The context.
 * @param[in] source The source of the record. If NULL, then this is set to the
 * string 'localhost'.
 * obtained via a call to jaldb_create_journal_file.
 * @param[in] app_meta_buf A buffer containing the application metadata.
 * @param[in] app_meta_len The size (in bytes) of app_meta_buf.
 * @param[in] path The path of the file that is journal data. This should be
 * @param[out] sid The serial ID for the record.
 *
 * @return JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_insert_journal_metadata(
	jaldb_context *ctx,
	const std::string &source,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_meta_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_meta_doc,
	const std::string &path,
	std::string &sid);

/**
 * Store journal metadata information about a record into a temporary database.
 *
 * @param[in] ctx the context to use
 * @param[in] source a string to identify where the record came from.
 * @param[in] sys_meta_doc a document that contains the system metadata.
 * @param[in] app_meta_doc a document that contains the app metadata (if any).
 * @param[in] path the path to the journal file (should be obtained using to
 *                 jaldb_create_journal_file).
 * @param[in] sid the serial ID as identified by the remote peer.
 */
enum jaldb_status jaldb_insert_journal_metadata_into_temp(
	jaldb_context *ctx,
	const std::string &source,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *sys_meta_doc,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *app_meta_doc,
	const std::string &path,
	const std::string &sid);

/**
 * Helper function to mark records as 'synced'
 * All records up to and including \p sid
 * that were successfully delivered to \p remote_host are marked as 'synced'.
 *
 * @param[in] ctx The context
 * @param[in] cont The container to process
 * @param[in] sid The sid to look for
 * @param[in] remote_host The machine that is marking the file as synced
 *
 * @return JALDB_OK, or JALDB_E_INVAL
 */
enum jaldb_status jaldb_mark_synced_common(
	jaldb_context *ctx,
	DbXml::XmlContainer *cont,
	const char *sid,
	const char *remote_host);

/**
 * Function that marks journal records as 'synced'.
 * All records up to and including \p sid
 * that were successfully delivered to \p remote_host are marked as 'synced'.
 *
 * @param[in] ctx The context
 * @param[in] cont The container to process
 * @param[in] sid The sid to look for
 * @param[in] remote_host The machine that is marking the file as synced
 *
 * @return JALDB_OK, or JALDB_E_INVAL
 */
enum jaldb_status jaldb_mark_journal_synced(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host);


/**
 * Function that marks audit records as 'synced'.
 * All records up to and including \p sid
 * that were successfully delivered to \p remote_host are marked as 'synced'.
 *
 * @param[in] ctx The context
 * @param[in] sid The sid to look for
 * @param[in] remote_host The machine that is marking the file as synced
 *
 * @return JALDB_OK, or JALDB_E_INVAL
 */
enum jaldb_status jaldb_mark_audit_synced(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host);


/**
 * Function that marks log records as 'synced'.
 * All records up to and including \p sid
 * that were successfully delivered to \p remote_host are marked as 'synced'.
 *
 * @param[in] ctx The context
 * @param[in] sid The sid to look for
 * @param[in] remote_host The machine that is marking the file as synced
 *
 * @return JALDB_OK, or JALDB_E_INVAL
 */
enum jaldb_status jaldb_mark_log_synced(
	jaldb_context *ctx,
	const char *sid,
	const char *remote_host);


/**
 * Helper function to mark records in the database as being sent successfully to a
 * particular remote peer. This indicates that the remote successfully received
 * the record, however, it is still possible that the remote has not yet been
 * notified that it received the record correctly, i.e. a digest response
 * message may not have been sent, or was lost.
 *
 * @param[in] ctx The context.
 * @param[in] cont The container to look in.
 * @param[in] sid The serial ID of the record to mark as sent_ok.
 * @param[in] remote_name The name of the remote that received the record.
 */
enum jaldb_status jaldb_mark_sent_ok_common(
	jaldb_context *ctx,
	DbXml::XmlContainer *cont,
	const char *sid,
	const char *remote_host);

/**
 * Helper function to mark a journal record in the database as being sent successfully to a
 * particular remote peer. This indicates that the remote successfully received
 * the record, however, it is still possible that the remote has not yet been
 * notified that it received the record correctly, i.e. a digest response
 * message may not have been sent, or was lost.
 *
 * @param[in] ctx The context.
 * @param[in] sid The serial ID of the record to mark as sent_ok.
 * @param[in] remote_name The name of the remote that received the record.
 */
enum jaldb_status jaldb_mark_journal_sent_ok(jaldb_context *ctx, const char* sid, const char *remote_name);
/**
 * Helper function to mark an audit record in the database as being sent successfully to a
 * particular remote peer. This indicates that the remote successfully received
 * the record, however, it is still possible that the remote has not yet been
 * notified that it received the record correctly, i.e. a digest response
 * message may not have been sent, or was lost.
 *
 * @param[in] ctx The context.
 * @param[in] sid The serial ID of the record to mark as sent_ok.
 * @param[in] remote_name The name of the remote that received the record.
 */
enum jaldb_status jaldb_mark_audit_sent_ok(jaldb_context *ctx, const char* sid, const char *remote_name);

/**
 * Helper function to mark a log record in the database as being sent successfully to a
 * particular remote peer. This indicates that the remote successfully received
 * the record, however, it is still possible that the remote has not yet been
 * notified that it received the record correctly, i.e. a digest response
 * message may not have been sent, or was lost.
 *
 * @param[in] ctx The context.
 * @param[in] sid The serial ID of the record to mark as sent_ok.
 * @param[in] remote_name The name of the remote that received the record.
 */
enum jaldb_status jaldb_mark_log_sent_ok(jaldb_context *ctx, const char* sid, const char *remote_name);

/**
 * Store journal_resume data in the journal temporary system container.
 * Data stored consists of the path to the journal file and the offset.
 *
 * @param[in] ctx the context to use
 * @param[in] remote_host a string to identify where the record came from.
 * @param[in] path the path to the journal file (should be obtained using to
 *                 jaldb_create_journal_file).
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
 *                 jaldb_create_journal_file).
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
 * Retrieve a list of document names present in the container \p cont.
 *
 * @param[in] cont the container to retrieve the list from.
 * @param[in] mgr the manager to use to create the transaction.
 * @param[out] doc_list A pointer to a list returned by the function.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_document_list(
		DbXml::XmlContainer *cont,
		DbXml::XmlManager *mgr,
		std::list<std::string> **doc_list);

 /**
 * Retrieve a list of the last \p k records for journal container.
 *
 * @param[in] ctx the context to use.
 * @param[in] k the number of records to retrieve.
 * @param[out] doc_list the list of document names.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_last_k_records_journal(
		jaldb_context *ctx,
		int k,
		std::list<std::string> &doc_list);

 /**
 * Retrieve a list of the last \p k records for audit container.
 *
 * @param[in] ctx the context to use.
 * @param[in] k the number of records to retrieve.
 * @param[out] doc_list the list of document names.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_last_k_records_audit(
		jaldb_context *ctx,
		int k,
		std::list<std::string> &doc_list);

 /**
 * Retrieve a list of the last \p k records for log container.
 *
 * @param[in] ctx the context to use.
 * @param[in] k the number of records to retrieve.
 * @param[out] doc_list the list of document names.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_last_k_records_log(
		jaldb_context *ctx,
		int k,
		std::list<std::string> &doc_list);

 /**
 * Function to retrieve a list of the last \p k records
 * for the container \p cont.
 *
 * @param[in] cont the container to retrieve the list from.
 * @param[in] mgr the manager to use to create the transaction.
 * @param[in] k the number of records to retrieve.
 * @param[out] doc_list the list of document names.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_last_k_records(
		DbXml::XmlContainer *cont,
		DbXml::XmlManager *mgr,
		int k,
		std::list<std::string> &doc_list);

 /**
 * Retrieve a list of the journal records received after the record denoted
 * by \p last_sid.
 *
 * @param[in] ctx the context to use.
 * @param[in] last_sid the serial id of the last record retrieved.
 * @param[out] doc_list the list of document names.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_records_since_last_sid_journal(
		jaldb_context *ctx,
		char *last_sid,
		std::list<std::string> &doc_list);

 /**
 * Retrieve a list of the audit records received after the record denoted
 * by \p last_sid.
 *
 * @param[in] ctx the context to use.
 * @param[in] last_sid the serial id of the last record retrieved.
 * @param[out] doc_list the list of document names.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_records_since_last_sid_audit(
		jaldb_context *ctx,
		char *last_sid,
		std::list<std::string> &doc_list);

 /**
 * Retrieve a list of the log records received after the record denoted
 * by \p last_sid.
 *
 * @param[in] ctx the context to use.
 * @param[in] last_sid the serial id of the last record retrieved.
 * @param[out] doc_list the list of document names.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_records_since_last_sid_log(
		jaldb_context *ctx,
		char *last_sid,
		std::list<std::string> &doc_list);
		
 /**
 * Retrieve a list of the records received after the record denoted
 * by \p last_sid.
 *
 * @param[in] cont the container to retrieve the list from.
 * @param[in] mgr the manager to use to create the transaction.
 * @param[in] last_sid the serial id of the last record retrieved.
 * @param[out] doc_list the list of document names.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_get_records_since_last_sid(
		DbXml::XmlContainer *cont,
		DbXml::XmlManager *mgr,
		char *last_sid,
		std::list<std::string> &doc_list);

 
#endif // _JALDB_CONTEXT_HPP_
