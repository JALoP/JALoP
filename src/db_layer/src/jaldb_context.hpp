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

#ifndef _JALDB_CONTEXT_HPP_
#define _JALDB_CONTEXT_HPP_

#include <map>
#include <dbxml/DbXml.hpp>
#include <dbxml/XmlContainer.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include "jaldb_context.h"

typedef std::map<std::string, DbXml::XmlContainer> string_to_container_map;

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
	string_to_container_map *temp_containers; //<! a map from strings to XmlContainers that identifiers temporary databases for use by the network stores.
};

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
	std::string &sid);

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
 * Open a database for to store records in while communicating with a network
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

#endif // _JALDB_CONTEXT_HPP_
