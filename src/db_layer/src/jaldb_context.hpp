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
#include <set>
#include <string>
#include <db.h>
#include "jaldb_context.h"

struct jaldb_record_dbs;

struct jaldb_context_t {
	char *journal_root; 				//!< The journal record root path.
	char *schemas_root; 				//!< The schemas root path.
	DB_ENV *env; 					//!< The Berkeley DB Environment.
	struct jaldb_record_dbs *log_dbs; 		//!< The DBs associated with log records
	struct jaldb_record_dbs *audit_dbs; 		//!< The DBs associated with audit records
	struct jaldb_record_dbs *journal_dbs; 		//!< The DBs associated with journal records
	DB *journal_conf_db; 				//!< The database for conf'ed journal records
	DB *audit_conf_db; 				//!< The database for conf'ed audit records
	DB *log_conf_db; 				//!< The database for conf'ed log records
	int db_read_only; 				//!< Whether or not to open the databases read only
	std::set<std::string> *seen_journal_records;	//<! Journal records already seen in live mode
	std::set<std::string> *seen_audit_records;	//<! Audit records already seen in live mode
	std::set<std::string> *seen_log_records;	//<! Log records already seen in live mode
};

/**
 * Store the most recently confirmed journal record for a particular host.
 * @param[in] ctx The jaldb_context to use
 * @param[in] remote_host The host that we received a digest conf for
 * @param[in] nonce The nonce that was 'confirmed'
 * @param[out] db_err_out The error code (if any) returned by Berkeley DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_NONCE if the Nonce is sequentially after the next available
 *  Nonce ID
 *  - JALDB_E_ALREADY_CONFED if the current mapping in the database is
 *    the same as \p nonce or sequentially later.
 *  - JALDB_E_CORRUPTED is the latest nonce cannot be found. This
 *  indicates an internal problem with the database.
 *  - JALDB_E_DB if there was an error updating the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 */
enum jaldb_status jaldb_store_confed_journal_nonce(jaldb_context *ctx,
		const char *remote_host, const char *nonce, int *db_err_out);

/**
 * Store the most recently confirmed audit record for a particular host.
 * @param[in] ctx The jaldb_context to use
 * @param[in] remote_host The host that we received a digest conf for
 * @param[in] nonce The nonce that was 'confirmed'
 * @param[out] db_err_out The error code (if any) returned by Berkeley DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_ALREADY_CONFED if the current mapping in the database is
 *    the same as \p nonce or sequentially later.
 *  - JALDB_E_NONCE if the Nonce is sequentially after the next available
 *  Nonce ID
 *  - JALDB_E_CORRUPTED is the latest nonce cannot be found. This
 *  indicates an internal problem with the database.
 *  - JALDB_E_DB if there was an error updating the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 */
enum jaldb_status jaldb_store_confed_audit_nonce(jaldb_context *ctx,
		const char *remote_host, const char *nonce, int *db_err_out);

/**
 * Store the most recently confirmed log record for a particular host.
 * @param[in] ctx The jaldb_context to use
 * @param[in] remote_host The host that we received a digest conf for
 * @param[in] nonce The nonce that was 'confirmed'
 * @param[out] db_err_out The error code (if any) returned by Berkeley DB
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL if one of the parameters was invalid.
 *  - JALDB_E_ALREADY_CONFED if the current mapping in the database is
 *    the same as \p nonce or sequentially later.
 *  - JALDB_E_NONCE if the Nonce is sequentially after the next available
 *  Nonce ID
 *  - JALDB_E_CORRUPTED is the latest nonce cannot be found. This
 *  indicates an internal problem with the database.
 *  - JALDB_E_DB if there was an error updating the database, check \p db_err_out
 *  for more info.
 * @throw XmlException
 */
enum jaldb_status jaldb_store_confed_log_nonce(jaldb_context *ctx,
		const char *remote_host, const char *nonce, int *db_err_out);



/**
 * Store journal_resume data in the journal temporary system container.
 * Data stored consists of the path to the journal file and the offset.
 *
 * @param[in] ctx the context to use
 * @param[in] remote_host a string to identify where the record came from.
 * @param[in] nonce the nonce of the record being stored.
 * @param[in] path the path to the journal file (should be obtained using to
 *                 jaldb_create_file).
 * @param[in] offset the file offset.
 *
 *@return JALDB_OK - Success, an error on failure.
 */
enum jaldb_status jaldb_store_journal_resume(
		jaldb_context *ctx,
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
enum jaldb_status jaldb_clear_journal_resume(
		jaldb_context *ctx,
		const char *remote_host);


/**
 * Retrieve journal_resume data from the journal temporary system container.
 * Data retrieved consists of the path to the journal file and the offset.
 * If the journal_resume data is not found, path and offset are not altered.
 *
 * @param[in] ctx the context to use
 * @param[in] remote_host a string to identify where the record came from.
 * @param[out] nonce the nonce to the journal record being resumed.
 * @param[out] path the path to the journal file (should be obtained using to
 *                 jaldb_create_file).
 * @param[out] offset the file offset.
 *
 *@return JALDB_OK - Success, an error on failure.
 */
enum jaldb_status jaldb_get_journal_resume(
		jaldb_context *ctx,
		const char *remote_host,
		char **nonce,
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
