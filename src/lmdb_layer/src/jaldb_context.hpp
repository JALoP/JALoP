/**
 * @file
 *
 * @brief This file provides the DB context structure and
 * constants for use by the DB Layer using Lightning Memory-Mapped Database (LMDB).
 *
 * ### LICENSE
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
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
#include <lmdb-safe.h>
#include "jaldb_context.h"
#include "jaldb_translators.h"

/**
* This needs to be a C style enum for use as int-compatible
* index arguments to the lmdb tuple templates
*/
enum LmdbDbIndex {
	IDX_NETWORK_NONCE = 0,
	IDX_NONCE_TIMESTAMP,
	IDX_SENT,
	IDX_UUID,
	IDX_TIMESTAMP
};

/**
* This is used to access the LMDB Typed api
*/
using LmdbDbType = TypedDBI<JaldbRecordTranslator,
	// network_nonce - formerly network_nonce_idx_db
	// This is our "primary" key or jalID
	index_on<JaldbRecordTranslator, std::string, &JaldbRecordTranslator::networkNonce>,
	// nonce_timestamp - formerly nonce_timestamp_db
	index_on<JaldbRecordTranslator, std::string, &JaldbRecordTranslator::nonceTimestamp>,

	// sent - formerly record_sent_db
	index_on<JaldbRecordTranslator, enum jaldb_sync_stat, &JaldbRecordTranslator::synced>,
	// uuid - formerly record_id_idx_db
	// TODO: There might be a better way to do this than converting the UUID to a string
	index_on_function<JaldbRecordTranslator, std::string, UuidExtract>,
	// timestamp - formerly timestamp_idx_db
	index_on<JaldbRecordTranslator, std::string, &JaldbRecordTranslator::timestamp>
	>;

/**
* This is the LMDB Typed read/write transaction object
*/
using LmdbDbRWTransaction = LmdbDbType::RWTransaction;

/**
* This is the LMDB Typed read only transaction object
*/
using LmdbDbROTransaction = LmdbDbType::ROTransaction;

/**
* The jaldb_record_dbs struct
*/
struct jaldb_record_dbs;

/**
* The main structure to store the jal database references.
*/
struct jaldb_context_t {
	/**
	* The journal record root path.
	*/
	char *journal_root;
	/**
	* The DBs associated with log records
	*/
	struct jaldb_record_dbs* log_dbs;
	/**
	* The DBs associated with audit records
	*/
	struct jaldb_record_dbs* audit_dbs;
	/**
	* The DBs associated with journal records
	*/
	struct jaldb_record_dbs* journal_dbs;
	/**
	* The LMDB Environment.
	*/
	std::shared_ptr<MDBEnv> env;
	/**
	* Whether or not to open the databases read only
	*/
	int db_read_only;
	/**
	* Journal records already seen in live mode
	*/
	std::set<std::string> *seen_journal_records;
	/**
	* Audit records already seen in live mode
	*/
	std::set<std::string> *seen_audit_records;
	/**
	* Log records already seen in live mode
	*/
	std::set<std::string> *seen_log_records;

	//The following are used for jal_purge only

	/**
	* Path to temporary database location used during compaction.
	*/
	std::string *compact_path;
	/**
	* Path to current lmdb databases used during compaction.
	*/
	std::string *db_root;
	/**
	* The number of records to purge per transaction.
	*/
	long batch_size;
};

/**
 * Store the most recently confirmed journal record for a particular host.
 * @param[in] ctx The jaldb_context to use
 * @param[in] remote_host The host that we received a digest conf for
 * @param[in] nonce The nonce that was 'confirmed'
 * @param[out] db_err_out The error code (if any) returned by LMDB
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
 * @param[out] db_err_out The error code (if any) returned by LMDB
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
 * @param[out] db_err_out The error code (if any) returned by LMDB
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
* @param[in] get_all records of given type.
*
* @return  JALDB_OK - success
*      JALDB_E_INVAL - invalid parameter.
*      JALDB_E_DB - Error occurred in database.
*/
enum jaldb_status jaldb_get_last_k_records(
		jaldb_context *ctx,
		size_t k,
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
 * @param[in] last_nonce the nonce of the last record retrieved.
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

/**
* JaldbStat class used by jaldb_tool
*/
class JaldbStat
{
public:

	/**
	* Constructor for JaldbStat
	*/
	JaldbStat()
	{
		count = 0;
		not_sent_count = 0;
		sent_count = 0;
		synced_count = 0;
		confirmed_count = 0;
		failed_count = 0;
	}

	/**
	* Can be used to display a friendly name for display.
	*/
	std::string db_name;
	/**
	* Can be used to display a friendly name for display.
	*/
	std::string db_location;
	/**
	* Total count of the record type.
	*/
	int count;
	/**
	* Total not_sent_count of the record type.
	*/
	int not_sent_count;
	/**
	* Total sent_count of the record type.
	*/
	int sent_count;
	/**
	* Total synced_count of the record type.
	*/
	int synced_count;
	/**
	* Total confirmed_count of the record type.
	*/
	int confirmed_count;
	/**
	* Total failed_count of the record type. If db value is corrupt on retrieving the record
	*/
	int failed_count;
	/**
	* JALDB_RTYPE_JOURNAL, JALDB_RTYPE_AUDIT, or JALDB_RTYPE_LOG.
	*/
	enum jaldb_rec_type record_type;
	/**
	* The earliest time network nonce timestamp of the record type.
	*/
	std::string earliest_time;
	/**
	* The latest time network nonce timestamp of the record type.
	*/
	std::string latest_time;
};

 /**
 * Retrieve statistics on a record type.
 *
 * @param[in] ctx the context to use.
 * @param[out] stat the JaldbStat class that will be filled in with the statistics.
 * @param[in] type the record type to gather stats for
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_* - Other error occurred in database.
 */
enum jaldb_status get_stats(jaldb_context *ctx, JaldbStat& stat, enum jaldb_rec_type type);

 /**
 * Mark all records to a sync_stat.
 *
 * @param[in] ctx the context to use.
 * @param[in] record_type JALDB_RTYPE_JOURNAL, JALDB_RTYPE_AUDIT, or JALDB_RTYPE_LOG.
 * @param[in] sync_stat JALDB_NOT_SENT, JALDB_SENT, or JALDB_SYNCED.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status mark_all_records(jaldb_context *ctx, jaldb_rec_type record_type, enum jaldb_sync_stat sync_stat);

 /**
 * Removes all records from a map of nonces.
 *
 * @param[in] ctx the context to use.
 * @param[in] type JALDB_RTYPE_JOURNAL, JALDB_RTYPE_AUDIT, or JALDB_RTYPE_LOG.
 * @param[in] purge_map The map of nonces to purge from the database.
 * @param[in] exiting The boolean flag that indicates that this function should exit if the parent application is exiting.
 *
 * @return 	JALDB_OK - success
 *		JALDB_E_INVAL - invalid parameter.
 *		JALDB_E_DB - Error occurred in database.
 */
enum jaldb_status jaldb_remove_records(jaldb_context *ctx, enum jaldb_rec_type type, std::map<std::string, std::string> purge_map, int& exiting);

#endif // _JALDB_CONTEXT_HPP_
