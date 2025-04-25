/**
 * @file
 *
 * @brief This file implements the DB context management
 * functions using Lightning Memory-Mapped Database (LMDB).
 *
 * ### LICENSE
 *
 * Copyright (C) 2025 The National Security Agency (NSA)
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

#define __STDC_FORMAT_MACROS

#include <fcntl.h>
#include <jalop/jal_status.h>
#include <inttypes.h> // For PRIu64
#include <list>
#include <sstream>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lmdb-safe.h"
#include "lmdb-typed.h"

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"
#include "jal_asprintf_internal.h"

#include "jaldb_context.hpp"
#include "jaldb_record.h"
#include "jaldb_record_dbs.h"
#include "jaldb_record_xml.h"
#include "jaldb_segment.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"

#define DEFAULT_DB_ROOT "/var/lib/jalop/db"

static enum jaldb_status jaldb_remove_record_from_db(jaldb_context *ctx, jaldb_record_dbs *rdbs, const char *nonce);

jaldb_context *jaldb_context_create()
{
	jaldb_context *context = (jaldb_context *)jal_calloc(1, sizeof(*context));
	return context;
}

enum jaldb_status jaldb_get_db_flags(
	const char *config_database_option,
	enum jaldb_flags *jdb_flags)
{
	if (NULL == jdb_flags)
	{
		return JALDB_E_INVAL;
	}

	if (NULL == config_database_option)
	{
		//NULL is ok, indicates no flags, so default to JDB_NONE
		*jdb_flags = JDB_NONE;
		return JALDB_OK;
	}

	std::string curr_db_option(config_database_option);
	if (JDB_NONE_STR == curr_db_option)
	{
		*jdb_flags = JDB_NONE;
	}
	else if (JDB_LMDB_PERFORMANCE_LEVEL1_STR == curr_db_option)
	{
		*jdb_flags = JDB_LMDB_PERFORMANCE_LEVEL1;
	}
	else if (JDB_LMDB_PERFORMANCE_LEVEL2_STR == curr_db_option)
	{
		*jdb_flags = JDB_LMDB_PERFORMANCE_LEVEL2;
	}
	else if (JDB_LMDB_PERFORMANCE_LEVEL3_STR == curr_db_option)
	{
		*jdb_flags = JDB_LMDB_PERFORMANCE_LEVEL3;
	}
	else
	{
		return JALDB_E_INVAL;
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_context_init(
	jaldb_context *ctx,
	const char *db_root,
	enum jaldb_flags jdb_flags)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}

	// Make certain that the context is not already initialized.
	if (ctx->env || ctx->journal_root) {
		return JALDB_E_INITIALIZED;
	}

	if (!db_root) {
		db_root = DEFAULT_DB_ROOT;
	}

	struct stat db_root_stat;
	int rc = stat(db_root, &db_root_stat);
	if (0 != rc) {
		fprintf(stderr, "ERROR: db_root not found.\n");
		return JALDB_E_INVAL;
	}
	if (!S_ISDIR(db_root_stat.st_mode)) {
		fprintf(stderr, "ERROR: db_root must be directory.\n");
		return JALDB_E_INVAL;
	}

	if (-1 == jal_asprintf(&ctx->journal_root, "%s%s", db_root, JALDB_JOURNAL_ROOT_NAME)) {
		return JALDB_E_NO_MEM;
	}

	//Setup lmdb environment
	std::shared_ptr<MDBEnv> lmdb_env;

	//Default is JDB_NONE (no flags)
	uint32_t env_flags = 0;
	if (JDB_READONLY == jdb_flags)
	{
		ctx->db_read_only = 1;
		env_flags |= MDB_RDONLY;
	}
	else if (JDB_LMDB_PERFORMANCE_LEVEL1 == jdb_flags)
	{
		env_flags |= MDB_NOMETASYNC;
	}
	else if (JDB_LMDB_PERFORMANCE_LEVEL2 == jdb_flags)
	{
		env_flags |= MDB_NOMETASYNC | MDB_NOSYNC;
	}
	else if (JDB_LMDB_PERFORMANCE_LEVEL3 == jdb_flags)
	{
		env_flags |= MDB_NOMETASYNC | MDB_NOSYNC | MDB_WRITEMAP | MDB_MAPASYNC;
	}

	try
	{
		lmdb_env = getMDBEnv(db_root, env_flags, 0600);

		if(JALDB_OK != jaldb_create_primary_dbs_with_indices(
				db_root, lmdb_env, "log", env_flags, &ctx->log_dbs)) {
			return JALDB_E_INVAL;
		}

		if(JALDB_OK != jaldb_create_primary_dbs_with_indices(
				db_root, lmdb_env, "audit", env_flags, &ctx->audit_dbs)) {
			return JALDB_E_INVAL;
		}

		if(JALDB_OK != jaldb_create_primary_dbs_with_indices(
				db_root, lmdb_env, "journal", env_flags, &ctx->journal_dbs)) {
			return JALDB_E_INVAL;
		}
	}
	catch(std::runtime_error &err)
	{
		fprintf(stderr, "ERROR: Failed to initialize LMDB environment: %s\n", err.what());
		return JALDB_E_INVAL;
	}

	ctx->env = lmdb_env;

	ctx->seen_journal_records = new std::set<std::string>();
	ctx->seen_audit_records = new std::set<std::string>();
	ctx->seen_log_records = new std::set<std::string>();

	return JALDB_OK;
}

void jaldb_context_destroy(jaldb_context **ctx)
{
	if (!ctx || !(*ctx)) {
		return;
	}
	jaldb_context *ctxp = *ctx;

	free(ctxp->journal_root);

	jaldb_destroy_record_dbs(&(ctxp->log_dbs));
	jaldb_destroy_record_dbs(&(ctxp->audit_dbs));
	jaldb_destroy_record_dbs(&(ctxp->journal_dbs));

	delete ctxp->seen_journal_records;
	delete ctxp->seen_audit_records;
	delete ctxp->seen_log_records;
	delete ctxp->db_root;
	delete ctxp->compact_path;

	ctxp->env = NULL;
	free(ctxp);
	*ctx = NULL;
}

std::string jaldb_make_temp_db_name(const std::string &id, const std::string &suffix)
{
	std::stringstream o;
	o << "__" << id << "_" << suffix;
	return o.str();
}

enum class MarkType {
	NOT_SENT,
	SENT,
	SYNC,
	CONFIRM,
	NOT_CONFIRM,
};

// Note: nonce_out is used only when markType = MarkType::CONFIRM
// to return a copy of the updated network_nonce (must be freed by caller)
// when markType == MarkType::CONFIRM
//   nonce_out must be non-NULL
//   *nonce_out must be NULL
// In other cases, nonce_out must be NULL
static enum jaldb_status jaldb_mark(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *nonce,
	MarkType markType,
	char** nonce_out)
{
	enum jaldb_status ret = JALDB_OK;

	if (!ctx || !type || !nonce) {
		return JALDB_E_INVAL;
	}

	// If we are doing a confirm, nonce_out must be non-NULL and *nonce_out must be NULL
	if(MarkType::CONFIRM == markType && (!nonce_out || *nonce_out)) {
		return JALDB_E_INVAL;
	}
	// Otherwise, nonce_out is unused and should be NULL
	else if (MarkType::CONFIRM != markType && nonce_out) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	std::string key = std::string(nonce);

	try {
		LmdbDbRWTransaction txn = rdbs->primary_db->getRWTransaction();

		JaldbRecordTranslator rec;
		int recordId = 0;
		try
		{
			recordId = txn.get<LmdbDbIndex::IDX_NETWORK_NONCE>(key, rec);
		}
		catch(std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_mark - Failed to retrieve record: %s\n", err.what());
			txn.abort();
			return JALDB_E_DB;
		}

		// Found no matching record for specified nonce
		if(0 == recordId)
		{
			txn.abort();
			return  JALDB_E_NOT_FOUND;
		}

		// Check to see if state matches target - nothing to do if they match
		switch(markType) {
			case MarkType::NOT_SENT:
				if(JALDB_NOT_SENT == rec.synced)
				{
					txn.abort();
				}
				// Update the state
				else {
					txn.modify(recordId, [](JaldbRecordTranslator& r) {
							r.synced = JALDB_NOT_SENT;
							});
					txn.commit();
				}
			break;
			case MarkType::SENT:
				if(JALDB_SENT == rec.synced)
				{
					txn.abort();
				}
				// Update the state
				else {
					txn.modify(recordId, [](JaldbRecordTranslator& r) {
							r.synced = JALDB_SENT;
							});
					txn.commit();
				}
			break;
			case MarkType::SYNC:
				if(JALDB_SYNCED == rec.synced)
				{
					txn.abort();
				}
				// Update the state
				else {
					txn.modify(recordId, [](JaldbRecordTranslator& r) {
							r.synced = JALDB_SYNCED;
							});
					txn.commit();
				}
			break;
			case MarkType::CONFIRM:
				// No change, skip db write
				if(rec.confirmed)
				{
					txn.abort();
				}
				// Update the state
				// In addition to updating the confirmed flag
				// we're also going to regenerate the networkNonce(a.k.a JALId)
				// Internally this will also update the nonceTimestamp
				// This is to cover the case where we're daisy-chaining network stores
				// and a publisher is reading from this same subscriber db. Regenerating the
				// networkNonce will make it appears as if the record had just been inserted by
				// a producer into the local store by this process, and updating the timestamp makes
				// sure it will be picked up by a live-mode publisher
				else {
					txn.modify(recordId, [nonce_out](JaldbRecordTranslator& r) {
						r.confirmed = true;
						// may throw std::runtime_error
						r.regenNetworkNonce();
						if(nonce_out) {
							*nonce_out = strdup(r.networkNonce.c_str());
						}
					});
					txn.commit();
				}
				break;
			case MarkType::NOT_CONFIRM:
				// Currently unused
				// Will cause the record to adopt a new JalID and appear as if it was just inserted
				// anew when the record is later re-confirmed
				if(JALDB_SYNCED == rec.synced)
				{
					txn.abort();
				}
				// Update the state
				else {
					txn.modify(recordId, [](JaldbRecordTranslator& r) {
							r.synced = JALDB_SYNCED;
							});
					txn.commit();
				}
			break;
		}
		return JALDB_OK;

	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_mark - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_mark - unknown error occurred\n");
		return JALDB_E_DB;
	}
	// Unreachable
}

enum jaldb_status jaldb_mark_sent(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *nonce,
	int target_state)
{
	if(0 == target_state) {
		return jaldb_mark(ctx, type, nonce, MarkType::NOT_SENT, NULL);
	} else if (1 == target_state) {
		return jaldb_mark(ctx, type, nonce, MarkType::SENT, NULL);
	} else {
		return JALDB_E_INVAL;
	}
}

enum jaldb_status jaldb_mark_synced(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *nonce)
{
	return jaldb_mark(
		ctx,
		type,
		nonce,
		MarkType::SYNC,
		NULL);
}

enum jaldb_status jaldb_mark_confirmed(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *network_nonce,
	char** nonce_out)
{
	return jaldb_mark(
			ctx,
			type,
			network_nonce,
			MarkType::CONFIRM,
			nonce_out);
}

enum jaldb_status jaldb_store_journal_resume(
	jaldb_context *ctx,
	const char *remote_host,
	const char *nonce,
	const char *path,
	uint64_t offset)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;

	std::string offset_key;
	std::string offset_val;

	std::string path_key;
	std::string path_val;

	std::string nonce_key;
	std::string nonce_val;

	if (!ctx || !remote_host || !path || !nonce) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	db_ret = jaldb_get_primary_record_dbs(ctx, JALDB_RTYPE_JOURNAL, &rdbs);
	if (JALDB_OK != db_ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	offset_key = std::string(JALDB_OFFSET_NAME);
	path_key = std::string(JALDB_JOURNAL_PATH);
	nonce_key = std::string(JALDB_RESUME_NONCE_NAME);

	// Create the three value strings (and sizes) for the DB calls.
	offset_val = std::to_string(offset);
	path_val = std::string(path);
	nonce_val = std::string(nonce);

	MDBRWTransaction txn;
	try {

		try
		{
			txn = ctx->env->getRWTransaction();
		}
		catch(std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_store_journal_resume - Failed to get database transaction: %s\n", err.what());
			ret = JALDB_E_DB;
			return ret;
		}

		/* Store the offset for the record */
		try
		{
			txn->put(rdbs->metadata_db, offset_key, offset_val);
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_store_journal_resume - Failed to insert offset record: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}

		/* Store the path for the record */
		try
		{
			txn->put(rdbs->metadata_db, path_key, path_val);
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_store_journal_resume - Failed to insert path record: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}

		/* Store the nonce for the record */
		try
		{
			txn->put(rdbs->metadata_db, nonce_key, nonce_val);
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_store_journal_resume - Failed to insert nonce record: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}

		/* Commit the database transactions */
		try
		{
			txn->commit();
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_store_journal_resume - Failed to commit transaction: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_store_journal_resume - exception: %s\n", err.what());
		txn->abort();
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_store_journal_resume - unknown error occurred\n");
		txn->abort();
		return JALDB_E_DB;
	}

	return ret;
}

enum jaldb_status jaldb_clear_journal_resume(
	jaldb_context *ctx,
	const char *remote_host)
{
	enum jaldb_status ret = JALDB_OK;
	std::string offset_key;
	std::string path_key;
	std::string nonce_key;
	int db_ret;

	if (!ctx || !remote_host) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	db_ret = jaldb_get_primary_record_dbs(ctx, JALDB_RTYPE_JOURNAL, &rdbs);
	if (JALDB_OK != db_ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	/* Create the three key strings (and sizes) for the DB calls.*/
	offset_key = std::string(JALDB_OFFSET_NAME);
	path_key = std::string(JALDB_JOURNAL_PATH);
	nonce_key = std::string(JALDB_RESUME_NONCE_NAME);

	MDBRWTransaction txn;
	try {
		try
		{
			txn = ctx->env->getRWTransaction();
		}
		catch(std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_clear_journal_resume - Failed to get database transaction: %s\n", err.what());
			ret = JALDB_E_DB;
			return ret;
		}

		/* Delete the offset for the record */
		try
		{
			db_ret = txn->del(rdbs->metadata_db, offset_key);

			if (0 != db_ret)
			{
				txn->abort();
				ret = JALDB_E_DB;
				return ret;
			}
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_clear_journal_resume - Failed to delete offset record: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}

		/* Delete the path for the record */
		try
		{
			db_ret = txn->del(rdbs->metadata_db, path_key);

			if (0 != db_ret)
			{
				txn->abort();
				ret = JALDB_E_DB;
				return ret;
			}
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_clear_journal_resume - Failed to delete path record: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}

		/* Delete the nonce for the record */
		try
		{
			db_ret = txn->del(rdbs->metadata_db, nonce_key);

			if (0 != db_ret)
			{
				txn->abort();
				ret = JALDB_E_DB;
				return ret;
			}
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_clear_journal_resume - Failed to delete nonce record: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}

		/* Commit the database transactions */
		try
		{
			txn->commit();
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_clear_journal_resume - Failed to commit transaction: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_clear_journal_resume - exception: %s\n", err.what());
		txn->abort();
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_clear_journal_resume - unknown error occurred\n");
		txn->abort();
		return JALDB_E_DB;
	}

	return ret;
}

enum jaldb_status jaldb_get_journal_resume(
		jaldb_context *ctx,
		const char *remote_host,
		char **nonce,
		char **path,
		uint64_t &offset)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;
	std::string offset_key;
	string_view offset_val;

	std::string path_key;
	string_view path_val;

	std::string nonce_key;
	string_view nonce_val;

	if (!ctx || !remote_host || !path || !nonce) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	db_ret = jaldb_get_primary_record_dbs(ctx, JALDB_RTYPE_JOURNAL, &rdbs);
	if (JALDB_OK != db_ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	/* Create the three key strings (and sizes) for the DB calls.*/
	offset_key = std::string(JALDB_OFFSET_NAME);
	path_key = std::string(JALDB_JOURNAL_PATH);
	nonce_key = std::string(JALDB_RESUME_NONCE_NAME);

	MDBROTransaction txn;
	try {
		try
		{
			txn = ctx->env->getROTransaction();
		}
		catch(std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_get_journal_resume - Failed to get database transaction: %s\n", err.what());
			ret = JALDB_E_DB;
			return ret;
		}

		/* Get the offset for the record. offset_val.data is allocated by the DB and freed by us */
		try
		{
			db_ret = txn->get(rdbs->metadata_db, offset_key, offset_val);

			if (0 != db_ret) {
				txn->abort();
				ret = JALDB_E_DB;
				return ret;
			}
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_get_journal_resume - Failed to retrieve offset record: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}

		/* Get the path for the record. path_val.data is allocated by the DB and freed by us */
		try
		{
			db_ret = txn->get(rdbs->metadata_db, path_key, path_val);

			if (0 != db_ret) {
				txn->abort();
				ret = JALDB_E_DB;
				return ret;
			}
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_get_journal_resume - Failed to retrieve path record: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}

		/* Get the nonce for the record. nonce_val.data is allocated by the DB and freed by us */
		try
		{
			db_ret = txn->get(rdbs->metadata_db, nonce_key, nonce_val);

			if (0 != db_ret) {
				txn->abort();
				ret = JALDB_E_DB;
				return ret;
			}
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_get_journal_resume - Failed to retrieve nonce record: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}

		/* Commit the database transactions */
		/* If DB_TXN.commit encounters an error, the transaction and all child transactions of the transaction are aborted. */
		try
		{
			txn->commit();
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_get_journal_resume - Failed to commit transaction: %s\n", err.what());
			txn->abort();
			ret = JALDB_E_DB;
			return ret;
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_get_journal_resume - exception: %s\n", err.what());
		txn->abort();
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_get_journal_resume - unknown error occurred\n");
		txn->abort();
		return JALDB_E_DB;
	}

	/* Check for a well formatted offset */
	if(0 > sscanf((char*)std::string(offset_val).c_str(), "%" PRIu64, &offset)) {
		ret = JALDB_E_CORRUPTED;
	}

	/* allocate memory for return value */
	*nonce = (char *)strdup(std::string(nonce_val).c_str());

	/* allocate memory for return value */
	*path = (char *)strdup(std::string(path_val).c_str());

	return ret;
}

enum jaldb_status jaldb_get_journal_document_list(
	jaldb_context *ctx,
	std::list<std::string> **doc_list)
{
	enum jaldb_status ret = JALDB_OK;
	ret = jaldb_get_all_records(ctx, doc_list, JALDB_RTYPE_JOURNAL);
	return ret;
}

enum jaldb_status jaldb_get_audit_document_list(
		jaldb_context *ctx,
		std::list<std::string> **doc_list)
{
	enum jaldb_status ret = JALDB_OK;
	ret = jaldb_get_all_records(ctx, doc_list, JALDB_RTYPE_AUDIT);
	return ret;
}

enum jaldb_status jaldb_get_log_document_list(
		jaldb_context *ctx,
		std::list<std::string> **doc_list)
{
	enum jaldb_status ret = JALDB_OK;
	ret = jaldb_get_all_records(ctx, doc_list, JALDB_RTYPE_LOG);
	return ret;
}

enum jaldb_status jaldb_get_last_k_records(
		jaldb_context *ctx,
		size_t k,
		std::list<std::string> &nonce_list,
		enum jaldb_rec_type type,
		bool get_all)
{
	enum jaldb_status ret = JALDB_OK;

	if (!ctx) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	try {
		LmdbDbROTransaction txn = rdbs->primary_db->getROTransaction();

		// Loop through all keys in main db
		size_t count = 0;
		for(auto iter = txn.rbegin<LmdbDbIndex::IDX_TIMESTAMP>();
				iter != txn.end() && (count < k || get_all);
				--iter) {
			nonce_list.push_front(iter->networkNonce);
			++count;
		}
		if(0 == nonce_list.size()) {
			return JALDB_E_INVAL;
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_get_last_k_records - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_get_last_k_records - unknown error occurred\n");
		return JALDB_E_DB;
	}
	return ret;
}

enum jaldb_status jaldb_get_all_records(
		jaldb_context *ctx,
		std::list<std::string> **nonce_list,
		enum jaldb_rec_type type)
{
	if (!ctx || !nonce_list || *nonce_list) {
		return JALDB_E_INVAL;
	}

	enum jaldb_status ret = JALDB_OK;
	*nonce_list = new std::list<std::string>;
	ret = jaldb_get_last_k_records(ctx, 0, **nonce_list, type, true);
	return ret;
}

enum jaldb_status jaldb_get_records_since_last_nonce(
	jaldb_context *ctx,
	char *last_nonce,
	std::list<std::string> &nonce_list,
	enum jaldb_rec_type type)
{
	enum jaldb_status ret = JALDB_OK;

	if (!ctx) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	if (!last_nonce || 0 == strlen(last_nonce)) {
		ret = JALDB_E_INVAL;
		return ret;
	}

	try {
		LmdbDbROTransaction txn = rdbs->primary_db->getROTransaction();

		// Add records to the list until we find a match for the network nonce
		// by starting at the end of the index, most recent records to less recent
		std::string last_nonce_str(last_nonce);
		bool found = false;

		for(auto iter = txn.rbegin<LmdbDbIndex::IDX_TIMESTAMP>();
				iter != txn.end();
				--iter) {

			if (iter->networkNonce == last_nonce_str)
			{
				found = true;
				break;
			}

			nonce_list.push_front(iter->networkNonce);
		}

		/* Check to see if we've hit the beginning of the DB, which means we did not find the nonce */
		/* Return a separate error code to indicate this along with the list of nonces */
		if (false == found)
		{
			ret = JALDB_E_NOT_FOUND;
			return ret;
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_get_records_since_last_nonce - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_get_records_since_last_nonce - unknown error occurred\n");
		return JALDB_E_DB;
	}

	return ret;
}

enum jaldb_status jaldb_insert_record(
	jaldb_context *ctx,
	struct jaldb_record *rec,
	int confirmed,
	char **local_nonce,
	long long record_size_limit)
{
	enum jaldb_status ret;
	int update_network_nonce = 0;

	if (!ctx || !rec || !local_nonce || *local_nonce) {
		return JALDB_E_INVAL;
	}
	if (!rec->source) {
		rec->source = jal_strdup("localhost");
	}
	if (!rec->network_nonce) {
		update_network_nonce = 1;
	}

	ret = jaldb_record_sanity_check(rec, record_size_limit);
	if (ret != JALDB_OK) {
		return ret;
	}

	rec->confirmed = confirmed ? 1 : 0;

	struct jaldb_record_dbs *rdbs = NULL;
	ret = jaldb_get_primary_record_dbs(ctx, rec->type, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	std::string key;
	try {

		LmdbDbRWTransaction txn = rdbs->primary_db->getRWTransaction();
		if (update_network_nonce) {
			char *primary_key = jaldb_gen_primary_key(rec->uuid);
			if (NULL == primary_key) {
				txn.abort();
				ret = JALDB_E_INVAL;
				return ret;
			}

			key = std::string(primary_key);
			free(rec->network_nonce);
			// Give the primary key to the network_nonce since we
			// would otherwise immediately free it anyway
			rec->network_nonce = primary_key;
		}
		else
		{
			key = std::string(rec->network_nonce);
		}

		try
		{
			txn.put(JaldbRecordTranslator::fromCStruct(*rec));
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_insert_record - Failed to insert record: %s\n", err.what());
			txn.abort();
			ret = JALDB_E_DB;
			return ret;
		}

		/* Commit the database transaction */
		try
		{
			txn.commit();
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_insert_record - Failed to commit transaction: %s\n", err.what());
			txn.abort();
			ret = JALDB_E_DB;
			return ret;
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_insert_record - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_insert_record- unknown error occurred\n");
		return JALDB_E_DB;
	}

	*local_nonce = (char *)strdup(key.c_str());
	return ret;
}

enum jaldb_status jaldb_get_record(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	char *nonce,
	struct jaldb_record **recpp)
{
	struct jaldb_record *rec = NULL;

	enum jaldb_status ret;
	int db_ret = 0;

	if (!ctx || !nonce || !recpp || *recpp) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	db_ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != db_ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	try {
		LmdbDbROTransaction txn = rdbs->primary_db->getROTransaction();
		try
		{
			JaldbRecordTranslator r;
			db_ret = txn.get<LmdbDbIndex::IDX_NETWORK_NONCE>(std::string(nonce), r);
			if(0 == db_ret) {
				return JALDB_E_NOT_FOUND;
			}
			rec = r.generateCStruct();
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_get_record - Failed to retrieve record: %s\n", err.what());
			ret = JALDB_E_DB;
			return ret;
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_get_record - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_get_record - unknown error occurred\n");
		return JALDB_E_DB;
	}

	*recpp = rec;
	rec = NULL;
	ret = JALDB_OK;
	return ret;
}

// TODO: The previous logic assumed there would only be 1 record with a specific UUID
// This is not enforced by the db, but this function will always return only 1
enum jaldb_status jaldb_get_record_by_uuid(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		uuid_t uuid,
		char **nonce,
		struct jaldb_record **recpp)
{
	struct jaldb_record *rec = NULL;

	enum jaldb_status ret;
	int db_ret = 0;

	if (!ctx || !nonce || !recpp || *recpp) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	db_ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != db_ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	try {
		LmdbDbROTransaction txn = rdbs->primary_db->getROTransaction();
		try
		{
			JaldbRecordTranslator r;
			#ifndef UUID_STR_LEN
			constexpr int  UUID_STR_LEN = 37;
			#endif
			char uuidCStr[UUID_STR_LEN] = {0};
			uuid_unparse_lower(uuid, uuidCStr);
			db_ret = txn.get<LmdbDbIndex::IDX_UUID>(std::string(uuidCStr), r);
			rec = r.generateCStruct();
			// Set the out-param nonce
			*nonce = strdup(r.networkNonce.c_str());
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_get_record_by_uuid - Failed to retrieve record: %s\n", err.what());
			ret = JALDB_E_DB;
			return ret;
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_get_record_by_uuid - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_get_record_by_uuid - unknown error occurred\n");
		return JALDB_E_DB;
	}

	*recpp = rec;
	rec = NULL;
	ret = JALDB_OK;
	return ret;
}

enum jaldb_status jaldb_open_segment_for_read(jaldb_context *ctx, struct jaldb_segment *s)
{
	char *path = NULL;
	int fd = -1;
	if (!ctx || !s || !s->on_disk || !s->payload || (0 == strlen((char*)s->payload))) {
		return JALDB_E_INVAL;
	}
	if (s->fd != -1) {
		return JALDB_OK;
	}
	jal_asprintf(&path, "%s/%s", ctx->journal_root, (char*)s->payload);
	fd = open(path, O_RDONLY);
	free(path);
	path = NULL;
	if (-1 == fd) {
		return JALDB_E_UNKNOWN;
	}

	s->fd = fd;
	return JALDB_OK;
}

enum jaldb_status jaldb_remove_records(jaldb_context *ctx, enum jaldb_rec_type type, std::map<std::string, std::string> purge_map, int& exiting)
{
	int db_ret;
	enum jaldb_status ret;
	struct jaldb_record_dbs *rdbs = NULL;
	long batchSize = ctx->batch_size;

	//Ensure that batch size is always at least 1
	if (batchSize < 1)
	{
		batchSize = 1;
	}

	db_ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (0 != db_ret || !rdbs || !rdbs->primary_db) {
		ret = JALDB_E_INVAL;
		return ret;
	}

	try {
		//Purge records via batch size if specified
		std::map<std::string, std::string>::iterator iter;
		for (iter = purge_map.begin(); iter != purge_map.end();) {
			LmdbDbRWTransaction txn = rdbs->primary_db->getRWTransaction();
			for (long i = 0; i < batchSize && iter != purge_map.end(); ++i, ++iter)
			{
				if (exiting) {
					break;
				}

				try
				{
					// Find the corresponding nonce
					JaldbRecordTranslator r;
					auto id = txn.get<LmdbDbIndex::IDX_NETWORK_NONCE>(iter->first, r);

					if(0 == id)
					{
						fprintf(stderr, "ERROR: failed to remove record: %s\n", iter->first.c_str());
					}
					else
					{
						txn.del(id);

						// Remove any on-disk payload file.
						std::string currPath = iter->second;
						if (!currPath.empty() && 0 < currPath.length()) {
							unlink((char*)currPath.c_str());
						}

						fprintf(stdout, "NONCE: %s Deleted\n", iter->first.c_str());
					}

				}
				catch (std::runtime_error &err)
				{
					fprintf(stderr, "ERROR: jaldb_remove_record_from_db - Failed to remove record: %s\n", err.what());
					txn.abort();
					ret = JALDB_E_DB;
					return ret;
				}
			}

			txn.commit();
			if (exiting) {
				break;
			}
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_remove_record_from_db - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_remove_record_from_db - unknown error occurred\n");
		return JALDB_E_DB;
	}
	ret = JALDB_OK;
	return ret;
}

enum jaldb_status jaldb_remove_record(jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *nonce)
{
	int db_ret;
	enum jaldb_status ret;
	struct jaldb_record_dbs *rdbs = NULL;

	db_ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (0 != db_ret || !rdbs || !rdbs->primary_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	ret = jaldb_remove_record_from_db(ctx, rdbs, nonce);

out:
	return ret;
}

enum jaldb_status jaldb_remove_record_from_db(
	jaldb_context *ctx,
	jaldb_record_dbs *rdbs,
	const char *nonce)
{
	enum jaldb_status ret;
	std::string key;

	if (!ctx || !nonce || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	key = std::string(nonce);

	try {
		LmdbDbRWTransaction txn = rdbs->primary_db->getRWTransaction();
		try
		{
			// Find the corresponding nonce
			JaldbRecordTranslator r;
			auto id = txn.get<LmdbDbIndex::IDX_NETWORK_NONCE>(key, r);

			if(0 == id)
			{
				txn.abort();
				ret = JALDB_E_NOT_FOUND;
				return ret;
			}

			txn.del(id);
			txn.commit();
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_remove_record_from_db - Failed to remove record: %s\n", err.what());
			txn.abort();
			ret = JALDB_E_DB;
			return ret;
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_remove_record_from_db - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_remove_record_from_db - unknown error occurred\n");
		return JALDB_E_DB;
	}
	ret = JALDB_OK;
	return ret;
}

enum jaldb_status jaldb_remove_segments_from_disk(jaldb_context *ctx, struct jaldb_record *rec)
{
	enum jaldb_status ret = JALDB_OK;
	enum jaldb_status tmp = JALDB_OK;
	tmp = jaldb_remove_segment_from_disk(ctx, rec->sys_meta);
	if (tmp != JALDB_OK) {
		ret = tmp;
	}
	tmp = jaldb_remove_segment_from_disk(ctx, rec->app_meta);
	if (tmp != JALDB_OK) {
		ret = tmp;
	}
	tmp = jaldb_remove_segment_from_disk(ctx, rec->payload);
	if (tmp != JALDB_OK) {
		ret = tmp;
	}
	return ret;
}

enum jaldb_status jaldb_remove_segment_from_disk(jaldb_context *ctx, struct jaldb_segment *segment)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}
	if (!segment) {
		return JALDB_OK;
	}
	if (!segment->on_disk) {
		return JALDB_OK;
	}
	char *path = NULL;
	jal_asprintf(&path, "%s/%s", ctx->journal_root, (char*)segment->payload);
	unlink(path);
	free(path);
	return JALDB_OK;
}

enum jaldb_status jaldb_mark_unsynced_records_unsent(
		jaldb_context *ctx,
		enum jaldb_rec_type type)
{
	enum jaldb_status ret = JALDB_OK;

	if (!ctx) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	try {
		LmdbDbRWTransaction txn = rdbs->primary_db->getRWTransaction();

		auto range = txn.equal_range<LmdbDbIndex::IDX_SENT>(JALDB_SENT);
		// Loop over all records marked sent but not synced (same enum, different value)
		for(auto iter = std::move(range.first); iter != range.second; ++iter)
		{
			txn.modify(iter.getID(), [](JaldbRecordTranslator& r) {
				r.synced = JALDB_NOT_SENT;
				});
		}

		/* Commit the database transaction */
		try
		{
			txn.commit();
		}
		catch (std::runtime_error &err)
		{
			fprintf(stderr, "ERROR: jaldb_mark_unsynced_records_unsent - Failed to commit transaction: %s\n", err.what());
			txn.abort();
			ret = JALDB_E_DB;
			return ret;
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_mark_unsynced_records_unsent - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_mark_unsynced_records_unsent - unknown error occurred\n");
		return JALDB_E_DB;
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_next_unsynced_record(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		char **network_nonce,
		struct jaldb_record **rec_out)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	struct jaldb_record *rec = NULL;

	if (!ctx || !network_nonce || *network_nonce || !rec_out || *rec_out) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	enum jaldb_status db_ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != db_ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	try
	{
		LmdbDbROTransaction txn = rdbs->primary_db->getROTransaction();

		// This function is used for archive mode, which sends all the unsynced records
		// that are confirmed (skips unconfirmed records)
		// Loop through and find first unsynced and confirmed record
		bool found = false;
		auto range = txn.equal_range<LmdbDbIndex::IDX_SENT>(JALDB_NOT_SENT);
		for(auto iter = std::move(range.first); iter != range.second; ++iter) {

			// Skip unconfirmed records
			if(true != iter->confirmed)
			{
				continue;
			}
			rec = iter->generateCStruct();
			*network_nonce = strdup(iter->networkNonce.c_str());
			found = true;
			break;
		}

		if (true != found)
		{
			ret = JALDB_E_NOT_FOUND;
			return ret;
		}

		*rec_out = rec;
		rec = NULL;
		ret = JALDB_OK;
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_next_unsynced_record - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_next_unsynced_record - unknown error occurred\n");
		return JALDB_E_DB;
	}

	return ret;
}

enum jaldb_status jaldb_next_chronological_record(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		char **network_nonce,
		struct jaldb_record **rec_out,
		char **timestamp)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	struct jaldb_record *rec = NULL;
	std::set <std::string> *seen_records = NULL;

	if (!ctx || !network_nonce || *network_nonce || !rec_out || *rec_out) {
		return JALDB_E_INVAL;
	}

	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		seen_records = ctx->seen_journal_records;
		break;
	case JALDB_RTYPE_AUDIT:
		seen_records = ctx->seen_audit_records;
		break;
	case JALDB_RTYPE_LOG:
		seen_records = ctx->seen_log_records;
		break;
	default:
		ret = JALDB_E_INVAL;
		return ret;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	// Starting at a given time (timestamp), which corresponds to the nonce_timestamp
	// index, find the first record which we have not seen before (seen_records)
	// which persists in the ctx because the original designer of this code was stupid
	// NOTE: seen_{journal|audit|log}_records persistence in the ctx is required for this function to work properly
	// Once found, add this record to our seen_records and return it to the caller
	// When we detect we have advanced to a new timestamp, clear out the seen records
	// to prevent it from getting huge, the timestamp starting point will prevent us
	// from revisiting

	try
	{
		LmdbDbROTransaction txn = rdbs->primary_db->getROTransaction();

		// Need to keep this iterator after the loop
		auto iter = txn.lower_bound<LmdbDbIndex::IDX_NONCE_TIMESTAMP>(*timestamp);
		for(; iter != txn.end(); ++iter) {
			// Is our new record a new timestamp?
			// We used to convert to time_t but... why?
			if(0 != strcmp(iter->nonceTimestamp.c_str(), *timestamp))
			{
				seen_records->clear();
				// record the new timestamp
				free(*timestamp);
				*timestamp = strdup(iter->nonceTimestamp.c_str());
			}

			// If we haven't seen this new record, record it
			if (seen_records->count(iter->networkNonce) == 0) {
				seen_records->insert(iter->networkNonce);
				break;
			}
		}

		// Check if we found no new records
		if(iter == txn.end()) {
			ret = JALDB_E_NOT_FOUND;
			return ret;
		}

		// Generate the C version of the record
		rec = iter->generateCStruct();
		*network_nonce = jal_strdup(rec->network_nonce);
		if (NULL == network_nonce) {
			ret = JALDB_E_NO_MEM;
			return ret;
		}
		*rec_out = rec;
		rec = NULL;
		ret = JALDB_OK;
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_next_chronological_record - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_next_chronological_record - unknown error occurred\n");
		return JALDB_E_DB;
	}

	return ret;
}

enum jaldb_status jaldb_get_primary_record_dbs(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		struct jaldb_record_dbs **rdbs)
{
	if (!ctx || !rdbs) {
		return JALDB_E_INVAL;
	}

	switch (type) {
		case JALDB_RTYPE_JOURNAL:
			*rdbs = ctx->journal_dbs;
			break;
		case JALDB_RTYPE_AUDIT:
			*rdbs = ctx->audit_dbs;
			break;
		case JALDB_RTYPE_LOG:
			*rdbs = ctx->log_dbs;
			break;
		default:
			return JALDB_E_INVAL;
	}

	return JALDB_OK;
}

enum jaldb_status jaldb_compact_lmdb(
		jaldb_context *ctx,
		enum jaldb_rec_type type)
{
	struct jaldb_record_dbs *rdbs = NULL;
	enum jaldb_status ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db)
	{
		return JALDB_E_INVAL;
	}

	std::string db_name;
	switch (type) {
		case JALDB_RTYPE_JOURNAL:
			db_name = "journal_records.mdb";
			break;
		case JALDB_RTYPE_AUDIT:
			db_name = "audit_records.mdb";
			break;
		case JALDB_RTYPE_LOG:
			db_name = "log_records.mdb";
			break;
		default:
			return JALDB_E_INVAL;
	}

	std::string tmpDbPath = *(ctx->compact_path) + "/" + db_name + ".tmp";
	remove(tmpDbPath.c_str());

	std::string currDbPath = *(ctx->db_root) + "/" + db_name;
	std::string backupDbPath = *(ctx->db_root) + "/" + db_name + ".bak";

	//Perform copy/compaction of current database
	std::shared_ptr<MDBEnv> env = rdbs->primary_db->getEnv();
	MDBEnv* envPtr = env.get();
	int rc = mdb_env_copy2(*envPtr, tmpDbPath.c_str(), MDB_CP_COMPACT);

	if (rc)
	{
		fprintf(stderr, "ERROR: Failed to compact database %s (%s)\n",
			currDbPath.c_str(), mdb_strerror(rc));
		return JALDB_E_INVAL;
	}

	//backs up existing live non-compacted database
	if (0 != rename(currDbPath.c_str(), backupDbPath.c_str()))
	{
		fprintf(stderr, "ERROR: Failed to backup current database %s\n",
			currDbPath.c_str());
		return JALDB_E_INVAL;
	}

	//Renames existing tmp compacted db to live db
	if (0 != rename(tmpDbPath.c_str(), currDbPath.c_str()))
	{
		fprintf(stderr, "ERROR: Failed to move temporary database %s to %s.  Reverting to original database.\n",
			tmpDbPath.c_str(), currDbPath.c_str());

		if (0 != rename(backupDbPath.c_str(), currDbPath.c_str()))
		{
			fprintf(stderr, "ERROR: Failed to revert database %s\n",
				currDbPath.c_str());
		}
		return JALDB_E_INVAL;
	}

	//Deletes backup db
	remove(backupDbPath.c_str());

	return JALDB_OK;
}

enum jaldb_status get_stats(jaldb_context *ctx, JaldbStat& stat, enum jaldb_rec_type type)
{
	enum jaldb_status ret = JALDB_OK;

	if (!ctx)
	{
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db)
	{
		return JALDB_E_INVAL;
	}

	try
	{
		LmdbDbROTransaction txn = rdbs->primary_db->getROTransaction();
		size_t counter = 0;
		size_t txnSize = txn.size();
		for (auto iter = txn.begin<LmdbDbIndex::IDX_NONCE_TIMESTAMP>(); iter != txn.end(); ++iter)
		{
			++counter;
			if (counter==1){
				stat.earliest_time = iter->nonceTimestamp;
			}
			if (counter==txnSize){
				stat.latest_time = iter->nonceTimestamp;
			}
			if (JALDB_NOT_SENT == iter->synced)
			{
				stat.not_sent_count++;
			}
			else if (JALDB_SENT == iter->synced)
			{
				stat.sent_count++;
			}
			else if(JALDB_SYNCED == iter->synced)
			{
				stat.synced_count++;
			}
			else
			{
				// Should never happen
				stat.failed_count++;
			}

			if (iter->confirmed)
			{
				stat.confirmed_count++;
			}
			stat.count++;
		}
	}
	catch (std::runtime_error &err)
	{
		fprintf(stderr, "ERROR: Failed to read database %i: %s\n", stat.record_type, err.what());
		return JALDB_E_INVAL;
	}

	return JALDB_OK;
}

enum jaldb_status mark_all_records(jaldb_context *ctx, jaldb_rec_type record_type, enum jaldb_sync_stat state)
{
	if (!ctx)
	{
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	enum jaldb_status ret = jaldb_get_primary_record_dbs(ctx, record_type, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db)
	{
		return JALDB_E_INVAL;
	}

	try
	{
		LmdbDbRWTransaction txn = rdbs->primary_db->getRWTransaction();

		// There appears to be a bug in lmdb-typed with iterators not correctly comparing to
		// txn.end() after being modified when there is only a single record in the db
		// Ensure we stop once we've gone through all the records
		size_t counter = 0;
		size_t txnSize = txn.size();
		for (auto iter = txn.begin<LmdbDbIndex::IDX_NETWORK_NONCE>(); counter < txnSize && iter != txn.end(); ++iter)
		{
			++counter;
			txn.modify(iter.getID(), [state](JaldbRecordTranslator & r)
			{
				r.synced = state;
			});
		}
		txn.commit();
	}
	catch (std::runtime_error &err)
	{
		fprintf(stderr, "ERROR: Failed to read-write database %i: %s\n", record_type, err.what());
		return JALDB_E_INVAL;
	}
	return JALDB_OK;
}
