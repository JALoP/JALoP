/**
 * @file
 *
 * @brief This file implements the DB purge functions.
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

#include <list>
#include <string.h>
#include "jal_asprintf_internal.h"
#include "jal_alloc.h"
#include "jaldb_record.h"
#include "jaldb_record_dbs.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "jaldb_context.hpp"
#include "jaldb_purge.hpp"

using namespace std;

enum jaldb_status jaldb_purge_unconfirmed_records(
	jaldb_context *ctx,
	const char *remote_host,
	enum jaldb_rec_type rtype)
{
	enum jaldb_status ret = JALDB_OK;

	if (!ctx || !remote_host ||
			0 == strcmp(remote_host, "localhost") ||
			0 == strcmp(remote_host, "127.0.0.1")) {
		return JALDB_E_INVAL;
	}

	struct jaldb_record_dbs *rdbs = NULL;
	ret = jaldb_get_primary_record_dbs(ctx, rtype, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	try {
		LmdbDbRWTransaction txn = rdbs->primary_db->getRWTransaction();

		//Delete all unconfirmed records only
		auto range = txn.equal_range<LmdbDbIndex::IDX_SENT>(JALDB_NOT_CONFIRMED);
		for(auto iter = std::move(range.first); iter != range.second; ++iter) {
			txn.del(iter.getID());
		}
		txn.commit();
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_purge_unconfirmed_records - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_purge_unconfirmed_records - unknown error occurred\n");
		return JALDB_E_DB;
	}
	return JALDB_OK;
}

enum jaldb_status jaldb_iterate_by_timestamp_purge(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *timestamp,
	jaldb_iter_cb cb,
	void *up,
	int& exiting)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	struct tm target_time, record_time;
	memset(&target_time, 0, sizeof(target_time));
	memset(&record_time, 0, sizeof(record_time));
	int target_ms = 0;
	int record_ms = 0;
	char *tmp_time = NULL;
	struct jaldb_record *rec = NULL;
	struct jaldb_record_dbs *rdbs = NULL;
	time_t target_secs = 0;
	std::map<std::string, std::string> purge_map;
	char *path = NULL;

	tmp_time = strptime(timestamp, "%Y-%m-%dT%H:%M:%S", &target_time);
	if (!tmp_time) {
		fprintf(stderr, "ERROR: Invalid time format specified.\n");
		ret = JALDB_E_INVAL_TIMESTAMP;
		return ret;
	}

	if (!sscanf(tmp_time,".%d-%*d:%*d", &target_ms)) { // nosemgrep - sscanf is needed here and a dynamic buffer is being used, so can't specify fixed width
		fprintf(stderr, "ERROR: Invalid time format specified.\n");
		ret = JALDB_E_INVAL_TIMESTAMP;
		return ret;
	}
	// Calculate the target time in secs once before we start looping
	target_secs = mktime(&target_time);

	if (!ctx) {
		return JALDB_E_UNINITIALIZED;
	}

	ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (JALDB_OK != ret || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	try {
		LmdbDbROTransaction txn = rdbs->primary_db->getROTransaction();

		bool exit_loop = false;
		// Loop through all keys in main db
		for(auto iter = txn.begin<LmdbDbIndex::IDX_TIMESTAMP>();
				iter != txn.end();
				++iter) {
			std::string curr_timestamp = iter->timestamp;
			std::string curr_nonce = iter->networkNonce;

			// mktime() like to set things like timezone to system timezone -
			// need to clean out the tm struct before each call
			memset(&record_time, 0, sizeof(record_time));

			tmp_time = strptime((char*) curr_timestamp.c_str(), "%Y-%m-%dT%H:%M:%S", &record_time);
			if (!tmp_time) {
				fprintf(stderr, "ERROR: Cannot get strptime from record\n");
				ret = JALDB_E_INVAL_TIMESTAMP;
				break;
			}

			if (!sscanf(tmp_time,".%d-%*d:%*d", &record_ms)) { // nosemgrep - sscanf is needed here and a dynamic buffer is being used, so can't specify fixed width
				ret = JALDB_E_INVAL_TIMESTAMP;
				break;
			}

			double delta = difftime(target_secs,mktime(&record_time));
			if (delta < 0) {
				// record_time is > target_time, so break out
				break;
			}

			if (delta == 0) {
				if (record_ms > target_ms) {
					break;
				}
			}

			rec = iter->generateCStruct();

			switch (cb((char*) curr_nonce.c_str(), rec, up)) {
				case JALDB_ITER_CONT:
					break;
				case JALDB_ITER_REM:
					if (JALDB_RTYPE_JOURNAL == type) {
						jaldb_segment *segment = rec->payload;
						if (segment && segment->on_disk) {
							jal_asprintf(&path, "%s/%s", ctx->journal_root, (char*)segment->payload);
						}
					}
					// Insert record nonce and payload path into purge map.
					if (path) {
						purge_map[std::string((const char*)(curr_nonce.c_str()))] = std::string((const char*)(path));
						free(path);
						path = NULL;
					} else {
						purge_map[std::string((const char*)(curr_nonce.c_str()))] = std::string("");
					}
					break;
					default:
						exit_loop = true;
			}

			if (exit_loop)
			{
				break;
			}

			jaldb_destroy_record(&rec);

			if (exiting) {
				break;
			}
		}
	}
	catch (std::exception &err)
	{
		fprintf(stderr, "ERROR: jaldb_iterate_by_timestamp_purge - exception: %s\n", err.what());
		return JALDB_E_DB;
	}
	catch (...)
	{
		fprintf(stderr, "ERROR: jaldb_iterate_by_timestamp_purge - unknown error occurred\n");
		return JALDB_E_DB;
	}

	// Remove records that are in the purge_map.
	ret = jaldb_remove_records(ctx, type, purge_map, exiting);

	jaldb_destroy_record(&rec);
	purge_map.clear();
	return ret;
}

enum jaldb_status jaldb_purge_log_by_nonce(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *nonce,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_log_by_uuid(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *uuid,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_audit_by_nonce(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *nonce,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_audit_by_uuid(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *uuid,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_journal_by_nonce(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *nonce,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_purge_journal_by_uuid(__attribute__((unused)) jaldb_context *ctx,
					__attribute__((unused)) const char *uuid,
					__attribute__((unused)) list<jaldb_doc_info> &docs,
					__attribute__((unused)) int force,
					__attribute__((unused)) int del)
{
	return JALDB_E_NOT_IMPL;
}
