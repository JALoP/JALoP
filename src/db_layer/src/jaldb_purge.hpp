/**
 * @file
 *
 * @brief This file provides the DB doc_info structure.
 *
 * ### LICENSE
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

#ifndef _JALDB_PURGE_HPP_
#define _JALDB_PURGE_HPP_

#include <list>
#include "jaldb_context.hpp"

struct jaldb_doc_info {
	char *nonce;
	char *uuid;
};

/**
 * Purge all cached records for the given remote.
 * This removes all records that were stored in a temporary database, for which
 * a digest and digest-conf message have not been sent or received.
 *
 * @param[in] ctx The context to use.
 * @param[in] remote_host The name of the remote host to purge records for.
 * @param[in] rtype The type of record stored in the database.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_purge_unconfirmed_records(
		jaldb_context *ctx,
		const char *remote_host,
		enum jaldb_rec_type rtype);

/**
 * Purge all log records up to and including the specified nonce.
 * By default, this creates a list of document info objects that contain
 * the nonces and uuids of all specified documents that would be removed.
 * If the del flag is set, this removes all records that have been synced and sent,
 * unless the force flag is specified, in which case all specified records are removed.
 *
 * @param[in] ctx The context to use.
 * @param[in] nonce The max nonce to remove.
 * @param[out] doc_list The list of jaldb_doc_info objects that contain info on each document
 * 			to be removed.
 * @param[in] force The force flag.
 * @param[in] del The delete flag.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_purge_log_by_nonce(
		jaldb_context *ctx,
		const char *nonce,
		std::list<jaldb_doc_info> &doc_list,
		int force,
		int del);

/**
 * Purge all log records up to and including the specified uuid.
 * If multiple documents contain the same uuid, it will list/remove those and
 * all preceeding documents.
 * By default, this creates a list of document info objects that contain
 * the nonces and uuids of all specified documents that would be removed.
 * If the del flag is set, this removes all records that have been synced and sent,
 * unless the force flag is specified, in which case all specified records are removed.
 *
 * @param[in] ctx The context to use.
 * @param[in] nonce The max nonce to remove.
 * @param[out] doc_list The list of jaldb_doc_info objects that contain info on each document
 * 			to be removed.
 * @param[in] force The force flag.
 * @param[in] del The delete flag.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_purge_log_by_uuid(
		jaldb_context *ctx,
		const char *nonce,
		std::list<jaldb_doc_info> &doc_list,
		int force,
		int del);

/**
 * Purge all audit records up to and including the specified nonce.
 * By default, this creates a list of document info objects that contain
 * the nonces and uuids of all specified documents that would be removed.
 * If the del flag is set, this removes all records that have been synced and sent,
 * unless the force flag is specified, in which case all specified records are removed.
 *
 * @param[in] ctx The context to use.
 * @param[in] nonce The max nonce to remove.
 * @param[out] doc_list The list of jaldb_doc_info objects that contain info on each document
 * 			to be removed.
 * @param[in] force The force flag.
 * @param[in] del The delete flag.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_purge_audit_by_nonce(
		jaldb_context *ctx,
		const char *nonce,
		std::list<jaldb_doc_info> &doc_list,
		int force,
		int del);

/**
 * Purge all log records up to and including the specified uuid.
 * If multiple documents contain the same uuid, it will list/remove those and
 * all preceeding documents.
 * By default, this creates a list of document info objects that contain
 * the nonces and uuids of all specified documents that would be removed.
 * If the del flag is set, this removes all records that have been synced and sent,
 * unless the force flag is specified, in which case all specified records are removed.
 *
 * @param[in] ctx The context to use.
 * @param[in] nonce The max nonce to remove.
 * @param[out] doc_list The list of jaldb_doc_info objects that contain info on each document
 * 			to be removed.
 * @param[in] force The force flag.
 * @param[in] del The delete flag.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_purge_audit_by_uuid(
		jaldb_context *ctx,
		const char *nonce,
		std::list<jaldb_doc_info> &doc_list,
		int force,
		int del);

/**
 * Purge all journal records up to and including the specified nonce.  This also
 * removes the journal file from the system, if it exists.
 * By default, this creates a list of document info objects that contain
 * the nonces and uuids of all specified documents that would be removed.
 * If the del flag is set, this removes all records that have been synced and sent,
 * unless the force flag is specified, in which case all specified records are removed.
 *
 * @param[in] ctx The context to use.
 * @param[in] nonce The max nonce to remove.
 * @param[out] doc_list The list of jaldb_doc_info objects that contain info on each document
 * 			to be removed.
 * @param[in] force The force flag.
 * @param[in] del The delete flag.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_purge_journal_by_nonce(
		jaldb_context *ctx,
		const char *nonce,
		std::list<jaldb_doc_info> &doc_list,
		int force,
		int del);

/**
 * Purge all journal records up to and including the specified uuid.  This also
 * removes the journal file from the system, if it exists.
 * If multiple documents contain the same uuid, it will list/remove those and
 * all preceeding documents.
 * By default, this creates a list of document info objects that contain
 * the nonces and uuids of all specified documents that would be removed.
 * If the del flag is set, this removes all records that have been synced and sent,
 * unless the force flag is specified, in which case all specified records are removed.
 *
 * @param[in] ctx The context to use.
 * @param[in] nonce The max nonce to remove.
 * @param[out] doc_list The list of jaldb_doc_info objects that contain info on each document
 * 			to be removed.
 * @param[in] force The force flag.
 * @param[in] del The delete flag.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_purge_journal_by_uuid(
		jaldb_context *ctx,
		const char *nonce,
		std::list<jaldb_doc_info> &doc_list,
		int force,
		int del);

/**
 * Utility function used by jal_purge CLI to iterate over the records in a DB in order by timestamp.
 *
 * This function iterates over the database in timestamp order. Operations performed
 * on each record are dictated by the return value of the callback. Only timestamps
 * which fulfill <tt> start_time <= current_time <= end_time </tt> are examined. Timestamps are
 * never negative numbers.
 *
 * If the return from \p cb is JALDB_ITER_CONT, continue processing, but do not
 * modify the current record.
 *
 * If the return from \p cb is JALDB_ITER_REMOVE, remove the current record,
 * and continue processing.
 *
 * Any other return value causes processing to halt, the current record is not
 * removed, and control is returned to the caller.
 *
 * @param[in] ctx the jaldb_context
 * @param[in] type JAL record type.
 * @param[in] timestamp The end time to stop iterating
 * @param[in] cb The user specified callback.
 * @param[in] up A pointer value that is passed un-modified to \p cb as the \p up
 * parameter.
 * @param[in] exiting This indicates if CTRL+C is pressed in the calling application.
 *
 * @return JALDB_OK on success, or an error
 */
enum jaldb_status jaldb_iterate_by_timestamp_purge(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *timestamp,
	jaldb_iter_cb cb,
	void *up,
	int &exiting);

#endif // _JALDB_PURGE_HPP_
