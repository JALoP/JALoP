/**
 * @file
 *
 * @brief This file provides the structure definition and
 * functions related to jaldb_record_dbs objects.
 *
 * ### LICENSE
 *
 * Copyright (C) 2025 Concurrent Technologies Corporation.
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

#ifndef _JALDB_RECORD_BDS_
#define _JALDB_RECORD_BDS_

#include <lmdb-safe.h>
#include "jaldb_status.h"
#include "jaldb_context.hpp"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This structure is used to track related DBs for a specific type of record.
 *
 * For permanent storage (i.e. records created by either the local store, or,
 * in the case of a Subscriber, confirmed as correctly received) records are
 * indexed by the Timestamp & UUID identified by the System Meta-data.
 */
struct jaldb_record_dbs {
	LmdbDbType* primary_db;             //<! The database to store actual records in.
	MDBDbi metadata_db;            //<! The database to use for storing metadata about unconfirmed records
};

/**
 * Create and initialize a jaldb_record_dbs structure.
 * All pointers will be initialized to NULL. The returned object must be
 * released with a call to jaldb_destroy_record_dbs.
 *
 * @return a newly allocated & initialized jaldb_record_dbs structure.
 */
struct jaldb_record_dbs *jaldb_create_record_dbs();

/**
 * Close DBs and release memory associated with a record DBs structure.
 * The assumption is that all secondary indices are associated with
 *
 * @param[in,out] record_dbs the jaldb_record_dbs structure to release. This
 * will close all associated DB handles.
 */
void jaldb_destroy_record_dbs(struct jaldb_record_dbs **record_dbs);

enum jaldb_status jaldb_create_primary_dbs_with_indices(
		std::string db_root,
		std::shared_ptr<MDBEnv> &env,
		const char *prefix,
		const u_int32_t db_flags,
		struct jaldb_record_dbs **pprdbs);

#ifdef __cplusplus
}
#endif

#endif // _JALDB_RECORD_BDS_
