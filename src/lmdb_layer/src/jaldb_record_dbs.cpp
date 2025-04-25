/**
 * @file
 *
 * @brief This file provides the implementation of
 * functions related to jaldb_record_dbs objects.
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

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#include "jaldb_record_dbs.h"
#include "jaldb_utils.h"

struct jaldb_record_dbs *jaldb_create_record_dbs()
{
	struct jaldb_record_dbs *ret = (struct jaldb_record_dbs*) jal_calloc(1, sizeof(*ret));
	return ret;
}

void jaldb_destroy_record_dbs(struct jaldb_record_dbs **record_dbs)
{
	if (!record_dbs || !*record_dbs) {
		return;
	}

	struct jaldb_record_dbs *rdbs = *record_dbs;
	// invoke the destructor and free its allocation using delete
	// since it was created using new
	delete rdbs->primary_db;
	// This memory was allocated with jal_calloc, so we can't just delete it
	// First invoke the destructor manually to let lmdb_safe clean itself up
	rdbs->metadata_db.~MDBDbi();
	// Then allow the shallow memory of the MDBDbi object itself
	// to be freed with the rest of the struct

	free(rdbs);
	*record_dbs = NULL;
}

enum jaldb_status jaldb_create_primary_dbs_with_indices(
		std::string db_root,
		std::shared_ptr<MDBEnv> &env,
		const char *prefix,
		const u_int32_t db_flags,
		struct jaldb_record_dbs **pprdbs)
{
	if (!pprdbs || *pprdbs) {
		return JALDB_E_INVAL;
	}

	enum jaldb_status ret;
	std::string primary_path = std::string(db_root) + "/" + prefix + "_records.mdb";
	std::string metadata_name = std::string(prefix) + "_metadata.db";

	struct jaldb_record_dbs *rdbs = jaldb_create_record_dbs();

	try
	{
		// Open the Primary DB. The Primary DB keys are nonces
		rdbs->primary_db = new LmdbDbType(getMDBEnv(primary_path.c_str(), MDB_NOSUBDIR | db_flags, 0600), "records");

		// Open the metadata DB. This is for tracking metadata and is *NOT* a
		// secondary index into the primary db
		rdbs->metadata_db = env->openDB(metadata_name, MDB_CREATE);
	}
	catch(std::runtime_error &err)
	{
		fprintf(stderr, "ERROR: Failed to open database: %s\n", err.what());
		ret = JALDB_E_DB;
		goto err_out;
	}

	*pprdbs = rdbs;
	ret = JALDB_OK;
	goto out;
err_out:
	jaldb_destroy_record_dbs(&rdbs);
out:
	return ret;
}

