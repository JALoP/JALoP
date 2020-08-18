/**
 * @file jaldb_context.cpp This file implements the DB context management
 * functions.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#define __STDC_FORMAT_MACROS

#include <fcntl.h>
#include <jalop/jal_status.h>
#include <inttypes.h> // For PRIu64
#include <list>
#include <sstream>
#include <string.h>
#include <sys/stat.h>

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"
#include "jal_asprintf_internal.h"

#include "jaldb_context.hpp"
#include "jaldb_record.h"
#include "jaldb_record_dbs.h"
#include "jaldb_record_xml.h"
#include "jaldb_segment.h"
#include "jaldb_serialize_record.h"
#include "jaldb_nonce.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"

using namespace std;

#define DEFAULT_DB_ROOT "/var/lib/jalop/db"
#define DEFAULT_SCHEMAS_ROOT "/usr/local/share/jalop/schemas"

static enum jaldb_status jaldb_remove_record_from_db(jaldb_context *ctx, jaldb_record_dbs *rdbs, const char *nonce);

jaldb_context *jaldb_context_create()
{
	jaldb_context *context = (jaldb_context *)jal_calloc(1, sizeof(*context));
	return context;
}

enum jaldb_status jaldb_context_init(
	jaldb_context *ctx,
	const char *db_root,
	const char *schemas_root,
	int db_rdonly_flag)
{
	if (!ctx) {
		return JALDB_E_INVAL;
	}

	// Make certain that the context is not already initialized.
	if (ctx->env || ctx->journal_root || ctx->schemas_root) {
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

	if (!schemas_root) {
		schemas_root = DEFAULT_SCHEMAS_ROOT;
	}
	ctx->schemas_root = jal_strdup(schemas_root);

	if (-1 == jal_asprintf(&ctx->journal_root, "%s%s", db_root, JALDB_JOURNAL_ROOT_NAME)) {
		return JALDB_E_NO_MEM;
	}

	// set readonly flag if specified
	ctx->db_read_only = db_rdonly_flag;

	uint32_t env_flags = DB_CREATE |
		DB_INIT_LOCK |
		DB_INIT_LOG |
		DB_INIT_MPOOL |
		DB_INIT_TXN |
		DB_THREAD;

	DB_ENV *env = NULL;
	int db_err = db_env_create(&env, 0);
	if (0 != db_err) {
		return JALDB_E_INVAL;
	}

	db_err = env->set_lk_detect(env, DB_LOCK_DEFAULT);
	if (0 != db_err) {
		return JALDB_E_INVAL;
	}
	db_err = env->set_flags(env, DB_TXN_NOSYNC, 1);
	if (0 != db_err) {
		return JALDB_E_INVAL;
	}

	db_err = env->open(env, db_root, env_flags, 0);
	if (0 != db_err) {
		return JALDB_E_INVAL;
	}

	DB_TXN *db_txn = NULL;

	db_err = env->txn_begin(env, NULL, &db_txn, DB_DIRTY_READ);
	if (db_err != 0) {
		return JALDB_E_INVAL;
	}

	uint32_t db_flags = DB_THREAD;
	if (db_rdonly_flag) {
		db_flags |= DB_RDONLY;
	} else {
		db_flags |= DB_CREATE;
	}
	enum jaldb_status ret;
	ret = jaldb_create_primary_dbs_with_indices(env, db_txn, "log", db_flags, &ctx->log_dbs);
	if (ret != JALDB_OK) {
		db_txn->abort(db_txn);
		return JALDB_E_INVAL;
	}

	ret = jaldb_create_primary_dbs_with_indices(env, db_txn, "audit", db_flags, &ctx->audit_dbs);
	if (ret != JALDB_OK) {
		db_txn->abort(db_txn);
		return JALDB_E_INVAL;
	}

	ret = jaldb_create_primary_dbs_with_indices(env, db_txn, "journal", db_flags, &ctx->journal_dbs);
	if (ret != JALDB_OK) {
		db_txn->abort(db_txn);
		return JALDB_E_INVAL;
	}

	db_err = db_create(&ctx->journal_conf_db, env, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->journal_conf_db), db_err);
		return JALDB_E_DB;
	}
	db_err = ctx->journal_conf_db->open(ctx->journal_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_JOURNAL_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->journal_conf_db), db_err);
		return JALDB_E_DB;
	}

	db_err = db_create(&ctx->audit_conf_db, env, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->audit_conf_db), db_err);
		return JALDB_E_DB;
	}
	db_err = ctx->audit_conf_db->open(ctx->audit_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_AUDIT_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);
		JALDB_DB_ERR((ctx->audit_conf_db), db_err);
		return JALDB_E_DB;
	}

	db_err = db_create(&ctx->log_conf_db, env, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);;
		JALDB_DB_ERR((ctx->log_conf_db), db_err);
		return JALDB_E_DB;
	}
	db_err = ctx->log_conf_db->open(ctx->log_conf_db, db_txn,
			JALDB_CONF_DB, JALDB_LOG_CONF_NAME, DB_BTREE, db_flags, 0);
	if (db_err != 0) {
		db_txn->abort(db_txn);;
		JALDB_DB_ERR((ctx->log_conf_db), db_err);
		return JALDB_E_DB;
	}

	db_txn->commit(db_txn, 0);
	ctx->env = env;

	ctx->seen_journal_records = new std::set<string>();
	ctx->seen_audit_records = new std::set<string>();
	ctx->seen_log_records = new std::set<string>();

	return JALDB_OK;
}

void jaldb_context_destroy(jaldb_context **ctx)
{
	if (!ctx || !(*ctx)) {
		return;
	}
	jaldb_context *ctxp = *ctx;

	free(ctxp->journal_root);
	free(ctxp->schemas_root);

	if (ctxp->journal_conf_db) {
		(*ctx)->journal_conf_db->close((*ctx)->journal_conf_db, 0);
	}

	if (ctxp->audit_conf_db) {
		(*ctx)->audit_conf_db->close((*ctx)->audit_conf_db, 0);
	}

	if (ctxp->log_conf_db) {
		(*ctx)->log_conf_db->close((*ctx)->log_conf_db, 0);
	}

	jaldb_destroy_record_dbs(&(ctxp->journal_dbs));
	jaldb_destroy_record_dbs(&(ctxp->audit_dbs));
	jaldb_destroy_record_dbs(&(ctxp->log_dbs));

	delete ctxp->seen_journal_records;
	delete ctxp->seen_audit_records;
	delete ctxp->seen_log_records;

	if (ctxp->env) {
		ctxp->env->close(ctxp->env, 0);
	}
	ctxp->env = NULL;
	free(ctxp);
	*ctx = NULL;
}

std::string jaldb_make_temp_db_name(const string &id, const string &suffix)
{
        stringstream o;
        o << "__" << id << "_" << suffix;
        return o.str();
}

enum jaldb_status jaldb_mark_sent(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *nonce,
	int target_state)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;

	struct jaldb_record_dbs *rdbs = NULL;

	int byte_swap;

	struct jaldb_serialize_record_headers *header_ptr = NULL;
	size_t header_bytes = sizeof(jaldb_serialize_record_headers);
	DB_TXN *txn = NULL;
	DBT key;
	DBT val;

	if (!ctx || !type || !nonce) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	switch (type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs || !rdbs->record_id_idx_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.flags = DB_DBT_REALLOC;
	key.size = strlen(nonce)+1;
	key.data = jal_strdup(nonce);

	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.dlen = header_bytes;
	val.size = header_bytes;
	val.doff = 0;
	val.data = jal_malloc(header_bytes);

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret){
		ret = JALDB_E_INVAL;
		goto out;
	}

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->primary_db->get(rdbs->primary_db, txn, &key, &val, DB_DEGREE_2);
		if (0 == db_ret) {
			header_ptr = (struct jaldb_serialize_record_headers *)val.data;
			if (header_ptr->version != JALDB_DB_LAYOUT_VERSION) {
				txn->abort(txn);
				ret = JALDB_E_INVAL;
				goto out;
			// Check to see if state matches target - nothing to do if they match
			} else if (((header_ptr->flags & JALDB_RFLAGS_SENT) ? 1 : 0) == target_state) {
				txn->abort(txn);
				goto out;
			// Update the state
			} else {
				if (1 == target_state) {
					// Set the flag
					header_ptr->flags |= JALDB_RFLAGS_SENT;
				}
				else if (0 == target_state){
					// Clear the flag
					header_ptr->flags &= ~JALDB_RFLAGS_SENT;
				} else {
					txn->abort(txn);
					goto out;
				}

				db_ret = rdbs->primary_db->put(rdbs->primary_db, txn, &key, &val, 0);
				if (0 == db_ret) {
					db_ret = txn->commit(txn, 0);
					if (0 == db_ret) {
						break;
					} else {
						continue;
					}
				}
			}
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}

		/* Something else went wrong... */
		ret = JALDB_E_DB;
		goto out;
	}

out:
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_mark_synced(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *nonce)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;

	struct jaldb_record_dbs *rdbs = NULL;

	int byte_swap;

	struct jaldb_serialize_record_headers *header_ptr = NULL;
	size_t header_bytes = sizeof(jaldb_serialize_record_headers);
	
	DB_TXN *txn = NULL;
	DBT key;
	DBT val;

	if (!ctx || !type || !nonce) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	switch (type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs || !rdbs->record_id_idx_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.flags = DB_DBT_REALLOC;
	key.size = strlen(nonce)+1;
	key.data = jal_strdup(nonce);

	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.dlen = header_bytes;
	val.size = header_bytes;
	val.doff = 0;
	val.data = jal_malloc(header_bytes);

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret){
		ret = JALDB_E_INVAL;
		goto out;
	}

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->primary_db->get(rdbs->primary_db, txn, &key, &val, DB_DEGREE_2);
		if (0 == db_ret) {
			header_ptr = (struct jaldb_serialize_record_headers *)val.data;
			if (header_ptr->version != JALDB_DB_LAYOUT_VERSION) {
				txn->abort(txn);
				ret = JALDB_E_INVAL;
				goto out;

			} else if (header_ptr->flags & JALDB_RFLAGS_SYNCED) {
				txn->abort(txn);
				goto out;

			} else {
				header_ptr->flags |= JALDB_RFLAGS_SYNCED;

				db_ret = rdbs->primary_db->put(rdbs->primary_db, txn, &key, &val, 0);

				if (0 == db_ret) {
					db_ret = txn->commit(txn, 0);

					if (0 == db_ret) {
						break;
					} else {
						continue;
					}
				}
			}
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}

		/* Something else went wrong... */
		ret = JALDB_E_DB;
		goto out;
	}

out:
	free(key.data);
	free(val.data);
	return ret;
}


enum jaldb_status jaldb_mark_confirmed(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	const char *network_nonce,
	char** nonce_out)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;

	uint8_t *buffer;
	struct jaldb_record_dbs *rdbs = NULL;
	size_t timestamp_bytes;
	size_t network_nonce_bytes;

	int byte_swap;

	struct jaldb_serialize_record_headers *header_ptr = NULL;
	size_t header_bytes = sizeof(jaldb_serialize_record_headers);
	DB_TXN *txn = NULL;
	DBT skey;
	DBT pkey;
	DBT val;

	if (!ctx || !type || !network_nonce || !nonce_out || *nonce_out) {
		return JALDB_E_INVAL;
	}

	memset(&skey, 0, sizeof(skey));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));

	switch (type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs || !rdbs->record_id_idx_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	timestamp_bytes = header_bytes + JALDB_TIMESTAMP_LENGTH + 1;
	network_nonce_bytes = timestamp_bytes + JALDB_MAX_NETWORK_NONCE_LENGTH + 1;

	skey.flags = DB_DBT_REALLOC;
	skey.size = strlen(network_nonce)+1;
	skey.data = jal_strdup(network_nonce);

	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.dlen = network_nonce_bytes;
	val.size = network_nonce_bytes;
	val.doff = 0;
	val.data = jal_malloc(network_nonce_bytes);

	pkey.flags = DB_DBT_REALLOC;

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret){
		ret = JALDB_E_INVAL;
		goto out;
	}

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->network_nonce_idx_db->pget(rdbs->network_nonce_idx_db,
									txn, &skey, &pkey, &val, 0);
		if (0 == db_ret) {
			header_ptr = (struct jaldb_serialize_record_headers *)val.data;
			if (header_ptr->version != JALDB_DB_LAYOUT_VERSION) {
				txn->abort(txn);
				ret = JALDB_E_INVAL;
				goto out;

			} else if (header_ptr->flags & JALDB_RFLAGS_CONFIRMED) {
				txn->abort(txn);
				ret = JALDB_E_INTERNAL_ERROR;
				goto out;

			} else {
				header_ptr->flags |= JALDB_RFLAGS_CONFIRMED;

				// Update the network nonce.
				
				buffer = (uint8_t *) header_ptr;
				buffer += timestamp_bytes;

				// Don't include the null terminator.
				memcpy(buffer, pkey.data, pkey.size - 1);
				buffer += (pkey.size - 1);

				// Account for the null terminator now.
				memset(buffer, '\0', (JALDB_MAX_NETWORK_NONCE_LENGTH - pkey.size + 1));

				db_ret = rdbs->primary_db->put(rdbs->primary_db, txn, &pkey, &val, 0);

				if (0 == db_ret) {
					db_ret = txn->commit(txn, 0);

					if (0 == db_ret) {
						*nonce_out = (char*) pkey.data;
						pkey.data = NULL;
						break;
					} else {
						continue;
					}
				}
			}
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}

		/* Something else went wrong... */
		ret = JALDB_E_DB;
		goto out;
	}

out:
	free(pkey.data);
	free(skey.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_store_journal_resume(
		jaldb_context *ctx,
		const char *remote_host,
		const char *nonce,
		const char *path,
		uint64_t offset)
{
	enum jaldb_status ret = JALDB_OK;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DBT offset_key;
	DBT path_key;
	DBT nonce_key;
	DBT offset_val;
	DBT path_val;
	DBT nonce_val;
	DB_TXN *txn;

	if (!ctx || !remote_host || !path || !nonce) {
		return JALDB_E_INVAL;
	}

	/* Berkeley DB stores the data as Key, Value pairs */

	/* Initialze the keys */
	memset(&offset_key, 0, sizeof(offset_key));
	memset(&path_key, 0, sizeof(path_key));
	memset(&nonce_key, 0, sizeof(nonce_key));

	/* Initialize the values */
	memset(&offset_val, 0, sizeof(offset_val));
	memset(&path_val, 0, sizeof(path_val));
	memset(&nonce_val, 0, sizeof(nonce_val));

	db_ret = jaldb_get_primary_record_dbs(ctx, JALDB_RTYPE_JOURNAL, &rdbs);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	/* Create the three key strings (and sizes) for the DB calls. Free at end of this function */
	/* BDB can resize with realloc, although not sure this will happen on a put. */
	offset_key.data = jal_strdup(JALDB_OFFSET_NAME);
	offset_key.size = strlen(JALDB_OFFSET_NAME) + 1;
	offset_key.flags = DB_DBT_REALLOC;

	path_key.data = jal_strdup(JALDB_JOURNAL_PATH);
	path_key.size = strlen(JALDB_JOURNAL_PATH) + 1;
	path_key.flags = DB_DBT_REALLOC;

	nonce_key.data = jal_strdup(JALDB_RESUME_NONCE_NAME);
	nonce_key.size = strlen(JALDB_RESUME_NONCE_NAME) + 1;
	nonce_key.flags = DB_DBT_REALLOC;

	/* Create the three value strings (and sizes) for the DB calls. Free at end of this function */
	/* BDB can resize with realloc, although not sure this will happen on a put. */
	offset_val.data = (char *)jal_malloc(21);
	snprintf((char *)offset_val.data, 21, "%" PRIu64, offset);
	offset_val.size = strlen((char *)offset_val.data) + 1;
	offset_val.flags = DB_DBT_REALLOC;

	path_val.data = jal_strdup(path);
	path_val.size = strlen(path) + 1;
	path_val.flags = DB_DBT_REALLOC;

	nonce_val.data = jal_strdup(nonce);
	nonce_val.size = strlen(nonce) + 1;
	nonce_val.flags = DB_DBT_REALLOC;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_INVAL;
			break;
		}

		/* Store the offset for the record */
		db_ret = rdbs->metadata_db->put(rdbs->metadata_db, txn, &offset_key, &offset_val, 0);
		if (0 != db_ret) {
			txn->abort(txn);
			ret = JALDB_E_DB;
			break;
		}

		/* Store the path for the record */
		db_ret = rdbs->metadata_db->put(rdbs->metadata_db, txn, &path_key, &path_val, 0);
		if (0 != db_ret) {
			txn->abort(txn);
			ret = JALDB_E_DB;
			break;
		}

		/* Store the nonce for the record */
		db_ret = rdbs->metadata_db->put(rdbs->metadata_db, txn, &nonce_key, &nonce_val, 0);
		if (0 != db_ret) {
			txn->abort(txn);
			ret = JALDB_E_DB;
			break;
		}

		/* Commit the database transactions */
		db_ret = txn->commit(txn, 0);
		if (0 == db_ret) {
			break;
		} else if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else {
			/* If DB_TXN->commit encounters an error, the transaction and all child transactions of the transaction are aborted. */
			ret = JALDB_E_DB;
			break;
		}
	}

	/* Free the memory allocated for the keys */
	free(offset_key.data);
	free(path_key.data);
	free(nonce_key.data);

	/* Free the memory allocated for the values */
	free(offset_val.data);
	free(path_val.data);
	free(nonce_val.data);

out:
	return ret;
}

enum jaldb_status jaldb_clear_journal_resume(
		jaldb_context *ctx,
		const char *remote_host)
{
	enum jaldb_status ret = JALDB_OK;
	struct jaldb_record_dbs *rdbs = NULL;
	DBT offset_key;
	DBT path_key;
	DBT nonce_key;
	int db_ret;
	DB_TXN *txn;

	if (!ctx || !remote_host) {
		return JALDB_E_INVAL;
	}

	/* Initialze the keys */
	memset(&offset_key, 0, sizeof(offset_key));
	memset(&path_key, 0, sizeof(path_key));
	memset(&nonce_key, 0, sizeof(nonce_key));

	db_ret = jaldb_get_primary_record_dbs(ctx, JALDB_RTYPE_JOURNAL, &rdbs);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	/* Create the three key strings (and sizes) for the DB calls. Free at end of this function */
	/* BDB can resize with realloc, although not sure this will happen on a put. */
	offset_key.data = jal_strdup(JALDB_OFFSET_NAME);
	offset_key.size = strlen(JALDB_OFFSET_NAME) + 1;
	offset_key.flags = DB_DBT_REALLOC;

	path_key.data = jal_strdup(JALDB_JOURNAL_PATH);
	path_key.size = strlen(JALDB_JOURNAL_PATH) + 1;
	path_key.flags = DB_DBT_REALLOC;

	nonce_key.data = jal_strdup(JALDB_RESUME_NONCE_NAME);
	nonce_key.size = strlen(JALDB_RESUME_NONCE_NAME) + 1;
	nonce_key.flags = DB_DBT_REALLOC;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_INVAL;
			break;
		}

		/* Delete the offset for the record */
		db_ret = rdbs->metadata_db->del(rdbs->metadata_db, txn, &offset_key, 0);
		if (0 != db_ret) {
			txn->abort(txn);
			ret = JALDB_E_DB;
			break;
		}

		/* Delete the path for the record */
		db_ret = rdbs->metadata_db->del(rdbs->metadata_db, txn, &path_key, 0);
		if (0 != db_ret) {
			txn->abort(txn);
			ret = JALDB_E_DB;
			break;
		}

		/* Delete the nonce for the record */
		db_ret = rdbs->metadata_db->del(rdbs->metadata_db, txn, &nonce_key, 0);
		if (0 != db_ret) {
			txn->abort(txn);
			ret = JALDB_E_DB;
			break;
		}

		/* Commit the database transactions */
		db_ret = txn->commit(txn, 0);
		if (0 == db_ret) {
			break;
		} else if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else {
			/* If DB_TXN->commit encounters an error, the transaction and all child transactions of the transaction are aborted. */
			ret = JALDB_E_DB;
			break;
		}
	}


out:
	/* Free the memory allocated for the keys */
	free(offset_key.data);
	free(path_key.data);
	free(nonce_key.data);

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
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DB_TXN *txn = NULL;
	DBT offset_key;
	DBT path_key;
	DBT nonce_key;
	DBT offset_val;
	DBT path_val;
	DBT nonce_val;

	if (!ctx || !remote_host || !path || !nonce) {
		return JALDB_E_INVAL;
	}

	/* Berkeley DB stores the data as Key, Value pairs */

	/* Initialze the keys */
	memset(&offset_key, 0, sizeof(offset_key));
	memset(&path_key, 0, sizeof(path_key));
	memset(&nonce_key, 0, sizeof(nonce_key));

	/* Initialize the values */
	memset(&offset_val, 0, sizeof(offset_val));
	memset(&path_val, 0, sizeof(path_val));
	memset(&nonce_val, 0, sizeof(nonce_val));

	db_ret = jaldb_get_primary_record_dbs(ctx, JALDB_RTYPE_JOURNAL, &rdbs);
	if (0 != db_ret || !rdbs || !rdbs->metadata_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	offset_val.flags = DB_DBT_REALLOC;
	path_val.flags = DB_DBT_REALLOC;
	nonce_val.flags = DB_DBT_REALLOC;

	/* Create the three key strings (and sizes) for the DB calls. Free at end of this function */
	/* BDB can resize with realloc. */
	offset_key.data = jal_strdup(JALDB_OFFSET_NAME);
	offset_key.size = strlen(JALDB_OFFSET_NAME) + 1;
	offset_key.flags = DB_DBT_REALLOC;

	path_key.data = jal_strdup(JALDB_JOURNAL_PATH);
	path_key.size = strlen(JALDB_JOURNAL_PATH) + 1;
	path_key.flags = DB_DBT_REALLOC;

	nonce_key.data = jal_strdup(JALDB_RESUME_NONCE_NAME);
	nonce_key.size = strlen(JALDB_RESUME_NONCE_NAME) + 1;
	nonce_key.flags = DB_DBT_REALLOC;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		/* Get the offset for the record. offset_val.data is allocated by the DB and freed by us */
		db_ret = rdbs->metadata_db->get(rdbs->metadata_db, txn, &offset_key, &offset_val, DB_DEGREE_2);
		if (0 != db_ret) {
			txn->abort(txn);
			ret = JALDB_E_DB;
			goto out;
		}

		/* Get the path for the record. path_val.data is allocated by the DB and freed by us */
		db_ret =  rdbs->metadata_db->get(rdbs->metadata_db, txn, &path_key, &path_val, DB_DEGREE_2);
		if (0 != db_ret) {
			txn->abort(txn);
			ret = JALDB_E_DB;
			goto out;
		}

		/* Get the nonce for the record. nonce_val.data is allocated by the DB and freed by us */
		db_ret =  rdbs->metadata_db->get(rdbs->metadata_db, txn, &nonce_key, &nonce_val, DB_DEGREE_2);
		if (0 != db_ret) {
			txn->abort(txn);
			ret = JALDB_E_DB;
			goto out;
		}

		/* Commit the database transactions */
		/* If DB_TXN->commit encounters an error, the transaction and all child transactions of the transaction are aborted. */
		db_ret = txn->commit(txn, 0);
		if (0 == db_ret) {
			break;
		} else if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		} else {
			ret = JALDB_E_DB;
			goto out;
		}
	}

	/* Check for a well formatted offset */
	if(0 > sscanf((char*)offset_val.data, "%" PRIu64, &offset)) {
		ret = JALDB_E_CORRUPTED;
	}

	/* Reuse allocated memory for return value */
	*nonce = (char *)nonce_val.data;
	/* Set original ptr to NULL so we can fall through to block of frees below */
	nonce_val.data = NULL;

	/* Reuse allocated memory for return value */
	*path = (char *)path_val.data;
	/* Set original ptr to NULL so we can fall through to block of frees below */
	path_val.data = NULL;

out:
	/* Free the memory allocated for the keys */
	free(offset_key.data);
	free(path_key.data);
	free(nonce_key.data);

	/* Free the memory allocated for the values */
	free(offset_val.data);
	free(path_val.data);
	free(nonce_val.data);
	return ret;
}

enum jaldb_status jaldb_get_journal_document_list(
	jaldb_context *ctx,
	list<string> **doc_list)
{
	enum jaldb_status ret = JALDB_OK;
	ret = jaldb_get_all_records(ctx, doc_list, JALDB_RTYPE_JOURNAL);
	return ret;
}

enum jaldb_status jaldb_get_audit_document_list(
		jaldb_context *ctx,
		list<string> **doc_list)
{
	enum jaldb_status ret = JALDB_OK;
	ret = jaldb_get_all_records(ctx, doc_list, JALDB_RTYPE_AUDIT);
	return ret;
}

enum jaldb_status jaldb_get_log_document_list(
		jaldb_context *ctx,
		list<string> **doc_list)
{
	enum jaldb_status ret = JALDB_OK;
	ret = jaldb_get_all_records(ctx, doc_list, JALDB_RTYPE_LOG);
	return ret;
}

enum jaldb_status jaldb_get_last_k_records(
		jaldb_context *ctx,
		int k,
		list<string> &nonce_list,
		enum jaldb_rec_type type,
		bool get_all)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;
	struct jaldb_record_dbs *rdbs = NULL;
	int byte_swap;
	DBC *cursor = NULL;
	DBT pkey;
	DBT key;
	DBT val;
	memset(&pkey, 0, sizeof(pkey));
	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));
	pkey.flags = DB_DBT_REALLOC;
	key.flags = DB_DBT_REALLOC;
	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.doff = 0;
	val.dlen = 0; //Only interested in the key at this point
	int count = 0;

	if (!ctx) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		return JALDB_E_INVAL;
	}

	if (!rdbs) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->timestamp_idx_db->get_byteswapped(rdbs->timestamp_idx_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->timestamp_idx_db->cursor(rdbs->timestamp_idx_db, NULL, &cursor, DB_DEGREE_2);
	if (0 != db_ret) {
		JALDB_DB_ERR(rdbs->timestamp_idx_db, db_ret);
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = cursor->c_pget(cursor, &key, &pkey, &val, DB_LAST);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	while((count < k || get_all) && (0 == db_ret)) {
		nonce_list.push_front((const char*)pkey.data);

		db_ret = cursor->c_pget(cursor, &key, &pkey, &val, DB_PREV);

		if(0 != db_ret) {
			break;
		}

		count++;
	}

out:
	if (cursor) {
		cursor->c_close(cursor);
	}

	free(pkey.data);
	free(key.data);
	free(val.data);
	return ret;

}

enum jaldb_status jaldb_get_all_records(
		jaldb_context *ctx,
		list<string> **nonce_list,
		enum jaldb_rec_type type)
{
	if (!ctx || !nonce_list || *nonce_list) {
		return JALDB_E_INVAL;
	}

	enum jaldb_status ret = JALDB_OK;
	*nonce_list = new list<string>;
	ret = jaldb_get_last_k_records(ctx, 0, **nonce_list, type, true);
	return ret;
}

enum jaldb_status jaldb_get_records_since_last_nonce(
		jaldb_context *ctx,
		char *last_nonce,
		list<string> &nonce_list,
		enum jaldb_rec_type type)
{
	enum jaldb_status ret = JALDB_OK;
	int db_ret;
	struct jaldb_record_dbs *rdbs = NULL;
	int byte_swap;
	DBC *cursor = NULL;
	DBT pkey;
	DBT key;
	DBT val;
	memset(&pkey, 0, sizeof(pkey));
	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));
	pkey.flags = DB_DBT_REALLOC;
	key.flags = DB_DBT_REALLOC;
	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.doff = 0;
	val.dlen = 0; //Only interested in the key at this point

	if (!ctx) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!last_nonce || 0 == strlen(last_nonce)) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		return JALDB_E_INVAL;
	}

	if (!rdbs) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->timestamp_idx_db->get_byteswapped(rdbs->timestamp_idx_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->timestamp_idx_db->cursor(rdbs->timestamp_idx_db, NULL, &cursor, DB_DEGREE_2);
	if (0 != db_ret) {
		JALDB_DB_ERR(rdbs->timestamp_idx_db, db_ret);
		ret = JALDB_E_INVAL;
		goto out;
	}

	// Set the cursor and get the last inserted record
	db_ret = cursor->c_pget(cursor, &key, &pkey, &val, DB_LAST);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	// Add records to the list until we find a match for the network nonce
	// If record purged (missing), next loop will get all records.
	while(strcmp((char *)pkey.data, last_nonce) != 0) {
		/* Check to see if we've hit the beginning of the DB, which means we did not find the nonce */
		/* Return a separate error code to indicate this along with the list of nonces */
		if (db_ret == DB_NOTFOUND ) {
			ret = JALDB_E_NOT_FOUND;
			goto out;

		/* Any other errors return invalid */
		} else if (db_ret != 0) {
			ret = JALDB_E_INVAL;
			goto out;
		}

		nonce_list.push_front((const char *)pkey.data); 
		db_ret = cursor->c_pget(cursor, &key, &pkey, &val, DB_PREV);
	}

out:
	if (cursor) {
		cursor->c_close(cursor);
	}

	free(pkey.data);
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_insert_record(jaldb_context *ctx, struct jaldb_record *rec, int confirmed, char **local_nonce)
{
	int byte_swap;
	enum jaldb_status ret;
	size_t buf_size = 0;
	struct jaldb_record_dbs *rdbs = NULL;
	uint8_t* buffer = NULL;
	int db_ret;
	int update_network_nonce = 0;
	DBT key;
	DBT val;
	DB_TXN *txn;

	if (!ctx || !rec || !local_nonce || *local_nonce) {
		return JALDB_E_INVAL;
	}
	if (!rec->source) {
		rec->source = jal_strdup("localhost");
	}
	if (!rec->network_nonce) {
		update_network_nonce = 1;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));	

	ret = jaldb_record_sanity_check(rec);
	if (ret != JALDB_OK) {
		goto out;
	}

	rec->confirmed = confirmed ? 1 : 0;

	switch(rec->type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			break;
		}

		char *primary_key = jaldb_gen_primary_key(rec->uuid);
		if (NULL == primary_key) {
			ret = JALDB_E_INVAL;
			goto out;
		}

		key.data = primary_key;
		key.size = strlen(primary_key) + 1;
		key.flags = DB_DBT_REALLOC;

		if (update_network_nonce) {
			free(rec->network_nonce);
			rec->network_nonce = jal_strdup(primary_key);
		}

		ret = jaldb_serialize_record(byte_swap, rec, &buffer, &buf_size);
		if (ret != JALDB_OK) {
			goto out;
		}
		val.data = buffer;
		val.size = buf_size;

		db_ret = rdbs->primary_db->put(rdbs->primary_db, txn, &key, &val, DB_NOOVERWRITE);
		if (0 == db_ret) {
			db_ret = txn->commit(txn, 0);
		} else {
			txn->abort(txn);
		}
		if (0 == db_ret) {
			ret = JALDB_OK;
			break;
		}
		if (DB_LOCK_DEADLOCK == db_ret || DB_KEYEXIST == db_ret) {
			free(buffer);
			buffer = NULL;
			continue;
		} else {
			ret = JALDB_E_DB;
			break;
		}
	}

out:
	*local_nonce = (char *)key.data;
	free(val.data);
	return ret;
}



enum jaldb_status jaldb_get_record(jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *nonce,
		struct jaldb_record **recpp)
{
	struct jaldb_record *rec = NULL;
	int byte_swap;
	enum jaldb_status ret;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DB_TXN *txn = NULL;
	DBT key;
	DBT val;

	if (!ctx || !nonce || !recpp || *recpp) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs || !rdbs->primary_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.flags = DB_DBT_REALLOC;
	key.size = strlen(nonce)+1;
	key.data = jal_strdup(nonce);

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	val.flags = DB_DBT_REALLOC;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->primary_db->get(rdbs->primary_db, txn, &key, &val, DB_DEGREE_2);
		if (0 == db_ret) {
			txn->commit(txn, 0);
			break;
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}
		// some other error
		ret = JALDB_E_DB;
		goto out;
	}
	ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
	if (ret != JALDB_OK) {
		goto out;
	}
	rec->type = type;
	if (!rec->sys_meta) {
		rec->sys_meta = jaldb_create_segment();
		char *doc = NULL;
		size_t doc_len = 0;
		ret = jaldb_record_to_system_metadata_doc(rec, NULL, NULL, 0, NULL, NULL, 0, NULL, &doc, &doc_len);
		if (ret != JALDB_OK) {
			goto out;
		}
		rec->sys_meta->payload = (uint8_t*)doc;
		rec->sys_meta->length = doc_len;
	}

	*recpp = rec;
	rec = NULL;
	ret = JALDB_OK;
out:
	jaldb_destroy_record(&rec);
	free(key.data);
	free(val.data);
	return ret;
}

enum jaldb_status jaldb_get_record_by_uuid(jaldb_context *ctx,
		enum jaldb_rec_type type,
		uuid_t uuid,
		char **nonce,
		struct jaldb_record **recpp)
{
	struct jaldb_record *rec = NULL;
	int byte_swap;
	enum jaldb_status ret;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DB_TXN *txn = NULL;
	DBT key;
	DBT pkey;
	DBT val;

	if (!ctx || !nonce || *nonce || !recpp || *recpp) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));

	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs || !rdbs->record_id_idx_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.flags = DB_DBT_USERMEM;
	key.data = uuid;
	key.size = 16; // UUIDs are always 16 bytes

	db_ret = rdbs->primary_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	val.flags = DB_DBT_REALLOC;
	pkey.flags = DB_DBT_REALLOC;

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->record_id_idx_db->pget(rdbs->record_id_idx_db, txn, &key, &pkey, &val, 0);
		if (0 == db_ret) {
			txn->commit(txn, 0);
			break;
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}
		// some other error
		ret = JALDB_E_DB;
		goto out;
	}
	ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
	if (ret != JALDB_OK) {
		goto out;
	}
	rec->type = type;
	if (!rec->sys_meta) {
		rec->sys_meta = jaldb_create_segment();
		char *doc = NULL;
		size_t doc_len = 0;
		ret = jaldb_record_to_system_metadata_doc(rec, NULL, NULL, 0, NULL, NULL, 0, NULL, &doc, &doc_len);
		if (ret != JALDB_OK) {
			goto out;
		}
		rec->sys_meta->payload = (uint8_t*)doc;
		rec->sys_meta->length = doc_len;
	}

	*nonce = (char*)pkey.data;
	pkey.data = NULL;
	if (!nonce) {
		ret = JALDB_E_NO_MEM;
		goto out;
	}

	*recpp = rec;
	rec = NULL;
	ret = JALDB_OK;
out:
	jaldb_destroy_record(&rec);
	free(pkey.data);
	free(val.data);
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

enum jaldb_status jaldb_remove_record_from_db(jaldb_context *ctx,
		jaldb_record_dbs *rdbs,
		const char *nonce)
{
	enum jaldb_status ret;
	int db_ret;
	DB_TXN *txn = NULL;
	DBT key;

	if (!ctx || !nonce || !rdbs || !rdbs->primary_db) {
		return JALDB_E_INVAL;
	}

	memset(&key, 0, sizeof(key));

	key.flags = DB_DBT_REALLOC;
	key.size = strlen(nonce)+1;
	key.data = jal_strdup(nonce);

	while (1) {
		db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
		if (0 != db_ret) {
			ret = JALDB_E_DB;
			goto out;
		}

		db_ret = rdbs->primary_db->del(rdbs->primary_db, txn, &key, 0);
		if (0 == db_ret) {
			txn->commit(txn, 0);
			break;
		}

		txn->abort(txn);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		}
		// some other error
		ret = JALDB_E_DB;
		goto out;
	}
	ret = JALDB_OK;
out:
	free(key.data);
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
	enum jaldb_status ret = JALDB_E_INVAL;

	int byte_swap;
	int db_ret;

	struct jaldb_serialize_record_headers *headers = NULL;
	struct jaldb_record_dbs *rdbs = NULL;

	DBC *cursor = NULL;

	DBT skey;
	DBT pkey;
	DBT val;

	memset(&skey, 0, sizeof(skey));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));

	if (!ctx) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs || !rdbs->primary_db || !rdbs->record_sent_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	skey.flags = DB_DBT_REALLOC;
	skey.size = sizeof(uint32_t);
	skey.data = jal_malloc(skey.size);
	// Set the secondary index we want to get records by
	*((uint32_t*)(skey.data)) = JALDB_RFLAGS_SENT | JALDB_RFLAGS_CONFIRMED; // Check for Sent and Confirmed (and not Synced)

	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.dlen = sizeof(*headers);
	val.size = sizeof(*headers);
	val.doff = 0;
	val.data = jal_malloc(val.size);

	pkey.flags = DB_DBT_REALLOC;

	db_ret = rdbs->record_sent_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	// pget will continue to return records matching the requested flag until no more found
	while (1) {
		val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
		db_ret = rdbs->record_sent_db->pget(rdbs->record_sent_db, NULL, &skey, &pkey, &val, 0);

		if (DB_NOTFOUND == db_ret) {
			ret = JALDB_OK;
			goto out;
		} else if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (0 != db_ret) {
			ret = JALDB_E_DB;
			JALDB_DB_ERR(rdbs->primary_db, db_ret);
			goto out;
		}
		// Use the returned nonce to id the record to be updated
		db_ret = jaldb_mark_sent(ctx, type, (char *)pkey.data, 0);
	}
out:
	if (cursor) {
		cursor->c_close(cursor);
	}

	free(skey.data);
	free(pkey.data);
	free(val.data);

	return ret;
}

enum jaldb_status jaldb_next_unsynced_record(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	char **network_nonce,
	struct jaldb_record **rec_out)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	struct jaldb_record *rec = NULL;
	int byte_swap;
	struct jaldb_serialize_record_headers *headers = NULL;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	DBT skey;
	DBT pkey;
	DBT val;
	memset(&skey, 0, sizeof(skey));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));

	if (!ctx || !network_nonce || *network_nonce || !rec_out || *rec_out) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		break;
	default:
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs || !rdbs->primary_db || !rdbs->record_sent_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	skey.size = sizeof(uint32_t);
	skey.data = jal_malloc(skey.size);
	*((uint32_t*)(skey.data)) = JALDB_RFLAGS_CONFIRMED;
	skey.flags = DB_DBT_REALLOC;

	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
	val.dlen = sizeof(*headers);
	val.size = sizeof(*headers);
	val.doff = 0;
	val.data = jal_malloc(val.size);

	pkey.flags = DB_DBT_REALLOC;

	db_ret = rdbs->record_sent_db->get_byteswapped(rdbs->primary_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	while (1) {
		
		val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;
		db_ret = rdbs->record_sent_db->pget(rdbs->record_sent_db, NULL, &skey, &pkey, &val, 0);
		val.flags = DB_DBT_REALLOC;
		
		if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
			goto out;
		} else if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		} else if (0 != db_ret) {
			ret = JALDB_E_DB;
			JALDB_DB_ERR(rdbs->primary_db, db_ret);
			goto out;
		}

		headers = ((struct jaldb_serialize_record_headers *)val.data);

		val.flags = DB_DBT_REALLOC;
		val.dlen = 0;
		db_ret = rdbs->record_sent_db->pget(rdbs->record_sent_db, NULL, &skey, &pkey, &val, 0);
		if (DB_LOCK_DEADLOCK == db_ret) {
			continue;
		}

		if (0 != db_ret) {
			JALDB_DB_ERR(rdbs->primary_db, db_ret);
			ret = JALDB_E_DB;
			goto out;
		}

		break;
	}

	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto out;
	}

	ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
	if (ret != JALDB_OK) {
		goto out;
	}
	rec->type = type;
	if (!rec->sys_meta) {
		rec->sys_meta = jaldb_create_segment();
		char *doc = NULL;
		size_t doc_len = 0;
		ret = jaldb_record_to_system_metadata_doc(rec, NULL, NULL, 0, NULL, NULL, 0, NULL, &doc, &doc_len);
		if (ret != JALDB_OK) {
			goto out;
		}
		rec->sys_meta->payload = (uint8_t*)doc;
		rec->sys_meta->length = doc_len;
	}

	*network_nonce = jal_strdup(rec->network_nonce);
	if (NULL == network_nonce) {
		ret = JALDB_E_NO_MEM;
		goto out;
	}

	*rec_out = rec;
	rec = NULL;
	ret = JALDB_OK;
out:
	free(skey.data);
	free(pkey.data);
	free(val.data);
	jaldb_destroy_record(&rec);

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
	struct tm search_time, current_time;
	int search_microseconds, cur_microseconds;
	memset(&search_time,0,sizeof(search_time));
	memset(&current_time,0,sizeof(current_time));
	int byte_swap;
	struct jaldb_record_dbs *rdbs = NULL;
	int db_ret;
	std::set <std::string> *seen_records = NULL;
	std::string nonce_string;
	DBT key;
	DBT pkey;
	DBT val;
	DBC *cursor = NULL;
	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	key.flags = DB_DBT_REALLOC;
	val.flags = DB_DBT_REALLOC;

	char *end_timestamp = strptime(*timestamp, "%Y-%m-%dT%H:%M:%S", &search_time);

	if (!end_timestamp) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!sscanf(end_timestamp,".%d-%*d:%*d",&search_microseconds)) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!ctx || !network_nonce || *network_nonce || !rec_out || *rec_out) {
		ret = JALDB_E_INVAL;
		goto out;
	}
	
	switch(type) {
	case JALDB_RTYPE_JOURNAL:
		rdbs = ctx->journal_dbs;
		seen_records = ctx->seen_journal_records;
		break;
	case JALDB_RTYPE_AUDIT:
		rdbs = ctx->audit_dbs;
		seen_records = ctx->seen_audit_records;
		break;
	case JALDB_RTYPE_LOG:
		rdbs = ctx->log_dbs;
		seen_records = ctx->seen_log_records;
		break;
	default:
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!rdbs) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	key.size = strlen(*timestamp) + 1;
	key.data = jal_strdup(*timestamp);

	db_ret = rdbs->nonce_timestamp_db->get_byteswapped(rdbs->nonce_timestamp_db, &byte_swap);
	if (0 != db_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_ret = rdbs->nonce_timestamp_db->cursor(rdbs->nonce_timestamp_db, NULL, &cursor, DB_DEGREE_2);
	if (0 != db_ret) {
		JALDB_DB_ERR(rdbs->nonce_timestamp_db, db_ret);
		goto out;
	}

	db_ret = cursor->c_pget(cursor, &key, &pkey, &val, DB_SET_RANGE);
	if (0 != db_ret) {
		if (DB_NOTFOUND == db_ret) {
			ret = JALDB_E_NOT_FOUND;
		} else {
			JALDB_DB_ERR(rdbs->nonce_timestamp_db, db_ret);
		}
		goto out;
	}

	end_timestamp = strptime((char*) key.data, "%Y-%m-%dT%H:%M:%S", &current_time);

	if (!end_timestamp) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	if (!sscanf(end_timestamp,".%d-%*d:%*d",&cur_microseconds)) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	nonce_string = (char *)pkey.data;

	while (difftime(mktime(&search_time), mktime(&current_time)) == 0 &&
			search_microseconds == cur_microseconds) {
		// Check to see if we already got a record at this time
		if (seen_records->count(nonce_string) == 0) {
			//Haven't seen it
			seen_records->insert(nonce_string);
			break;
		} else {
			db_ret = cursor->c_pget(cursor, &key, &pkey, &val, DB_NEXT);
			if (0 != db_ret) {
				if (DB_NOTFOUND == db_ret) {
					ret = JALDB_E_NOT_FOUND;
				} else {
					JALDB_DB_ERR(rdbs->nonce_timestamp_db, db_ret);
				}
				goto out;
			}
			nonce_string = (char *)pkey.data;
		}
		end_timestamp = strptime((char*) key.data, "%Y-%m-%dT%H:%M:%S", &current_time);
		if (!end_timestamp) {
			ret = JALDB_E_INVAL;
			goto out;
		}
		if (!sscanf(end_timestamp,".%d-%*d:%*d",&cur_microseconds)) {
			ret = JALDB_E_INVAL;
			goto out;
		}
	}

	if (difftime(mktime(&search_time), mktime(&current_time)) != 0 ||
			search_microseconds != cur_microseconds) {
		free(*timestamp);
		*timestamp = (char*)key.data;
		key.data = NULL;
		seen_records->clear();
		seen_records->insert(nonce_string);
	}

	ret = jaldb_deserialize_record(byte_swap, (uint8_t*) val.data, val.size, &rec);
	if (ret != JALDB_OK) {
		goto out;
	}

	rec->type = type;
	if (!rec->sys_meta) {
		rec->sys_meta = jaldb_create_segment();
		char *doc = NULL;
		size_t doc_len = 0;
		ret = jaldb_record_to_system_metadata_doc(rec, NULL, NULL, 0, NULL, NULL, 0, NULL, &doc, &doc_len);
		if (ret != JALDB_OK) {
			goto out;
		}
		rec->sys_meta->payload = (uint8_t*)doc;
		rec->sys_meta->length = doc_len;
	}

	*network_nonce = jal_strdup(rec->network_nonce);
	if (NULL == network_nonce) {
		ret = JALDB_E_NO_MEM;
		goto out;
	}

	*rec_out = rec;
	rec = NULL;
	ret = JALDB_OK;

out:
	if (cursor) {
		cursor->c_close(cursor);
	}

	free(key.data);
	free(val.data);
	jaldb_destroy_record(&rec);
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
	if (ctx->db_read_only) {
		return JALDB_E_READ_ONLY;
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

enum jaldb_status jaldb_remove_db_logs(jaldb_context *ctx)
{
	if (!ctx || !ctx->env) {
		return JALDB_E_INVAL;
	}

	int db_err;
	char **file_list = NULL;

	db_err = ctx->env->txn_checkpoint(ctx->env, 0, 0, 0);
	if (0 != db_err) {
		return JALDB_E_INTERNAL_ERROR;
	}

	db_err = ctx->env->log_archive(ctx->env, &file_list, DB_ARCH_ABS);
	if (0 != db_err) {
		return JALDB_E_INTERNAL_ERROR;
	}
	char **cur_file = file_list;
	while (cur_file) {
		if (0 != remove(*cur_file)) {
			free(file_list);
			return JALDB_E_DB;
		}
		cur_file++;
	}
	free(file_list);

	return JALDB_OK;
}

enum jaldb_status jaldb_compact_db(jaldb_context *ctx, DB *db)
{
	int db_ret;
	enum jaldb_status ret;
	DB_TXN *txn = NULL;
	DB_COMPACT c_data;
	u_int32_t c_flags = DB_FREE_SPACE; // return free pages to filesystem.

	memset(&c_data, 0, sizeof(c_data));

	c_data.compact_fillpercent = 0;
	c_data.compact_timeout = 0;
	c_data.compact_pages = 0;

        while (1) {
                db_ret = ctx->env->txn_begin(ctx->env, NULL, &txn, 0);
                if (0 != db_ret) {
                        ret = JALDB_E_DB;
                        goto out;
                }

                db_ret = db->compact(db, txn, NULL, NULL, &c_data, c_flags, NULL);
                if (0 == db_ret) {
                        txn->commit(txn, 0);
                        break;
                }

                txn->abort(txn);
                if (DB_LOCK_DEADLOCK == db_ret) {
                        continue;
                }
                // some other error
                ret = JALDB_E_DB;
                goto out;
        }

        // check some compaction stats
        fprintf(stdout, "Pages examined  : %d\n", c_data.compact_pages_examine);
        fprintf(stdout, "Pages freed     : %d\n", c_data.compact_pages_free);
        fprintf(stdout, "Levels Removed  : %d\n", c_data.compact_levels);
        fprintf(stdout, "Deadlocks       : %d\n", c_data.compact_deadlock);
        fprintf(stdout, "Pages Truncated : %d\n", c_data.compact_pages_truncated);

        ret = JALDB_OK;
out:
        return ret;
}

enum jaldb_status jaldb_compact_primary_db(
	jaldb_context *ctx,
	enum jaldb_rec_type type)
{
	int db_ret;
	enum jaldb_status ret;
	struct jaldb_record_dbs *rdbs = NULL;
	string db_name;

	db_ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (0 != db_ret || !rdbs || !rdbs->primary_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_name = "primary_db";
	fprintf(stdout, "Compact %s\n", db_name.c_str());
	ret = jaldb_compact_db(ctx, rdbs->primary_db);
	if (JALDB_OK != ret) {
		fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
	}
out:
	return ret;
}

enum jaldb_status jaldb_compact_dbs(
		jaldb_context *ctx,
		enum jaldb_rec_type type)
{
	int db_ret;
	enum jaldb_status ret = JALDB_OK;
	struct jaldb_record_dbs *rdbs = NULL;
	string db_name;

	db_ret = jaldb_get_primary_record_dbs(ctx, type, &rdbs);
	if (0 != db_ret || !rdbs || !rdbs->primary_db) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	db_name = "primary_db";
	fprintf(stdout, "Compact %s\n", db_name.c_str());
	ret = jaldb_compact_db(ctx, rdbs->primary_db);
	if (JALDB_OK != ret) {
		fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
	}

	db_name = "timestamp_idx_db";
	fprintf(stdout, "Compact %s\n", db_name.c_str());
	ret = jaldb_compact_db(ctx, rdbs->timestamp_idx_db);
	if (JALDB_OK != ret) {
		fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
	}

	db_name = "nonce_timestamp_db";
	fprintf(stdout, "Compact %s\n", db_name.c_str());
	ret = jaldb_compact_db(ctx, rdbs->nonce_timestamp_db);
	if (JALDB_OK != ret) {
		fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
	}

	db_name = "record_id_idx_db";
	fprintf(stdout, "Compact %s\n", db_name.c_str());
	ret = jaldb_compact_db(ctx, rdbs->record_id_idx_db);
	if (JALDB_OK != ret) {
		fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
	}

	db_name = "record_sent_db";
	fprintf(stdout, "Compact %s\n", db_name.c_str());
	ret = jaldb_compact_db(ctx, rdbs->record_sent_db);
	if (JALDB_OK != ret) {
		fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
	}

	db_name = "metadata_db";
	fprintf(stdout, "Compact %s\n", db_name.c_str());
	ret = jaldb_compact_db(ctx, rdbs->metadata_db);
	if (JALDB_OK != ret) {
		fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
	}

	db_name = "network_nonce_idx_db";
	fprintf(stdout, "Compact %s\n", db_name.c_str());
	ret = jaldb_compact_db(ctx, rdbs->network_nonce_idx_db);
	if (JALDB_OK != ret) {
		fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
	}

	db_name = "record_confirmed_db";
	fprintf(stdout, "Compact %s\n", db_name.c_str());
	ret = jaldb_compact_db(ctx, rdbs->record_confirmed_db);
	if (JALDB_OK != ret) {
		fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
	}

	switch (type) {
	case JALDB_RTYPE_JOURNAL:
		db_name = "journal_conf_db";
		fprintf(stdout, "Compact %s\n", db_name.c_str());
		ret = jaldb_compact_db(ctx, ctx->journal_conf_db);
		if (JALDB_OK != ret) {
				fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
		}
		break;
	case JALDB_RTYPE_AUDIT:
		db_name = "audit_conf_db";
		fprintf(stdout, "Compact %s\n", db_name.c_str());
		ret = jaldb_compact_db(ctx, ctx->audit_conf_db);
		if (JALDB_OK != ret) {
			fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
		}
		break;
	case JALDB_RTYPE_LOG:
		db_name = "log_conf_db";
		fprintf(stdout, "Compact %s\n", db_name.c_str());
		ret = jaldb_compact_db(ctx, ctx->log_conf_db);
		if (JALDB_OK != ret) {
			fprintf(stderr, "ERROR: Faild to compact %s\n", db_name.c_str());
		}
		break;
	default:
		ret = JALDB_E_INVAL;
	}
out:
	return ret;
}
