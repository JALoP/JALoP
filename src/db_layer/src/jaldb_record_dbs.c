/**
 * @file jaldb_record_dbs.c This file provides the implementation of
 * functions related to jaldb_record_dbs objects.
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

#include <db.h>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#include "jaldb_datetime.h"
#include "jaldb_record_dbs.h"
#include "jaldb_record_extract.h"
#include "jaldb_serial_id.h"
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

	// According to BDB documentation, secondary databases should be closed
	// before the primary. Any new indices must be closed before the
	// primary_db is closed.

	if (rdbs->timestamp_tz_idx_db) {
		rdbs->timestamp_tz_idx_db->close(rdbs->timestamp_tz_idx_db, 0);
	}
	if (rdbs->timestamp_no_tz_idx_db) {
		rdbs->timestamp_no_tz_idx_db->close(rdbs->timestamp_no_tz_idx_db, 0);
	}
	if (rdbs->nonce_timestamp_db) {
		rdbs->nonce_timestamp_db->close(rdbs->nonce_timestamp_db, 0);
	}
	if (rdbs->record_id_idx_db) {
		rdbs->record_id_idx_db->close(rdbs->record_id_idx_db, 0);
	}
	if (rdbs->record_sent_db) {
		rdbs->record_sent_db->close(rdbs->record_sent_db, 0);
	}
	if (rdbs->sid_db) {
		rdbs->sid_db->close(rdbs->sid_db, 0);
	}
	if (rdbs->primary_db) {
		rdbs->primary_db->close(rdbs->primary_db, 0);
	}
	if (rdbs->metadata_db) {
		rdbs->metadata_db->close(rdbs->metadata_db, 0);
	}
	free(rdbs);
	*record_dbs = NULL;
}

enum jaldb_status jaldb_create_primary_dbs_with_indices(
		DB_ENV *env,
		DB_TXN *txn,
		const char *prefix,
		const u_int32_t db_flags,
		struct jaldb_record_dbs **pprdbs)
{
	if (!pprdbs || *pprdbs) {
		return JALDB_E_INVAL;
	}

	int db_ret;
	enum jaldb_status ret;
	char *primary_name =  NULL;
	char *timestamp_tz_name = NULL;
	char *timestamp_no_tz_name = NULL;
	char *nonce_timestamp_name = NULL;
	char *record_uuid_name = NULL;
	char *record_sent_name = NULL;
	char *sid_name = NULL;

	struct jaldb_record_dbs *rdbs = jaldb_create_record_dbs();

	if (prefix) {
		jal_asprintf(&primary_name, "%s_records.db", prefix);
		jal_asprintf(&timestamp_tz_name, "%s_timestamp_tz_idx.db", prefix);
		jal_asprintf(&timestamp_no_tz_name, "%s_timestamp_no_tz_idx.db", prefix);
		jal_asprintf(&nonce_timestamp_name, "%s_nonce_timestamp.db", prefix);
		jal_asprintf(&record_uuid_name, "%s_record_uuid_idx.db", prefix);
		jal_asprintf(&record_sent_name, "%s_record_sent.db", prefix);
		jal_asprintf(&sid_name, "%s_sid.db", prefix);
	}

	// Open the Primary DB. The Primary DB keys are serial IDs
	db_ret = db_create(&(rdbs->primary_db), env, 0);
	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->primary_db->set_bt_compare(rdbs->primary_db, jaldb_nonce_compare);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->primary_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->primary_db->open(rdbs->primary_db, txn,
			primary_name, NULL, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->primary_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	// Open the 'Timestamp (w/timezone)' DB. The Primary DB keys are XML DateTime
	// strings. The timestamp DB is is used as a secondary index for the
	// primary DB.

	db_ret = db_create(&(rdbs->timestamp_tz_idx_db), env, 0);
	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->timestamp_tz_idx_db->set_flags(rdbs->timestamp_tz_idx_db, DB_DUP | DB_DUPSORT);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->timestamp_tz_idx_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->timestamp_tz_idx_db->set_bt_compare(rdbs->timestamp_tz_idx_db,
			jaldb_xml_datetime_compare);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->timestamp_tz_idx_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->timestamp_tz_idx_db->open(rdbs->timestamp_tz_idx_db, txn,
			timestamp_tz_name, NULL, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->timestamp_tz_idx_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	// Open the 'Timestamp (wo/timezone)' DB. The Primary DB keys are XML DateTime
	// strings. The timestamp DB is is used as a secondary index for the
	// primary DB.

	db_ret = db_create(&(rdbs->timestamp_no_tz_idx_db), env, 0);
	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->timestamp_no_tz_idx_db->set_flags(rdbs->timestamp_no_tz_idx_db, DB_DUP | DB_DUPSORT);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->timestamp_no_tz_idx_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->timestamp_no_tz_idx_db->set_bt_compare(rdbs->timestamp_no_tz_idx_db,
			jaldb_xml_datetime_compare);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->timestamp_no_tz_idx_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->timestamp_no_tz_idx_db->open(rdbs->timestamp_no_tz_idx_db, txn,
			timestamp_no_tz_name, NULL, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->timestamp_no_tz_idx_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	// Open the 'Nonce timestamp' DB. The Primary DB keys are XML DateTime
	// strings. The nonce timestamp DB is is used as a secondary index for the
	// primary DB.

	db_ret = db_create(&(rdbs->nonce_timestamp_db), env, 0);
	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->nonce_timestamp_db->set_flags(rdbs->nonce_timestamp_db, DB_DUP | DB_DUPSORT);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->nonce_timestamp_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->nonce_timestamp_db->set_bt_compare(rdbs->nonce_timestamp_db,
			jaldb_xml_datetime_compare);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->nonce_timestamp_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->nonce_timestamp_db->open(rdbs->nonce_timestamp_db, txn,
			nonce_timestamp_name, NULL, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->nonce_timestamp_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}


	// Open the record id DB. This is used as (yet another) secondary
	// index for the primary DB. The keys for this DB are the record UUID
	// identified in the system metadata.
	db_ret = db_create(&(rdbs->record_id_idx_db), env, 0);
	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->record_id_idx_db->set_flags(rdbs->record_id_idx_db, DB_DUP | DB_DUPSORT);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->record_id_idx_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->record_id_idx_db->open(rdbs->record_id_idx_db, txn,
			record_uuid_name, NULL, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->record_id_idx_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	// Open the sent DB.  This is a secondary index grouping whether records
	// Have been sent.
	db_ret = db_create(&(rdbs->record_sent_db), env, 0);
	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->record_sent_db->set_flags(rdbs->record_sent_db, DB_DUP | DB_DUPSORT);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->record_sent_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->record_sent_db->open(rdbs->record_sent_db, txn,
			record_sent_name, NULL, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->record_sent_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = db_create(&(rdbs->sid_db), env, 0);
	if (db_ret != 0) {
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->sid_db->open(rdbs->sid_db, txn,
			sid_name, NULL, DB_BTREE, db_flags, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->sid_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	// Associate the databases for secondary keys.
	db_ret = rdbs->primary_db->associate(rdbs->primary_db, txn, rdbs->timestamp_tz_idx_db,
			jaldb_extract_datetime_w_tz_key, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->primary_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->primary_db->associate(rdbs->primary_db, txn, rdbs->timestamp_no_tz_idx_db,
			jaldb_extract_datetime_wo_tz_key, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->primary_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->primary_db->associate(rdbs->primary_db, txn, rdbs->nonce_timestamp_db,
			jaldb_extract_nonce_timestamp_key, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->primary_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->primary_db->associate(rdbs->primary_db, txn, rdbs->record_id_idx_db,
			jaldb_extract_record_uuid, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->primary_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	db_ret = rdbs->primary_db->associate(rdbs->primary_db, txn, rdbs->record_sent_db,
			jaldb_extract_record_sent_flag, 0);
	if (db_ret != 0) {
		JALDB_DB_ERR((rdbs->primary_db), db_ret);
		ret = JALDB_E_DB;
		goto err_out;
	}

	*pprdbs = rdbs;
	ret = JALDB_OK;
	goto out;
err_out:
	jaldb_destroy_record_dbs(&rdbs);
out:
	free(primary_name);
	free(timestamp_tz_name);
	free(timestamp_no_tz_name);
	free(record_uuid_name);
	free(sid_name);
	return ret;
}

