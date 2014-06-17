/**
 * @file test_jaldb_reocrd_dbs.c This file contains unit tests for functions
 * related to the jaldb_record_dbs structure.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <test-dept.h>
#include <db.h>
#include <errno.h>
#include <libxml/xmlschemastypes.h>
#include <stdlib.h>
#include <uuid/uuid.h>

#include "jaldb_record_dbs.h"
#include "jaldb_serialize_record.h"

#define DEF_MOCK_CLOSE(dbname) \
char dbname ## _closed; \
int mock_ ## dbname ## _close(DB *db, u_int32_t flags) \
{ \
	dbname ## _closed++; \
	return 0; \
}

#define MOCK_DB(rdbs, m) \
DB m; \
memset(&m, 0, sizeof(m)); \
rdbs->m = &m; \
rdbs->m->close = mock_ ## m ## _close;

DEF_MOCK_CLOSE(timestamp_idx_db)
DEF_MOCK_CLOSE(record_id_idx_db)

static void silent_errcall(const DB_ENV *dbenv, const char *errpfx, const char *msg)
{
	// do nothing... This is silent, remember?
}
struct jaldb_record_dbs *rdbs;

char primary_db_closed;
char secondaries_closed_before_primary;

static int mock_primary_db_close(DB *db, u_int32_t flags)
{
	if (!timestamp_idx_db_closed || !record_id_idx_db_closed) {
		secondaries_closed_before_primary = 0;
		return 1;
	}
	primary_db_closed = 1;
	return 0;
}

static int set_bt_compare_fails(DB *db,
    int (*bt_compare_fcn)(DB *db, const DBT *dbt1, const DBT *dbt2))
{
	return EINVAL;
}

static int associate_fail_at;
static int associate_fails_by_count(DB *primary, DB_TXN *txnid, DB *secondary,
    int (*callback)(DB *secondary,
    const DBT *key, const DBT *data, DBT *result), u_int32_t flags)
{
	if (associate_fail_at-- == 0) {
		return EINVAL;
	}
	return 0;
}

static int db_create_fail_at;

static int db_create_fails_by_count(DB **dbp, DB_ENV *dbenv, u_int32_t flags)
{
	if (db_create_fail_at == 0) {
		return EINVAL;
	}
	db_create_fail_at--;
	restore_function(db_create);
	int ret = db_create(dbp, dbenv, flags);
	replace_function(db_create, db_create_fails_by_count);
	return ret;
}
static int bt_compare_fail_at;
static int db_create_fails_bt_compare_by_count(DB **dbp, DB_ENV *dbenv, u_int32_t flags)
{
	restore_function(db_create);
	int ret = db_create(dbp, dbenv, flags);
	replace_function(db_create, db_create_fails_bt_compare_by_count);
	if (ret != 0) {
		// something else went wrong, so fail here
		abort();
	}
	if (bt_compare_fail_at == 0) {
		(*dbp)->set_bt_compare = set_bt_compare_fails;
		(*dbp)->set_errcall(*dbp, silent_errcall);
	}
	bt_compare_fail_at--;
	return ret;
}

int open_fails(DB *db, DB_TXN *txnid, const char *file,
    const char *database, DBTYPE type, u_int32_t flags, int mode)
{
	return EINVAL;
}

static int open_fail_at;
static int db_create_fails_open_by_count(DB **dbp, DB_ENV *dbenv, u_int32_t flags)
{
	restore_function(db_create);
	int ret = db_create(dbp, dbenv, flags);
	replace_function(db_create, db_create_fails_open_by_count);
	if (ret != 0) {
		// something else went wrong, so fail here
		abort();
	}
	if (open_fail_at-- == 0) {
		(*dbp)->open = open_fails;
		(*dbp)->set_errcall(*dbp, silent_errcall);
	}
	return ret;
}

static int db_create_fails_associate_by_count(DB **dbp, DB_ENV *dbenv, u_int32_t flags)
{
	restore_function(db_create);
	int ret = db_create(dbp, dbenv, flags);
	replace_function(db_create, db_create_fails_associate_by_count);
	if (ret != 0) {
		// something else went wrong, so fail here
		abort();
	}
	(*dbp)->associate = associate_fails_by_count;
	(*dbp)->set_errcall(*dbp, silent_errcall);
	return ret;
}
#define PADDING 1024
#define BUFFER_SIZE (sizeof(struct jaldb_serialize_record_headers) + PADDING)

#define MAKE_REC(recn) \
static DBT rec ## recn ## _key, rec  ## recn ## _data, rec ## recn ## _ts_key, rec  ## recn ## _uuid_key; \
static uint8_t rec ## recn ## _key_buffer; \
static uint8_t rec ## recn ## _data_buffer[BUFFER_SIZE]; \
struct jaldb_serialize_record_headers *rec ## recn ## _headers = (struct jaldb_serialize_record_headers *) rec ## recn ## _data_buffer; \
static uuid_t rec ## recn ## _uuid = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, recn};


MAKE_REC(1)
MAKE_REC(2)
MAKE_REC(3)
MAKE_REC(4)
MAKE_REC(5)

#define INIT_REC(recn, ts) \
do { \
rec ## recn ## _key_buffer = recn; \
rec ## recn ## _headers->version = JALDB_DB_LAYOUT_VERSION; \
uuid_copy(rec ## recn ## _headers->record_uuid, rec ## recn ##_uuid); \
strcpy((char*) rec ## recn ## _data_buffer + sizeof(struct jaldb_serialize_record_headers), ts); \
memset(&rec ## recn ## _key, 0, sizeof(rec ## recn ##_key)); \
memset(&rec ## recn ## _data, 0, sizeof(rec ## recn ##_data)); \
memset(&rec ## recn ## _ts_key, 0, sizeof(rec ## recn ##_ts_key)); \
memset(&rec ## recn ## _uuid_key, 0, sizeof(rec ## recn ##_uuid_key)); \
rec ## recn ## _key.data = &rec ## recn ## _key_buffer; \
rec ## recn ## _key.size = sizeof(rec ## recn ## _key_buffer); \
rec ## recn ## _data.data = rec ## recn ## _data_buffer; \
rec ## recn ## _data.size = BUFFER_SIZE; \
rec ## recn ## _ts_key.data = (void*) ts; \
rec ## recn ## _ts_key.size = strlen(ts) + 1; \
rec ## recn ## _uuid_key.data = (void*) rec ## recn ## _uuid; \
rec ## recn ## _uuid_key.size = sizeof(rec ## recn ## _uuid); \
} while (0)

#define R1_DATETIME "2012-12-12T09:00:00"
#define R2_DATETIME "2012-12-12T09:00:00"
#define R3_DATETIME "2012-12-12T09:00:00"
#define R4_DATETIME "2012-12-12T09:00:01"

#define R5_DATETIME_BAD "2012-12-12T09:00:0"

void setup()
{
	xmlSchemaInitTypes();
	db_create_fail_at = 0;
	bt_compare_fail_at = 0;
	associate_fail_at = 0;
	open_fail_at = 0;
	primary_db_closed = 0;
	timestamp_idx_db_closed = 0;
	record_id_idx_db_closed = 0;
	secondaries_closed_before_primary = 1;
	rdbs = NULL;
	INIT_REC(1, R1_DATETIME);
	INIT_REC(2, R2_DATETIME);
	INIT_REC(3, R3_DATETIME);
	INIT_REC(4, R4_DATETIME);
	INIT_REC(5, R5_DATETIME_BAD);
}

#define REMOVE_DB(db) \
	do { \
		if (db) { \
			const char *fname = NULL; \
			const char *dbname = NULL; \
			db->get_dbname(db, &fname, NULL); \
			/* Need to make copies since BDB returns a pointer to
			 * the file/db name, rather than make a copy. This
			 * pointer is invalid once close() is called, but we
			 * need the fname/dbname for the call to remove...
			 */ \
			if (fname) { \
				fname = strdup(fname); \
			} \
			db->close(db, DB_NOSYNC);\
			db_create(&(db), NULL, 0); \
			db->remove(db, fname, NULL, 0); \
			db = NULL; \
			free((void*)fname); \
			free((void*)dbname); \
		} \
	} while(0)

void teardown()
{
	//if (rdbs) {
		//REMOVE_DB(rdbs->timestamp_idx_db);
		//REMOVE_DB(rdbs->record_id_idx_db);
		//REMOVE_DB(rdbs->primary_db);
	//}

	jaldb_destroy_record_dbs(&rdbs);
	restore_function(db_create);
	xmlSchemaCleanupTypes();
}

void test_create_initializes_to_null()
{
	struct jaldb_record_dbs null_rdbs;
	memset(&null_rdbs, 0, sizeof(null_rdbs));
	rdbs = jaldb_create_record_dbs();
	assert_not_equals((void*) NULL, rdbs);
	assert_equals(0, memcmp(rdbs, &null_rdbs, sizeof(*rdbs)));
}

void test_destroy_validates_input()
{
	jaldb_destroy_record_dbs(&rdbs);
	jaldb_destroy_record_dbs(NULL);
}

void test_destroy_record_dbs_works()
{
	rdbs = jaldb_create_record_dbs();

	MOCK_DB(rdbs, primary_db);
	MOCK_DB(rdbs, timestamp_idx_db);
	MOCK_DB(rdbs, record_id_idx_db);

	jaldb_destroy_record_dbs(&rdbs);
	assert_true(primary_db_closed);
	assert_true(timestamp_idx_db_closed);
	assert_true(record_id_idx_db_closed);

}

void test_destroy_record_dbs_works_without_timestamps()
{
	rdbs = jaldb_create_record_dbs();

	MOCK_DB(rdbs, primary_db);
	MOCK_DB(rdbs, timestamp_idx_db);
	MOCK_DB(rdbs, record_id_idx_db);

	timestamp_idx_db_closed = 1;

	jaldb_destroy_record_dbs(&rdbs);
	assert_true(primary_db_closed);
	assert_true(record_id_idx_db_closed);
	assert_true(timestamp_idx_db_closed);

}

void test_destroy_record_dbs_works_without_record_id_db()
{
	rdbs = jaldb_create_record_dbs();

	MOCK_DB(rdbs, primary_db);
	MOCK_DB(rdbs, timestamp_idx_db);

	// pretend it was closed for mocked function
	record_id_idx_db_closed = 1;

	jaldb_destroy_record_dbs(&rdbs);
	assert_true(primary_db_closed);
	assert_true(timestamp_idx_db_closed);

}

void test_destroy_record_dbs_works_without_nonce()
{
	rdbs = jaldb_create_record_dbs();

	MOCK_DB(rdbs, primary_db);
	MOCK_DB(rdbs, timestamp_idx_db);
	MOCK_DB(rdbs, record_id_idx_db);

	jaldb_destroy_record_dbs(&rdbs);
	assert_true(primary_db_closed);
	assert_true(timestamp_idx_db_closed);
	assert_true(record_id_idx_db_closed);
}

void test_create_primary_dbs_w_indices_works()
{
	enum jaldb_status ret;
	int db_err;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_equals(JALDB_OK, ret);

	db_err = rdbs->primary_db->put(rdbs->primary_db, NULL, &rec1_key, &rec1_data, DB_NOOVERWRITE);
	assert_equals(0, db_err);
	db_err = rdbs->primary_db->put(rdbs->primary_db, NULL, &rec2_key, &rec2_data, DB_NOOVERWRITE);
	assert_equals(0, db_err);
	db_err = rdbs->primary_db->put(rdbs->primary_db, NULL, &rec3_key, &rec3_data, DB_NOOVERWRITE);
	assert_equals(0, db_err);
	db_err = rdbs->primary_db->put(rdbs->primary_db, NULL, &rec4_key, &rec4_data, DB_NOOVERWRITE);
	assert_equals(0, db_err);

	db_err = rdbs->primary_db->put(rdbs->primary_db, NULL, &rec5_key, &rec5_data, DB_NOOVERWRITE);
	assert_not_equals(0, db_err);

	// make sure records showed up in the correct indexes & order
	DBT key;
	DBT pkey;
	DBT val;
	DBC *ts_c = NULL;
	DBC *r_uuid_c = NULL;

	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));

	db_err = rdbs->timestamp_idx_db->cursor(rdbs->timestamp_idx_db, NULL, &ts_c, 0);
	assert_equals(0, db_err);
	db_err = rdbs->record_id_idx_db->cursor(rdbs->record_id_idx_db, NULL, &r_uuid_c, 0);
	assert_equals(0, db_err);

	// the index for timestamps should have r1, r2, r3, and r4
	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	db_err = ts_c->c_pget(ts_c, &key, &pkey, &val, DB_NEXT);
	assert_equals(0, db_err);
	assert_equals(1, *((uint8_t*)pkey.data));
	if (key.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(key.data);
	}
	if (pkey.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(pkey.data);
	}
	if (val.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(val.data);
	}

	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	db_err = ts_c->c_pget(ts_c, &key, &pkey, &val, DB_NEXT_DUP);
	assert_equals(0, db_err);
	assert_equals(2, *((uint8_t*)pkey.data));
	if (key.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(key.data);
	}
	if (pkey.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(pkey.data);
	}
	if (val.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(val.data);
	}

	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	db_err = ts_c->c_pget(ts_c, &key, &pkey, &val, DB_NEXT_DUP);
	assert_equals(0, db_err);
	assert_equals(3, *((uint8_t*)pkey.data));
	if (key.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(key.data);
	}
	if (pkey.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(pkey.data);
	}
	if (val.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(val.data);
	}

	db_err = ts_c->c_pget(ts_c, &key, &pkey, &val, DB_NEXT_DUP);
	assert_equals(DB_NOTFOUND, db_err); // only the first three records have the same TS

	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	db_err = ts_c->c_pget(ts_c, &key, &pkey, &val, DB_NEXT_NODUP);
	assert_equals(0, db_err);
	assert_equals(4, *((uint8_t*)pkey.data));
	if (key.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(key.data);
	}
	if (pkey.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(pkey.data);
	}
	if (val.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(val.data);
	}

	db_err = ts_c->c_pget(ts_c, &key, &pkey, &val, DB_NEXT);
	assert_equals(DB_NOTFOUND, db_err); // Shouldn't be any more records in the DB.
	ts_c->c_close(ts_c);
	ts_c = NULL;
	
	// Lastly, check the UUID index, everything should make it in here...
	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	db_err = r_uuid_c->c_pget(r_uuid_c, &key, &pkey, &val, DB_NEXT);
	assert_equals(0, db_err);
	assert_equals(1, *((uint8_t*)pkey.data));
	if (key.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(key.data);
	}
	if (pkey.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(pkey.data);
	}
	if (val.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(val.data);
	}

	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	db_err = r_uuid_c->c_pget(r_uuid_c, &key, &pkey, &val, DB_NEXT_NODUP);
	assert_equals(0, db_err);
	assert_equals(2, *((uint8_t*)pkey.data));
	if (key.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(key.data);
	}
	if (pkey.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(pkey.data);
	}
	if (val.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(val.data);
	}

	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	db_err = r_uuid_c->c_pget(r_uuid_c, &key, &pkey, &val, DB_NEXT_NODUP);
	assert_equals(0, db_err);
	assert_equals(3, *((uint8_t*)pkey.data));
	if (key.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) { free(key.data);
	}
	if (pkey.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(pkey.data);
	}
	if (val.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(val.data);
	}

	memset(&key, 0, sizeof(key));
	memset(&pkey, 0, sizeof(pkey));
	memset(&val, 0, sizeof(val));
	db_err = r_uuid_c->c_pget(r_uuid_c, &key, &pkey, &val, DB_NEXT_NODUP);
	assert_equals(0, db_err);
	assert_equals(4, *((uint8_t*)pkey.data));
	if (key.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(key.data);
	}
	if (pkey.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(pkey.data);
	}
	if (val.flags & (DB_DBT_MALLOC | DB_DBT_REALLOC)) {
		free(val.data);
	}

	r_uuid_c->c_close(r_uuid_c);
	r_uuid_c = NULL;

}

void test_create_primary_w_indices_dbs_returns_error_on_bad_input()
{
	enum jaldb_status ret;

	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, NULL);
	assert_not_equals(JALDB_OK, ret);

	rdbs = (struct jaldb_record_dbs*) 0xdeadbeef;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	rdbs = NULL;
}

void test_create_primary_w_indices_dbs_returns_error_when_db_create_fails()
{
	enum jaldb_status ret;
	// This is slightly hacky, and works by failing based on the call
	// count fo db_create_fails...
	replace_function(db_create, db_create_fails_by_count);
	db_create_fail_at = 0;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	db_create_fail_at = 1;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	db_create_fail_at = 2;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	db_create_fail_at = 3;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	db_create_fail_at = 4;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

}

void test_create_primary_w_indices_dbs_returns_error_when_set_bt_compare_fails()
{
	enum jaldb_status ret;
	// This is slightly hacky, and works by failing based on the call
	// count fo db_create_fails...
	replace_function(db_create, db_create_fails_bt_compare_by_count);
	bt_compare_fail_at = 0;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	bt_compare_fail_at = 1;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	bt_compare_fail_at = 2;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

}

void test_create_primary_w_indices_dbs_returns_error_when_associate_fails()
{
	enum jaldb_status ret;
	// This is slightly hacky, and works by failing based on the call
	// count fo db_create_fails...
	replace_function(db_create, db_create_fails_associate_by_count);
	associate_fail_at = 0;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	associate_fail_at = 1;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	associate_fail_at = 2;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

}

void test_create_primary_w_indices_dbs_returns_error_when_db_open_fails()
{
	enum jaldb_status ret;
	// This is slightly hacky, and works by failing based on the call
	// count fo db_create_fails...
	replace_function(db_create, db_create_fails_open_by_count);
	open_fail_at = 0;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	open_fail_at = 1;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	open_fail_at = 2;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	open_fail_at = 3;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

	open_fail_at = 4;
	ret = jaldb_create_primary_dbs_with_indices(NULL, NULL, NULL, DB_CREATE, &rdbs);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*) NULL, rdbs);

}
