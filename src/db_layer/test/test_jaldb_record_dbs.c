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

#include <test-dept.h>

#include <db.h>

#include "jaldb_record_dbs.h"

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

DEF_MOCK_CLOSE(timestamp_tz_idx_db)
DEF_MOCK_CLOSE(timestamp_no_tz_idx_db)
DEF_MOCK_CLOSE(record_id_idx_db)
DEF_MOCK_CLOSE(sid_db)

char primary_db_closed;
char secondaries_closed_before_primary;

int mock_primary_db_close(DB *db, u_int32_t flags)
{
	if (!timestamp_no_tz_idx_db_closed || !timestamp_tz_idx_db_closed || !record_id_idx_db_closed || !sid_db_closed) {
		secondaries_closed_before_primary = 0;
		return 1;
	}
	primary_db_closed = 1;
	return 0;
}

void setup()
{
	primary_db_closed = 0;
	timestamp_no_tz_idx_db_closed = 0;
	timestamp_tz_idx_db_closed = 0;
	record_id_idx_db_closed = 0;
	sid_db_closed = 0;
	secondaries_closed_before_primary = 1;
}

void teardown()
{
}

void test_create_initializes_to_null()
{
	struct jaldb_record_dbs *ret = jaldb_create_record_dbs();
	struct jaldb_record_dbs null_rdbs;
	memset(&null_rdbs, 0, sizeof(null_rdbs));
	ret = jaldb_create_record_dbs();
	assert_not_equals((void*) NULL, ret);
	assert_equals(0, memcmp(ret, &null_rdbs, sizeof(*ret)));
}

void test_destroy_validates_input()
{
	struct jaldb_record_dbs *rdbs = NULL;

	jaldb_destroy_record_dbs(&rdbs);
	jaldb_destroy_record_dbs(NULL);
}

void test_destroy_record_dbs_works()
{
	struct jaldb_record_dbs *rdbs = jaldb_create_record_dbs();

	MOCK_DB(rdbs, primary_db);
	MOCK_DB(rdbs, timestamp_tz_idx_db);
	MOCK_DB(rdbs, timestamp_no_tz_idx_db);
	MOCK_DB(rdbs, record_id_idx_db);
	MOCK_DB(rdbs, sid_db);

	jaldb_destroy_record_dbs(&rdbs);
	assert_true(primary_db_closed);
	assert_true(timestamp_tz_idx_db_closed);
	assert_true(timestamp_no_tz_idx_db_closed);
	assert_true(sid_db_closed);
	assert_true(record_id_idx_db_closed);

}

void test_destroy_record_dbs_works_without_tz_timestamp()
{
	struct jaldb_record_dbs *rdbs = jaldb_create_record_dbs();

	MOCK_DB(rdbs, primary_db);
	MOCK_DB(rdbs, timestamp_no_tz_idx_db);
	MOCK_DB(rdbs, record_id_idx_db);
	MOCK_DB(rdbs, sid_db);

	timestamp_tz_idx_db_closed = 1;

	jaldb_destroy_record_dbs(&rdbs);
	assert_true(primary_db_closed);
	assert_true(sid_db_closed);
	assert_true(record_id_idx_db_closed);
	assert_true(timestamp_tz_idx_db_closed);

}

void test_destroy_record_dbs_works_without_no_tz_timestamp()
{
	struct jaldb_record_dbs *rdbs = jaldb_create_record_dbs();

	MOCK_DB(rdbs, primary_db);
	MOCK_DB(rdbs, timestamp_tz_idx_db);
	MOCK_DB(rdbs, record_id_idx_db);
	MOCK_DB(rdbs, sid_db);

	timestamp_no_tz_idx_db_closed = 1;

	jaldb_destroy_record_dbs(&rdbs);
	assert_true(primary_db_closed);
	assert_true(sid_db_closed);
	assert_true(record_id_idx_db_closed);
	assert_true(timestamp_tz_idx_db_closed);

}

void test_destroy_record_dbs_works_without_record_id_db()
{
	struct jaldb_record_dbs *rdbs = jaldb_create_record_dbs();

	MOCK_DB(rdbs, primary_db);
	MOCK_DB(rdbs, timestamp_tz_idx_db);
	MOCK_DB(rdbs, timestamp_no_tz_idx_db);
	MOCK_DB(rdbs, sid_db);

	// pretend it was closed for mocked function
	record_id_idx_db_closed = 1;

	jaldb_destroy_record_dbs(&rdbs);
	assert_true(primary_db_closed);
	assert_true(sid_db_closed);
	assert_true(timestamp_tz_idx_db_closed);
	assert_true(timestamp_no_tz_idx_db_closed);

}

void test_destroy_record_dbs_works_without_sid()
{
	struct jaldb_record_dbs *rdbs = jaldb_create_record_dbs();

	MOCK_DB(rdbs, primary_db);
	MOCK_DB(rdbs, timestamp_tz_idx_db);
	MOCK_DB(rdbs, timestamp_no_tz_idx_db);
	MOCK_DB(rdbs, record_id_idx_db);

	// pretend it was closed for mocked function
	sid_db_closed = 1;

	jaldb_destroy_record_dbs(&rdbs);
	assert_true(primary_db_closed);
	assert_true(timestamp_tz_idx_db_closed);
	assert_true(timestamp_no_tz_idx_db_closed);
	assert_true(record_id_idx_db_closed);

}

