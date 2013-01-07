/**
 * @file test_jaldb_traverse.cpp This file contains functions that traverse the DB.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2013 Tresys Technology LLC, Columbia, Maryland, USA
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

// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// C++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
extern "C" {
#include <test-dept.h>
}

#include "test_utils.h"

#include <dirent.h>
#include <libxml/xmlschemastypes.h>
#include <sys/stat.h>

#include <openssl/bn.h>

#include "jal_alloc.h"

#include "jaldb_segment.h"
#include "jaldb_traverse.h"
#include "jaldb_context.h"

#define DB_ROOT "./testdb/"
#define SCHEMA_ROOT "./schemas/"

#define DT1 "2012-12-12T09:00:00Z"
#define DT2 "2012-12-12T09:00:01Z"
#define DT3 "2012-12-12T09:00:00+13:00"
#define DT4 "2012-12-12T09:00:00-13:00"

#define UUID_1 "11234567-89AB-CDEF-0123-456789ABCDEF"
#define UUID_2 "21234567-89AB-CDEF-0123-456789ABCDEF"
#define UUID_3 "31234567-89AB-CDEF-0123-456789ABCDEF"
#define UUID_4 "41234567-89AB-CDEF-0123-456789ABCDEF"

#define S1 "source 1"
#define S2 "source 2"
#define S3 "source 2"
#define S4 "source 2"

#define HN1 "hostname 1"
#define HN2 "hostname 2"
#define HN3 "hostname 2"
#define HN4 "hostname 2"

#define UN1 "username 1"
#define UN2 "username 2"
#define UN3 "username 2"
#define UN4 "username 2"


#define START_HEX "0"
#define END_HEX "4"
#define EXPECTED_RECORD_VERSION 1
#define ITEMS_IN_DB 4

static jaldb_context *context;
static BIGNUM *start = NULL;
static BIGNUM *end = NULL;
static char fail_up;
static long current;
static int iter_call_cnt;

struct jaldb_record *records[4] = { NULL, NULL, NULL, NULL };

extern "C" enum jaldb_iter_status iter_cb(const char *hex_sid, struct jaldb_record *rec, void *up)
{
	char *failure = (char*)up;
	enum jaldb_iter_status ret = JALDB_ITER_CONT;
	iter_call_cnt++;
	BIGNUM *expected = BN_new();
	BN_set_word(expected, current);
	BIGNUM *actual = NULL;

	if (current > ITEMS_IN_DB) {
		goto fail;
	}

	BN_hex2bn(&actual, hex_sid);
	if (0 != BN_cmp(actual, expected)) {
		goto fail;
	}

	if (0 != uuid_compare(rec->uuid, records[current - 1]->uuid)) {
		goto fail;
	}
	ret = JALDB_ITER_CONT;
	current++;
	goto out;
fail:
	*failure = 1;
	ret = JALDB_ITER_ABORT;
out:
	if (actual) {
		BN_free(actual);
	}
	if (expected) {
		BN_free(expected);
	}
	return ret;
}

extern "C" void setup()
{
	fail_up = 0;
	iter_call_cnt = 0;
	dir_cleanup(DB_ROOT);
	mkdir(DB_ROOT, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	context = jaldb_context_create();
	jaldb_context_init(context, DB_ROOT, SCHEMA_ROOT, false);

	records[0] = jaldb_create_record();
	records[1] = jaldb_create_record();
	records[2] = jaldb_create_record();
	records[3] = jaldb_create_record();

	records[0]->version = EXPECTED_RECORD_VERSION;
	records[0]->source = jal_strdup("source");
	records[0]->type = JALDB_RTYPE_LOG;
	records[0]->timestamp = jal_strdup(DT1);
	records[0]->payload = jaldb_create_segment();
	records[0]->username = jal_strdup(UN1);
	records[0]->hostname = jal_strdup(UN1);
	records[0]->source = jal_strdup(UN1);
	assert_equals(0, uuid_parse(UUID_1, records[0]->uuid));

	records[1]->version = EXPECTED_RECORD_VERSION;
	records[1]->source = jal_strdup("source");
	records[1]->type = JALDB_RTYPE_LOG;
	records[1]->timestamp = jal_strdup(DT2);
	records[1]->payload = jaldb_create_segment();
	records[1]->username = jal_strdup(UN2);
	records[1]->hostname = jal_strdup(HN2);
	records[1]->source = jal_strdup(S2);
	assert_equals(0, uuid_parse(UUID_2, records[1]->uuid));

	records[2]->version = EXPECTED_RECORD_VERSION;
	records[2]->source = jal_strdup("source");
	records[2]->type = JALDB_RTYPE_LOG;
	records[2]->timestamp = jal_strdup(DT3);
	records[2]->payload = jaldb_create_segment();
	records[2]->username = jal_strdup(UN3);
	records[2]->hostname = jal_strdup(HN3);
	records[2]->source = jal_strdup(S3);
	assert_equals(0, uuid_parse(UUID_3, records[2]->uuid));

	records[3]->version = EXPECTED_RECORD_VERSION;
	records[3]->source = jal_strdup("source");
	records[3]->type = JALDB_RTYPE_LOG;
	records[3]->timestamp = jal_strdup(DT4);
	records[3]->payload = jaldb_create_segment();
	records[3]->username = jal_strdup(UN4);
	records[3]->hostname = jal_strdup(HN4);
	records[3]->source = jal_strdup(S4);
	assert_equals(0, uuid_parse(UUID_4, records[3]->uuid));

	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0]));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[1]));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[2]));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[3]));

	start = BN_new();
	BN_set_word(start, 1);

	end = BN_new();
	BN_set_word(end, 4);
}

extern "C" void teardown()
{
	jaldb_context_destroy(&context);
	dir_cleanup(DB_ROOT);

	if (start) {
		BN_free(start);
	}

	if (end) {
		BN_free(end);
	}
	for(int i = 0; i < ITEMS_IN_DB; i++) {
		jaldb_destroy_record(&records[i]);
	}

	xmlSchemaCleanupTypes();
}

extern "C" void test_iterate_by_sid_works_with_nulls_for_range()
{
	enum jaldb_status ret;
	current = 1;
	ret = jaldb_iterate_by_sid_range(context, JALDB_RTYPE_LOG, NULL, NULL, iter_cb, &fail_up);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, fail_up);
	assert_equals(ITEMS_IN_DB, iter_call_cnt);
}

extern "C" void test_iterate_by_works_with_end_point()
{
	enum jaldb_status ret;
	current = 1;
	ret = jaldb_iterate_by_sid_range(context, JALDB_RTYPE_LOG, NULL, END_HEX, iter_cb, &fail_up);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, fail_up);
	assert_equals(ITEMS_IN_DB, iter_call_cnt);
}

extern "C" void test_iterate_by_works_with_start_point()
{
	enum jaldb_status ret;
	current = 1;
	ret = jaldb_iterate_by_sid_range(context, JALDB_RTYPE_LOG, START_HEX, NULL, iter_cb, &fail_up);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, fail_up);
	assert_equals(ITEMS_IN_DB, iter_call_cnt);
}

extern "C" void test_iterate_by_works_with_start_and_end()
{
	enum jaldb_status ret;
	current = 1;
	ret = jaldb_iterate_by_sid_range(context, JALDB_RTYPE_LOG, START_HEX, END_HEX, iter_cb, &fail_up);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, fail_up);
	assert_equals(ITEMS_IN_DB, iter_call_cnt);
}

extern "C" void test_iterate_by_works_with_limits()
{
	enum jaldb_status ret;
	current = 2;
	ret = jaldb_iterate_by_sid_range(context, JALDB_RTYPE_LOG, "2", "3", iter_cb, &fail_up);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, fail_up);
	// should only get call for records 1 & 3
	assert_equals(2, iter_call_cnt);
}

extern "C" enum jaldb_iter_status iter_cb_for_gap_test(const char *hex_sid, struct jaldb_record *rec, void *up)
{
	char *failure = (char*)up;
	enum jaldb_iter_status ret = JALDB_ITER_CONT;
	iter_call_cnt++;
	BIGNUM *expected = BN_new();
	BIGNUM *actual = NULL;
	if (current > ITEMS_IN_DB) {
		goto fail;
	}
	BN_set_word(expected, current);

	BN_hex2bn(&actual, hex_sid);
	if (0 != BN_cmp(actual, expected)) {
		goto fail;
	}

	if (0 != uuid_compare(rec->uuid, records[current - 1]->uuid)) {
		goto fail;
	}
	ret = JALDB_ITER_CONT;
	// The Gap test does a range from 2 to 4 (with record 3 deleted)
	current = 4;
	goto out;
fail:
	*failure = 1;
	ret = JALDB_ITER_ABORT;
out:
	if (actual) {
		BN_free(actual);
	}
	if (expected) {
		BN_free(expected);
	}
	return ret;
}

extern "C" void test_iterate_by_works_with_limits_and_gaps()
{
	enum jaldb_status ret;
	current = 2;
	ret = jaldb_remove_record(context, JALDB_RTYPE_LOG, (char*)"3");
	assert_equals(JALDB_OK, ret);
	ret = jaldb_iterate_by_sid_range(context, JALDB_RTYPE_LOG, "2", "4", iter_cb_for_gap_test, &fail_up);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, fail_up);
	// should only get call for records 2 & 4
	assert_equals(2, iter_call_cnt);
}

extern "C" enum jaldb_iter_status iter_cb_delete(const char *hex_sid, struct jaldb_record *rec, void *up)
{
	char *failure = (char*)up;
	enum jaldb_iter_status ret = JALDB_ITER_CONT;
	iter_call_cnt++;
	BIGNUM *expected = BN_new();
	BIGNUM *actual = NULL;
	if (current > ITEMS_IN_DB) {
		goto fail;
	}

	BN_set_word(expected, current);

	BN_hex2bn(&actual, hex_sid);
	if (0 != BN_cmp(actual, expected)) {
		goto fail;
	}

	if (0 != uuid_compare(rec->uuid, records[current - 1]->uuid)) {
		goto fail;
	}
	ret = JALDB_ITER_REM;
	current++;
	goto out;
fail:
	*failure = 1;
	ret = JALDB_ITER_ABORT;
out:
	if (actual) {
		BN_free(actual);
	}
	if (expected) {
		BN_free(expected);
	}
	return ret;
}

extern "C" void test_with_deletion_works()
{
	struct jaldb_record *rec = NULL;
	enum jaldb_status ret;
	current = 1;
	ret = jaldb_iterate_by_sid_range(context, JALDB_RTYPE_LOG, NULL, "3", iter_cb_delete, &fail_up);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, fail_up);
	// should get called for 1, 2, 3
	assert_equals(3, iter_call_cnt);

	assert_equals(JALDB_E_NOT_FOUND, jaldb_get_record(context, JALDB_RTYPE_LOG, (char*)"1", &rec))
	assert_equals(JALDB_E_NOT_FOUND, jaldb_get_record(context, JALDB_RTYPE_LOG, (char*)"2", &rec));
	assert_equals(JALDB_E_NOT_FOUND, jaldb_get_record(context, JALDB_RTYPE_LOG, (char*)"3", &rec));
	assert_equals(JALDB_OK, jaldb_get_record(context, JALDB_RTYPE_LOG, (char*)"4", &rec));
	jaldb_destroy_record(&rec);
}
