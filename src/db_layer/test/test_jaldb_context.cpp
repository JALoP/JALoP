/**
 * @file test_jaldb_context.cpp This file contains functions to test
 * jaldb_context.cpp.
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
#define __STDC_FORMAT_MACROS
#include <db.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libxml/xmlschemastypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>
#include <stdlib.h>
#include "jal_alloc.h"
#include "jaldb_context.hpp"
#include "jaldb_strings.h"
#include "jaldb_segment.h"
#include "jaldb_utils.h"

using namespace std;

#define OTHER_DB_ROOT "./testdb/"
#define OTHER_SCHEMA_ROOT "./schemas/"
#define JOURNAL_ROOT "/journal/"
#define AUDIT_SYS_TEST_XML_DOC "./test-input/domwriter_audit_sys.xml"
#define AUDIT_APP_TEST_XML_DOC "./test-input/domwriter_audit_app.xml"
#define FAKE_NONCE "12341234"
#define AUDIT_TEST_XML_DOC "./test-input/domwriter_audit.xml"
#define LOG_SYS_TEST_XML_DOC "./test-input/domwriter_log_sys.xml"
#define LOG_APP_TEST_XML_DOC "./test-input/domwriter_log_app.xml"
#define REMOTE_HOST "remote_host"
#define TEST_XML_DOC "./test-input/domwriter.xml"
#define LOG_DATA_X "Log Buffer\nLog Entry 1\n"
#define LOG_DATA_Y "Log Buffer\nLog Entry 1\nLog Entry 2\n"
#define PAYLOAD "SoMe_data   is here\nMoreData is Here!\n"

#define LIMIT 100
#define LIMIT_NUM_DIGITS 3
#define LAST_NONCE_VALUE "doc_50"
#define LAST_K_RECORDS_VALUE 20

// record NONCE 1
#define DT1 "2012-12-12T09:00:00.00000"
#define HN1 "somehost"
#define UN1 "someuser"
#define S1 "source1"
#define UUID_1 "11234567-89AB-CDEF-0123-456789ABCDEF"

// record NONCE 2
#define DT2 "2012-12-12T02:00:00.00000"
#define HN2 "somehost2"
#define UN2 "someuser2"
#define S2 "source2"
#define UUID_2 "21234567-89AB-CDEF-0123-456789ABCDEF"

// record NONCE 3
#define DT3 "2012-12-12T03:00:00.00000"
#define HN3 "somehost3"
#define UN3 "someuser3"
#define S3 "source3"
#define UUID_3 "31234567-89AB-CDEF-0123-456789ABCDEF"

// record NONCE 4
#define DT4 "2012-12-12T04:00:00.00000"
#define HN4 "somehost4"
#define UN4 "someuser4"
#define S4 "source4"
#define UUID_4 "41234567-89AB-CDEF-0123-456789ABCDEF"

#define EXPECTED_RECORD_VERSION 1

static void *audit_sys_meta_doc = NULL;
static void *audit_app_meta_doc = NULL;
static void *audit_doc = NULL;
static void *log_sys_meta_doc = NULL;
static void *log_app_meta_doc = NULL;
static jaldb_context *context = NULL;

#define ITEMS_IN_DB 4
struct jaldb_record *records[ITEMS_IN_DB];

extern "C" void setup()
{
	dir_cleanup(OTHER_DB_ROOT);
	mkdir(OTHER_DB_ROOT, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	context = jaldb_context_create();
	assert_equals(JALDB_OK, jaldb_context_init(context, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, false));

	records[0] = jaldb_create_record();
	records[0]->version = EXPECTED_RECORD_VERSION;
	records[0]->type = JALDB_RTYPE_LOG;
	records[0]->timestamp = jal_strdup(DT1);
	records[0]->hostname = jal_strdup(HN1);
	records[0]->source = jal_strdup(S1);
	records[0]->username = jal_strdup(UN1);
	records[0]->payload = jaldb_create_segment();
	assert_equals(0, uuid_parse(UUID_1, records[0]->uuid));

	records[1] = jaldb_create_record();
	records[1]->version = EXPECTED_RECORD_VERSION;
	records[1]->type = JALDB_RTYPE_LOG;
	records[1]->timestamp = jal_strdup(DT2);
	records[1]->hostname = jal_strdup(HN2);
	records[1]->source = jal_strdup(S2);
	records[1]->username = jal_strdup(UN2);
	records[1]->payload = jaldb_create_segment();
	assert_equals(0, uuid_parse(UUID_2, records[1]->uuid));

	records[2] = jaldb_create_record();
	records[2]->version = EXPECTED_RECORD_VERSION;
	records[2]->type = JALDB_RTYPE_LOG;
	records[2]->timestamp = jal_strdup(DT3);
	records[2]->hostname = jal_strdup(HN3);
	records[2]->source = jal_strdup(S3);
	records[2]->username = jal_strdup(UN3);
	records[2]->payload = jaldb_create_segment();
	assert_equals(0, uuid_parse(UUID_3, records[2]->uuid));

	records[3] = jaldb_create_record();
	records[3]->version = EXPECTED_RECORD_VERSION;
	records[3]->type = JALDB_RTYPE_LOG;
	records[3]->timestamp = jal_strdup(DT4);
	records[3]->hostname = jal_strdup(HN4);
	records[3]->source = jal_strdup(S4);
	records[3]->username = jal_strdup(UN4);
	records[3]->payload = jaldb_create_segment();
	assert_equals(0, uuid_parse(UUID_4, records[3]->uuid));
}

extern "C" void teardown()
{
	audit_sys_meta_doc = NULL;
	audit_app_meta_doc = NULL;
	audit_doc = NULL;
	log_sys_meta_doc = NULL;
	log_app_meta_doc = NULL;
	jaldb_context_destroy(&context);
	dir_cleanup(OTHER_DB_ROOT);

	for(int i = 0; i < ITEMS_IN_DB; i++) {
		jaldb_destroy_record(&records[i]);
	}

	xmlSchemaCleanupTypes();
}

extern "C" void test_remove_by_nonce()
{
	struct jaldb_record *rec = NULL;

	char *nonce = NULL;	

	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce));
	assert_equals(JALDB_OK, jaldb_remove_record(context, JALDB_RTYPE_LOG, nonce));
	assert_equals(JALDB_E_NOT_FOUND, jaldb_get_record(context, JALDB_RTYPE_LOG, nonce, &rec));

	free(nonce);
	nonce = NULL;
}

extern "C" void test_remove_by_nonce_returns_error_when_not_found()
{
	char *nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce));
	assert_equals(JALDB_E_NOT_FOUND, jaldb_remove_record(context, JALDB_RTYPE_LOG, (char*)"2"));
	free(nonce);
	nonce = NULL;
}

extern "C" void test_mark_record_synced_succeeds_if_not_marked_sent()
{
	char *nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce));
	assert_equals(JALDB_OK, jaldb_mark_synced(context, JALDB_RTYPE_LOG, nonce));
	free(nonce);
	nonce = NULL;
}

extern "C" void test_mark_record_synced_returns_error_when_nonce_not_found()
{
	char *nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce));
	assert_equals(JALDB_E_NOT_FOUND, jaldb_mark_synced(context, JALDB_RTYPE_LOG, (const char*)"2"));
	free(nonce);
	nonce = NULL;
}

extern "C" void test_mark_record_sent()
{
	struct jaldb_record *rec = NULL;
	char *nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce));

	assert_equals(JALDB_OK, jaldb_get_record(context, JALDB_RTYPE_LOG, nonce, &rec));
	assert_equals(0, rec->synced);
	jaldb_destroy_record(&rec);
	rec = NULL;

	assert_equals(JALDB_OK, jaldb_mark_sent(context, JALDB_RTYPE_LOG, nonce));

	assert_equals(JALDB_OK, jaldb_get_record(context, JALDB_RTYPE_LOG, nonce, &rec));
	assert_equals(1, rec->synced);
	jaldb_destroy_record(&rec);
	free(nonce);
}

extern "C" void test_mark_record_sent_and_synced()
{
	struct jaldb_record *rec = NULL;
	char *nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce));
	assert_equals(JALDB_OK, jaldb_mark_sent(context, JALDB_RTYPE_LOG, nonce));
	assert_equals(JALDB_OK, jaldb_mark_synced(context, JALDB_RTYPE_LOG, nonce));

	assert_equals(JALDB_OK, jaldb_get_record(context, JALDB_RTYPE_LOG, nonce, &rec));
	assert_equals(2, rec->synced);
	jaldb_destroy_record(&rec);
	free(nonce);
}

extern "C" void test_marking_record_synced_doesnt_affect_sent_ordering()
{
	struct jaldb_record *rec1 = NULL;
	struct jaldb_record *rec2 = NULL;
	struct jaldb_record *rec3 = NULL;
	char *nonce1 = NULL;
	char *nonce2 = NULL;
	char *nonce3 = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce1));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[1], 1, &nonce2));
	assert_equals(JALDB_OK, jaldb_mark_sent(context, JALDB_RTYPE_LOG, nonce1));
	assert_equals(JALDB_OK, jaldb_mark_synced(context, JALDB_RTYPE_LOG, nonce1));

	assert_equals(JALDB_OK, jaldb_next_unsynced_record(context,JALDB_RTYPE_LOG, &nonce3, &rec3));

	assert_equals(0, strcmp(nonce2,nonce3));

	assert_equals(JALDB_OK, jaldb_mark_sent(context, JALDB_RTYPE_LOG, nonce2));

	assert_equals(JALDB_OK, jaldb_get_record(context, JALDB_RTYPE_LOG, nonce1, &rec1));
	assert_equals(JALDB_OK, jaldb_get_record(context, JALDB_RTYPE_LOG, nonce2, &rec2));
	assert_equals(2, rec1->synced);
	assert_equals(1, rec2->synced);
	jaldb_destroy_record(&rec1);
	jaldb_destroy_record(&rec2);
	jaldb_destroy_record(&rec3);
	free(nonce1);
	free(nonce2);
	free(nonce3);
}

extern "C" void test_mark_record_sent_returns_error_when_nonce_not_found()
{
	char *nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce));
	assert_equals(JALDB_E_NOT_FOUND, jaldb_mark_sent(context, JALDB_RTYPE_LOG, (const char*)"2"));
	free(nonce);
	nonce = NULL;
}


extern "C" void test_next_unsynced_works()
{
	struct jaldb_record *rec = NULL;
	char *nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce));
	free(nonce);
	nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[1], 1, &nonce));
	free(nonce);
	nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[2], 1, &nonce));
	free(nonce);
	nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[3], 1, &nonce));
	free(nonce);
	nonce = NULL;

	assert_equals(JALDB_OK, jaldb_next_unsynced_record(context, JALDB_RTYPE_LOG, &nonce, &rec));
	assert_string_equals(S1, rec->source);
	jaldb_destroy_record(&rec);

	assert_equals(JALDB_OK, jaldb_mark_sent(context, JALDB_RTYPE_LOG, nonce));
	assert_equals(JALDB_OK, jaldb_mark_synced(context, JALDB_RTYPE_LOG, nonce));

	free(nonce);
	nonce = NULL;
	rec = NULL;

	assert_equals(JALDB_OK, jaldb_next_unsynced_record(context, JALDB_RTYPE_LOG, &nonce, &rec));
	assert_string_equals(S2, rec->source);
	jaldb_destroy_record(&rec);
	rec = NULL;

	free(nonce);
	nonce = NULL;

	assert_equals(JALDB_OK, jaldb_next_unsynced_record(context, JALDB_RTYPE_LOG, &nonce, &rec));
	assert_string_equals(S2, rec->source);
	jaldb_destroy_record(&rec);
	rec = NULL;

	assert_equals(JALDB_OK, jaldb_mark_sent(context, JALDB_RTYPE_LOG, nonce));
	assert_equals(JALDB_OK, jaldb_mark_synced(context, JALDB_RTYPE_LOG, nonce));

	free(nonce);
	nonce = NULL;
	rec = NULL;

	// now records 1 and 2 are synced.
	assert_equals(JALDB_OK, jaldb_next_unsynced_record(context, JALDB_RTYPE_LOG, &nonce, &rec));
	assert_string_equals(S3, rec->source);
	jaldb_destroy_record(&rec);

	assert_equals(JALDB_OK, jaldb_mark_sent(context, JALDB_RTYPE_LOG, nonce));
	assert_equals(JALDB_OK, jaldb_mark_synced(context, JALDB_RTYPE_LOG, nonce));

	free(nonce);
	nonce = NULL;
	rec = NULL;

	assert_equals(JALDB_OK, jaldb_next_unsynced_record(context, JALDB_RTYPE_LOG, &nonce, &rec));
	assert_string_equals(S4, rec->source);
	jaldb_destroy_record(&rec);

	assert_equals(JALDB_OK, jaldb_mark_sent(context, JALDB_RTYPE_LOG, nonce));
	assert_equals(JALDB_OK, jaldb_mark_synced(context, JALDB_RTYPE_LOG, nonce));

	free(nonce);
	nonce = NULL;
	rec = NULL;

	// everything is synced now...
	assert_equals(JALDB_E_NOT_FOUND, jaldb_next_unsynced_record(context, JALDB_RTYPE_LOG, &nonce, &rec));

}

extern "C" void test_next_chronological_works()
{
	struct jaldb_record *rec = NULL;
	char *nonce = NULL;
	char *start_time = NULL;
	char *end_time = NULL;

	start_time = jaldb_gen_timestamp();
	assert_not_equals(NULL, start_time);

	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce));
	free(nonce);
	nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[1], 1, &nonce));
	free(nonce);
	nonce = NULL;

	sleep(2);
	
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[2], 1, &nonce));
	free(nonce);
	nonce = NULL;
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[3], 1, &nonce));
	free(nonce);
	nonce = NULL;

	sleep(2);

	end_time = jaldb_gen_timestamp();
	assert_not_equals(NULL,end_time);

	assert_equals(JALDB_OK, jaldb_next_chronological_record(context, JALDB_RTYPE_LOG, &nonce, &rec, &start_time));
	assert_string_equals(S1, rec->source);
	jaldb_destroy_record(&rec);

	free(nonce);
	nonce = NULL;
	rec = NULL;

	assert_equals(JALDB_OK, jaldb_next_chronological_record(context, JALDB_RTYPE_LOG, &nonce, &rec, &start_time));
	assert_string_equals(S2, rec->source);
	jaldb_destroy_record(&rec);

	free(nonce);
	nonce = NULL;
	rec = NULL;

	assert_equals(JALDB_E_NOT_FOUND, jaldb_next_chronological_record(context, JALDB_RTYPE_LOG, &nonce, &rec, &end_time));

	assert_equals(JALDB_OK, jaldb_next_chronological_record(context, JALDB_RTYPE_LOG, &nonce, &rec, &start_time));
	assert_string_equals(S3, rec->source);
	jaldb_destroy_record(&rec);

	free(nonce);
	nonce = NULL;
	rec = NULL;

	assert_equals(JALDB_OK, jaldb_next_chronological_record(context, JALDB_RTYPE_LOG, &nonce, &rec, &start_time));
	assert_string_equals(S4, rec->source);
	jaldb_destroy_record(&rec);

	free(nonce);
	nonce = NULL;
	rec = NULL;

	assert_equals(JALDB_E_NOT_FOUND, jaldb_next_chronological_record(context, JALDB_RTYPE_LOG, &nonce, &rec, &start_time));

	free(start_time);
	free(end_time);

}

extern "C" void test_jaldb_get_last_k_records_works()
{
	enum jaldb_status ret;
	list<string> nonce_list;

	char *nonce1 = NULL;
	char *nonce2 = NULL;
	char *nonce3 = NULL;
	char *nonce4 = NULL;

	// Timestamp index is based on timestamp extract from record. Time order will be nonce 2, 3, 4, 1
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce1));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[1], 1, &nonce2));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[2], 1, &nonce3));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[3], 1, &nonce4));

	// Test getting n records, less than current number
	ret = jaldb_get_last_k_records(context, 3, nonce_list, JALDB_RTYPE_LOG, false);
	assert_equals(JALDB_OK, ret);
	assert_equals(3, nonce_list.size());
	assert_equals(nonce3, nonce_list.front());
	assert_equals(nonce1, nonce_list.back());
	nonce_list.clear();

	// Test getting n records, equal to current number
	ret = jaldb_get_last_k_records(context, 4, nonce_list, JALDB_RTYPE_LOG, false);
	assert_equals(JALDB_OK, ret);
	assert_equals(4, nonce_list.size());
	assert_equals(nonce2, nonce_list.front());
	assert_equals(nonce1, nonce_list.back());
	nonce_list.clear();

	// Test getting n records, greater than current number
	ret = jaldb_get_last_k_records(context, 10, nonce_list, JALDB_RTYPE_LOG, false);
	assert_equals(JALDB_OK, ret);
	assert_equals(4, nonce_list.size());
	assert_equals(nonce2, nonce_list.front());
	assert_equals(nonce1, nonce_list.back());
	nonce_list.clear();

	// Test getting all records with zero size passed
	ret = jaldb_get_last_k_records(context, 0, nonce_list, JALDB_RTYPE_LOG, true);
	assert_equals(JALDB_OK, ret);
	assert_equals(4, nonce_list.size());
	assert_equals(nonce2, nonce_list.front());
	assert_equals(nonce1, nonce_list.back());
	nonce_list.clear();

	// Test getting all records with less than current number size size passed
	ret = jaldb_get_last_k_records(context, 2, nonce_list, JALDB_RTYPE_LOG, true);
	assert_equals(JALDB_OK, ret);
	assert_equals(4, nonce_list.size());
	assert_equals(nonce2, nonce_list.front());
	assert_equals(nonce1, nonce_list.back());
	nonce_list.clear();

	free(nonce1);
	free(nonce2);
	free(nonce3);
	free(nonce4);
	nonce1 = NULL;
	nonce2 = NULL;
	nonce3 = NULL;
	nonce4= NULL;
}

extern "C" void test_jaldb_get_last_k_records_returns_error_with_no_records()
{
	enum jaldb_status ret;
	list<string> nonce_list;

	ret = jaldb_get_last_k_records(context, 3, nonce_list, JALDB_RTYPE_LOG);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_get_records_since_last_nonce_works()
{
	enum jaldb_status ret;
	list<string> nonce_list;

	char *nonce1 = NULL;
	char *nonce2 = NULL;
	char *nonce3 = NULL;
	char *nonce4 = NULL;

	// Timestamp index is based on timestamp extract from record. Time order will be nonce 2, 3, 4, 1
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce1));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[1], 1, &nonce2));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[2], 1, &nonce3));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[3], 1, &nonce4));

	ret = jaldb_get_records_since_last_nonce(context, nonce2, nonce_list, JALDB_RTYPE_LOG);
	assert_equals(JALDB_OK, ret);
	
	assert_equals(3, nonce_list.size());
	assert_equals(nonce3, nonce_list.front());
	assert_equals(nonce1, nonce_list.back());

	free(nonce1);
	free(nonce2);
	free(nonce3);
	free(nonce4);
	nonce1 = NULL;
	nonce2 = NULL;
	nonce3 = NULL;
	nonce4 = NULL;
}

extern "C" void test_jaldb_get_records_since_last_nonce_returns_error_with_missing_last_nonce()
{
	enum jaldb_status ret;
	list<string> nonce_list;

	char *nonce1 = NULL;
	char *nonce2 = NULL;
	char *nonce3 = NULL;
	char *nonce4 = NULL;
	char last_nonce[] =  "11111111-AAAA-BBBB-2222-333333CCCCCC";

	// Timestamp index is based on timestamp extract from record. Time order will be nonce 2, 3, 4, 1
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 1, &nonce1));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[1], 2, &nonce2));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[2], 2, &nonce3));
	assert_equals(JALDB_OK, jaldb_insert_record(context, records[3], 3, &nonce4));

	// If last nonce not found, then check for flag and all records returned
	ret = jaldb_get_records_since_last_nonce(context, last_nonce, nonce_list, JALDB_RTYPE_LOG);
	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals(4, nonce_list.size());
	assert_equals(nonce2, nonce_list.front());
	assert_equals(nonce1, nonce_list.back());

	free(nonce1);
	free(nonce2);
	free(nonce3);
	free(nonce4);
	nonce1 = NULL;
	nonce2 = NULL;
	nonce3 = NULL;
	nonce4 = NULL;
}

extern "C" void test_jaldb_get_records_since_last_nonce_returns_error_with_no_last_nonce()
{
	enum jaldb_status ret;
	list<string> nonce_list;
	ret = jaldb_get_records_since_last_nonce(context, NULL, nonce_list, JALDB_RTYPE_LOG);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_mark_confirmed_works()
{
	struct jaldb_record *rec = NULL;
	struct jaldb_record *temp_rec = NULL;
	char *nonce = NULL;
	char *nonce2 = NULL;
	
	records[0]->network_nonce = jal_strdup("1");

	assert_equals(JALDB_OK, jaldb_insert_record(context, records[0], 0, &nonce));
	assert_equals(JALDB_OK, jaldb_get_record(context, JALDB_RTYPE_LOG, nonce, &rec));
	assert_equals(0, rec->confirmed);
	assert_equals(JALDB_OK, jaldb_mark_confirmed(context, JALDB_RTYPE_LOG, (char*)"1",&nonce2));
	assert_string_equals(nonce,nonce2);

	jaldb_destroy_record(&rec);
	rec = NULL;

	assert_equals(JALDB_OK, jaldb_get_record(context, JALDB_RTYPE_LOG, nonce2, &rec));
	assert_equals(1, rec->confirmed);

	free(records[0]->network_nonce);
	records[0]->network_nonce = NULL;

	free(nonce);
	jaldb_destroy_record(&rec);
	jaldb_destroy_record(&temp_rec);
}

extern "C" void test_jaldb_mark_confirmed_returns_error_when_record_not_found()
{
	struct jaldb_record *temp_rec = NULL;
	char *nonce = NULL;
	assert_equals(JALDB_E_NOT_FOUND, jaldb_mark_confirmed(context, JALDB_RTYPE_LOG, (char*)"doesntexist", &nonce));
	assert_equals(NULL, nonce);
	jaldb_destroy_record(&temp_rec);
}

// Disabling tests for now
#if 0
extern "C" void test_db_destroy_does_not_crash()
{
	jaldb_context *ctx = NULL;
	jaldb_context_destroy(&ctx);

	jaldb_context_destroy(NULL);
}

extern "C" void test_db_destroy_sets_ctx_to_null()
{
	jaldb_context *ctx = jaldb_context_create();
	assert_not_equals((void *)NULL, ctx);
	enum jaldb_status ret = jaldb_context_init(ctx, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, false);
	assert_equals(JALDB_OK, ret);
	jaldb_context_destroy(&ctx);
	assert_pointer_equals((void *)NULL, ctx);
}

extern "C" void test_store_confed_journal_nonce_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *nonce = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret =
		jaldb_store_confed_journal_nonce(NULL, rhost, nonce, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_journal_nonce(context, rhost, nonce, &db_error_out);
	free(rhost);
	free(nonce);
	rhost = NULL;
	nonce = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_store_confed_audit_nonce_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *nonce = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret =
		jaldb_store_confed_audit_nonce(NULL, rhost, nonce, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	free(rhost);
	free(nonce);
	rhost = NULL;
	nonce = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_store_confed_log_nonce_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *nonce = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret =
		jaldb_store_confed_log_nonce(NULL, rhost, nonce, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	free(rhost);
	free(nonce);
	rhost = NULL;
	nonce = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_make_temp_db_name_returns_ok()
{
	std::string dbase_name = "__remote_host_temp.db";
	std::string db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, "temp.db");
	assert_string_equals(dbase_name.c_str(), db_name.c_str());
}


extern "C" void test_db_create_journal_file()
{
	// TODO: This should really be verifying that the path exists, fd is
	// open, etc. It should also clean up the created files.
	char *path = NULL;
	int fd;
	jaldb_create_journal_file(context, &path, &fd);
	free(path);
	close(fd);
}

extern "C" void test_open_temp_db_returns_ok()
{
	std::string log_db_name = jaldb_make_temp_db_name(REMOTE_HOST, JALDB_LOG_DB_NAME);
	DB *dbase_out = NULL;
	int db_error_out = 0;
	enum jaldb_status ret =
		jaldb_open_temp_db(context, log_db_name, &dbase_out, &db_error_out);
	assert_equals(JALDB_OK, ret);

	const char *file_name;
	int db_error;
	db_error = dbase_out->get_dbname(dbase_out, &file_name, NULL);
	assert_equals(0, db_error);
	assert_string_equals(log_db_name.c_str(), file_name);
}

extern "C" void test_open_temp_db_fails_with_invalid_input()
{
	std::string log_db_name = jaldb_make_temp_db_name(REMOTE_HOST, JALDB_LOG_DB_NAME);
	DB *dbase_out = NULL;
	int db_error_out = 0;
	enum jaldb_status ret =
		jaldb_open_temp_db(NULL, log_db_name, &dbase_out, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);

	string_to_db_map *tmp_temp_dbs = context->temp_dbs;
	context->temp_dbs = NULL;
	ret = jaldb_open_temp_db(context, log_db_name, &dbase_out, &db_error_out);
	context->temp_dbs = tmp_temp_dbs;
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);

	ret = jaldb_open_temp_db(context, log_db_name, NULL, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);

	dbase_out = (DB*) 0xDEADBEEF;
	ret = jaldb_open_temp_db(context, log_db_name, &dbase_out, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) 0xDEADBEEF, dbase_out);
	dbase_out = NULL;
	ret = jaldb_open_temp_db(context, log_db_name, &dbase_out, NULL);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);

	log_db_name = "";
	ret = jaldb_open_temp_db(context, log_db_name, &dbase_out, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);
}

extern "C" void test_read_only_flag_prevents_writing_to_db()
{
	jaldb_context *ctx = jaldb_context_create();
	enum jaldb_status ret;
	int db_err;
	ret = jaldb_context_init(ctx, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, 1);
	assert_equals(JALDB_OK, ret);

	std::string src = "foo";
	std::string nonce = "1";

	assert_true(0);
	jaldb_context_destroy(&ctx);
}

extern "C" void test_next_audit_record_returns_ok()
{
	std::string src = "";
	std::string last_nonce;
	std::string nonce;
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, NULL, audit_doc, last_nonce);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, NULL, audit_doc, nonce);
	assert_equals(JALDB_OK, ret);

	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *audit_buf = NULL;
	size_t audit_len = 0;
	char *next_nonce = NULL;

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		 &app_meta_buf, &app_meta_len, &audit_buf, &audit_len);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, next_nonce);
	assert_equals(0, strcmp(next_nonce, nonce.c_str()));
	assert_equals((void*)NULL, app_meta_buf);
	assert_equals(0, app_meta_len);
	assert_not_equals(NULL, sys_meta_buf);
	assert_not_equals(0, sys_meta_len);
	assert_not_equals(NULL, audit_buf);
	assert_not_equals(0, audit_len);

	free(next_nonce);
	free(app_meta_buf);
	free(sys_meta_buf);
	free(audit_buf);
}

extern "C" void test_next_audit_record_returns_ok_with_app_metadata()
{
	std::string src = "fake_host";
	std::string last_nonce;
	std::string nonce;
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, last_nonce);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, nonce);
	assert_equals(JALDB_OK, ret);

	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *audit_buf = NULL;
	size_t audit_len = 0;
	char *next_nonce = NULL;

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, app_meta_buf);
	assert_not_equals(0, app_meta_len);
	assert_not_equals(NULL, sys_meta_buf);
	assert_not_equals(0, sys_meta_len);
	assert_not_equals(NULL, audit_buf);
	assert_not_equals(0, audit_len);

	free(next_nonce);
	free(app_meta_buf);
	free(sys_meta_buf);
	free(audit_buf);
}

extern "C" void test_next_audit_fails_on_invalid_input()
{

	std::string src = "";
	audit_app_meta_doc = NULL;
	std::string last_nonce;
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, last_nonce);
	assert_equals(JALDB_OK, ret);

	//Test Vars
	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *audit_buf = NULL;
	uint8_t *bad_pointer = (uint8_t*)0xDEADBEEF;
	size_t audit_len = 0;
	char *next_nonce = NULL;

	ret = jaldb_next_audit_record(NULL, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, NULL, &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), NULL, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	next_nonce = (char*) 0xbadf00d;
	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);
	next_nonce = NULL;

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, NULL, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &bad_pointer, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, NULL,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		NULL, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&bad_pointer, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, NULL, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, NULL, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &bad_pointer, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, NULL);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, NULL, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_next_log_record_fails_on_invalid_input()
{
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	int db_err = 0;
	char *next_nonce;
	std::string src = "";
	audit_app_meta_doc = NULL;
	std::string nonce = "3";
	jaldb_status ret;

	ret = jaldb_insert_log_record(
			context, src, log_sys_meta_doc, log_app_meta_doc, logbuf, loglen, nonce, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	//Test Vars
	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *log_buf = NULL;
	uint8_t *bad_pointer = (uint8_t*)0xDEADBEEF;
	size_t log_len = 0;

	ret = jaldb_next_log_record(NULL, nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, NULL, &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), NULL, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	next_nonce = (char*) 0xbadf00d;
	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_meta_buf,
			&sys_meta_len, &app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);
	next_nonce = NULL;

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, NULL, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &bad_pointer, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_meta_buf, NULL,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		NULL, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&bad_pointer, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, NULL, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, NULL, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &bad_pointer, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, NULL, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, NULL);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_next_log_record_succeeds()
{
	std::string src;
	std::string last_nonce;
	std::string nonce;
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	int db_err = 0;
	enum jaldb_status ret;

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
				logbuf, loglen, last_nonce, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
				logbuf, loglen, nonce, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	char *next_nonce = NULL;
	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;

	ret = jaldb_next_log_record(context, last_nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, next_nonce);
	assert_equals(0, strcmp(next_nonce, nonce.c_str()));
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_not_equals(NULL, app_buf);
	assert_true(app_sz > 0);
	assert_not_equals(NULL, log_buf);
	assert_true(log_sz > 0);
	assert_equals(0, db_err);

	free(next_nonce);
	free(sys_buf);
	free(app_buf);
	free(log_buf);
}

extern "C" void test_jaldb_next_log_record_succeeds_with_no_app_meta()
{
	std::string src;
	std::string last_nonce;
	std::string nonce;
	char *next_nonce = NULL;
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	int db_err = 0;
	enum jaldb_status ret;

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, NULL,
				logbuf, loglen, last_nonce, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, NULL,
				logbuf, loglen, nonce, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);


	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;

	ret = jaldb_next_log_record(context, last_nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, next_nonce);
	assert_equals(0, strcmp(nonce.c_str(), next_nonce));
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_not_equals(NULL, log_buf);
	assert_true(log_sz > 0);
	assert_equals(0, db_err);

	free(next_nonce);
	free(sys_buf);
	free(log_buf);
}

extern "C" void test_jaldb_next_log_record_returns_not_found()
{
	std::string src;
	std::string nonce = "1";
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	char *next_nonce = NULL;
	enum jaldb_status ret;
	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;
	int db_err = 0;

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_equals((void*)NULL, log_buf);
	assert_true(log_sz == 0);

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, NULL,
				logbuf, loglen, nonce, &db_err);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_next_log_record(context, nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_equals((void*)NULL, log_buf);
	assert_true(log_sz == 0);
}

extern "C" void test_jaldb_next_log_record_succeeds_when_no_log_meta()
{
	std::string src;
	std::string last_nonce;
	std::string nonce;
	char *next_nonce = NULL;
	int db_err = 0;
	enum jaldb_status ret;

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
				NULL, 0, last_nonce, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
				NULL, 0, nonce, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);


	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;

	ret = jaldb_next_log_record(context, last_nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, next_nonce);
	assert_equals(0, strcmp(nonce.c_str(), next_nonce));
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_not_equals(NULL, app_buf);
	assert_true(app_sz > 0);
	assert_equals((void*)NULL, log_buf);
	assert_true(log_sz == 0);
	assert_equals(0, db_err);
	free(next_nonce);
	free(sys_buf);
	free(app_buf);
}

extern "C" void test_jaldb_next_journal_record_fails_on_invalid_input()
{
	enum jaldb_status ret;
	int fd = -1;
	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	char *next_nonce = NULL;
	std::string nonce = "12341234";

	ret = jaldb_next_journal_record(context, nonce.c_str(), &next_nonce, NULL,
				&sys_sz, &app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_next_journal_record(context, NULL, &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_next_journal_record(NULL, nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_next_journal_record(context, nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				NULL, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_next_journal_record(context, nonce.c_str(), &next_nonce, NULL, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	sys_buf = (uint8_t *)malloc(sizeof(*sys_buf));
	ret = jaldb_next_journal_record(context, nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	free(sys_buf);
	sys_buf = NULL;

	app_buf = (uint8_t *)malloc(sizeof(*sys_buf));
	ret = jaldb_next_journal_record(context, nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_not_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	free(app_buf);
	app_buf = NULL;


	fd = 0;
	ret = jaldb_next_journal_record(context, nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == 0);
	fd = -1;

	ret = jaldb_next_journal_record(context, nonce.c_str(), NULL, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	next_nonce = (char*) 0xbadf00d;
	ret = jaldb_next_journal_record(context, nonce.c_str(), &next_nonce, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
}

extern "C" void test_jaldb_next_journal_record_succeeds()
{
	int rc = 0;
	int fd = -1;
	std::string source;
	std::string last_nonce;
	std::string nonce;
	char *next_nonce = NULL;
	std::string msg = "journal";
	char *buf = NULL;
	char *path = NULL;
	enum jaldb_status ret;

	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					audit_app_meta_doc,
					path,
					last_nonce);

	assert_equals(JALDB_OK, ret);
	fd = -1;
	free(path);
	path = NULL;
	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					NULL,
					path,
					nonce);

	assert_equals(JALDB_OK, ret);

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	fd = -1;

	ret = jaldb_next_journal_record(context,
				last_nonce.c_str(),
				&next_nonce,
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, sys_buf);
	assert_not_equals(NULL, next_nonce);
	assert_equals(0, strcmp(nonce.c_str(), next_nonce));
	assert_true(sys_sz > 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd > -1);
	assert_true(fd_sz > 0);

	buf = (char *)malloc(fd_sz);
	rc = read(fd, buf, fd_sz);
	assert_not_equals(-1, rc);
	assert_true(!strcmp(buf, msg.c_str()));
	close(fd);
	free(next_nonce);
	free(path);
	free(buf);
	free(sys_buf);
	free(app_buf);
}

extern "C" void test_jaldb_next_journal_record_succeeds_with_no_app_meta()
{
	int rc = 0;
	int fd = -1;
	std::string source;
	std::string last_nonce;
	std::string nonce;
	char *next_nonce = NULL;
	std::string msg = "journal";
	char *buf = NULL;
	char *path = NULL;
	enum jaldb_status ret;

	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					audit_app_meta_doc,
					path,
					last_nonce);

	assert_equals(JALDB_OK, ret);
	fd = -1;
	free(path);
	path = NULL;
	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					NULL,
					path,
					nonce);

	assert_equals(JALDB_OK, ret);

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	fd = -1;

	ret = jaldb_next_journal_record(context,
				last_nonce.c_str(),
				&next_nonce,
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, next_nonce);
	assert_equals(0, strcmp(nonce.c_str(), next_nonce));
	assert_not_equals(NULL, sys_buf);
	assert_equals(0, strcmp(nonce.c_str(), next_nonce));
	assert_true(sys_sz > 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd > -1);
	assert_true(fd_sz > 0);

	buf = (char *)malloc(fd_sz);
	rc = read(fd, buf, fd_sz);
	assert_not_equals(-1, rc);
	assert_true(!strcmp(buf, msg.c_str()));
	free(next_nonce);
	close(fd);
	free(path);
	free(buf);
	free(sys_buf);
}

extern "C" void test_jaldb_next_journal_record_returns_not_found()
{
	int rc = 0;
	int fd = -1;
	std::string nonce = "1";
	std::string source;
	enum jaldb_status ret;
	char *next_nonce = NULL;
	char *path = NULL;
	std::string msg = "journal";

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;

	ret = jaldb_next_journal_record(context,
				nonce.c_str(),
				&next_nonce,
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals((void*)NULL, next_nonce);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	assert_true(fd_sz == 0);

	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					NULL,
					path,
					nonce);

	assert_equals(JALDB_OK, ret);
	fd = -1;

	ret = jaldb_next_journal_record(context,
				nonce.c_str(),
				&next_nonce,
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals((void*)NULL, next_nonce);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	assert_true(fd_sz == 0);
}

extern "C" void test_jaldb_next_journal_record_returns_corrupted_when_no_journal_file()
{
	int fd = -1;
	std::string source;
	std::string last_nonce;
	std::string nonce;
	char *next_nonce = NULL;
	char *path = strdup("/foo/bar/journal.asdf");
	enum jaldb_status ret;

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					audit_app_meta_doc,
					path,
					last_nonce);

	assert_equals(JALDB_OK, ret);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					audit_app_meta_doc,
					path,
					nonce);

	assert_equals(JALDB_OK, ret);

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	fd = -1;

	ret = jaldb_next_journal_record(context,
				last_nonce.c_str(),
				&next_nonce,
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_E_CORRUPTED, ret);
	assert_equals((void*)NULL, next_nonce);
	assert_equals((void*)NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals((void*)NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	assert_true(fd_sz == 0);
	free(path);
}
#endif

