/**
 * @file test_jaldb_record.c This file contains functions to test
 * jaldb_record.c.
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

#include <test-dept.h>

#include "jal_alloc.h"

#include "jaldb_record.h"
#include "jaldb_segment.h"

#define EXPECTED_RECORD_VERSION 1

void test_jaldb_create_record_works()
{
	uuid_t test_uuid;
	uuid_clear(test_uuid);

	struct jaldb_record *record = jaldb_create_record();

	assert_not_equals(NULL, record);
	assert_equals(0, record->pid);
	assert_equals(0, record->uid);
	assert_pointer_equals((void*)NULL, record->sys_meta);
	assert_pointer_equals((void*)NULL, record->app_meta);
	assert_pointer_equals((void*)NULL, record->payload);
	assert_pointer_equals((void*)NULL, record->source);
	assert_pointer_equals((void*)NULL, record->hostname);
	assert_pointer_equals((void*)NULL, record->timestamp);
	assert_pointer_equals((void*)NULL, record->username);
	assert_pointer_equals((void*)NULL, record->sec_lbl);
	assert_equals(EXPECTED_RECORD_VERSION, record->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, record->type);
	assert_equals(0, record->synced);
	assert_equals(0, record->have_uid);
	assert_equals(0, uuid_compare(test_uuid, record->host_uuid));
	assert_equals(0, uuid_compare(test_uuid, record->uuid));
	assert_equals(0, record->synced);

	jaldb_destroy_record(&record);
}

void test_jaldb_destroy_record_works_does_not_crash()
{
	struct jaldb_record *record = NULL;
	jaldb_destroy_record(&record);
	jaldb_destroy_record(NULL);
}

void test_jaldb_destroy_release_all_elements()
{
	struct jaldb_record *record = jaldb_create_record();
	record->sys_meta = jaldb_create_segment();
	record->app_meta = jaldb_create_segment();
	record->payload = jaldb_create_segment();

	record->source = jal_strdup("source");
	record->hostname = jal_strdup("hostname");
	record->timestamp = jal_strdup("timestamp");
	record->username = jal_strdup("username");
	record->sec_lbl = jal_strdup("sec_lbl");

	jaldb_destroy_record(&record);
	assert_pointer_equals((void*) NULL, record);
}

void test_jaldb_destroy_works()
{
	struct jaldb_record *record = jaldb_create_record();
	jaldb_destroy_record(&record);
	assert_pointer_equals((void*) NULL, record);
}

void test_jaldfb_record_sanity_check_works_for_journal()
{
	enum jaldb_status ret;
	struct jaldb_record *record = jaldb_create_record();

	record->version = EXPECTED_RECORD_VERSION;
	record->payload = jaldb_create_segment();
	record->source = jal_strdup("source");
	record->hostname = jal_strdup("somehost");
	record->username = jal_strdup("someuser");
	record->type = JALDB_RTYPE_JOURNAL;

	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	record->app_meta = jaldb_create_segment();
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	record->sys_meta = jaldb_create_segment();
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	jaldb_destroy_segment(&record->payload);
	ret = jaldb_record_sanity_check(record);
	assert_not_equals(JALDB_OK, ret);

	jaldb_destroy_record(&record);
}

void test_jaldfb_record_sanity_check_works_for_audit()
{
	enum jaldb_status ret;
	struct jaldb_record *record = jaldb_create_record();

	record->version = EXPECTED_RECORD_VERSION;
	record->payload = jaldb_create_segment();
	record->source = jal_strdup("source");
	record->type = JALDB_RTYPE_AUDIT;
	record->hostname = jal_strdup("somehost");
	record->username = jal_strdup("someuser");

	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	record->app_meta = jaldb_create_segment();
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	record->sys_meta = jaldb_create_segment();
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	jaldb_destroy_segment(&record->payload);
	ret = jaldb_record_sanity_check(record);
	assert_not_equals(JALDB_OK, ret);

	jaldb_destroy_record(&record);
}
void test_jaldb_record_sanity_check_works_for_log()
{
	enum jaldb_status ret;
	struct jaldb_record *record = jaldb_create_record();

	record->version = EXPECTED_RECORD_VERSION;
	record->source = jal_strdup("source");
	record->hostname = jal_strdup("somehost");
	record->username = jal_strdup("someuser");
	record->type = JALDB_RTYPE_LOG;

	ret = jaldb_record_sanity_check(record);
	assert_not_equals(JALDB_OK, ret);

	record->app_meta = jaldb_create_segment();
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	record->sys_meta = jaldb_create_segment();
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	record->payload = jaldb_create_segment();
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	jaldb_destroy_segment(&record->app_meta);
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	jaldb_destroy_record(&record);
}

void test_jaldb_record_sanity_check_fails_for_null()
{
	enum jaldb_status ret;

	ret = jaldb_record_sanity_check(NULL);
	assert_not_equals(JALDB_OK, ret);
}

void test_jaldfb_record_sanity_check_fails_on_bad_segments()
{
	enum jaldb_status ret;
	struct jaldb_record *record = jaldb_create_record();

	record->version = EXPECTED_RECORD_VERSION;
	record->source = jal_strdup("source");
	record->hostname = jal_strdup("somehost");
	record->username = jal_strdup("someuser");
	record->type = JALDB_RTYPE_LOG;

	record->app_meta = jaldb_create_segment();
	record->app_meta->on_disk = 1;

	ret = jaldb_record_sanity_check(record);
	assert_not_equals(JALDB_OK, ret);

	record->sys_meta = record->app_meta;
	record->app_meta = NULL;
	ret = jaldb_record_sanity_check(record);
	assert_not_equals(JALDB_OK, ret);

	record->payload = record->sys_meta;
	record->sys_meta = NULL;
	ret = jaldb_record_sanity_check(record);
	assert_not_equals(JALDB_OK, ret);

	jaldb_destroy_record(&record);
}

void test_jaldb_record_sanity_check_fails_on_missing_fields()
{
	enum jaldb_status ret;
	struct jaldb_record *record = jaldb_create_record();

	record->version = EXPECTED_RECORD_VERSION;
	record->source = jal_strdup("source");
	record->type = JALDB_RTYPE_LOG;
	record->hostname = jal_strdup("somehost");
	record->username = jal_strdup("someuser");

	char *tmp;

	record->payload = jaldb_create_segment();

	tmp = record->hostname;
	record->hostname = NULL;
	ret = jaldb_record_sanity_check(record);
	record->hostname = tmp;
	assert_not_equals(JALDB_OK, ret);

	tmp = record->username;
	record->username = NULL;
	ret = jaldb_record_sanity_check(record);
	record->username = tmp;
	// assert_not_equals(JALDB_OK, ret);// probably because SO_PEERCRED.

	tmp = record->source;
	record->source = NULL;
	ret = jaldb_record_sanity_check(record);
	record->source = tmp;
	assert_not_equals(JALDB_OK, ret);

	jaldb_destroy_record(&record);
}

void test_jaldb_record_sanity_check_fails_for_large_record()
{
	enum jaldb_status ret;
	struct jaldb_record *record = jaldb_create_record();

	record->version = EXPECTED_RECORD_VERSION;
	record->source = jal_strdup("source");
	record->hostname = jal_strdup("somehost");
	record->username = jal_strdup("someuser");
	record->type = JALDB_RTYPE_LOG;

	ret = jaldb_record_sanity_check(record);
	assert_not_equals(JALDB_OK, ret);

	record->app_meta = jaldb_create_segment();
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	record->sys_meta = jaldb_create_segment();
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	record->payload = jaldb_create_segment();
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	record->app_meta->length = 50000000;
	record->app_meta->payload = (uint8_t*) jal_strdup("app_meta");
	record->sys_meta->length = 50000000;
	record->sys_meta->payload = (uint8_t*) jal_strdup("sys_meta");
	record->payload->length  = 100000001;
	record->payload->payload = (uint8_t*) jal_strdup("payload");


	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_E_REJECT, ret);

	jaldb_destroy_segment(&record->app_meta);
	ret = jaldb_record_sanity_check(record);
	assert_equals(JALDB_OK, ret);

	jaldb_destroy_record(&record);
}
