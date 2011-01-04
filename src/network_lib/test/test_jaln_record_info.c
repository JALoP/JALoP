/**
 * @file test_jaln_record_info.c This file contains tests for jaln_record_info.c functions.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011 Tresys Technology LLC, Columbia, Maryland, USA
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
#include "jaln_record_info.h"

#define SERIAL_ID "1234"

static struct jaln_record_info *rec_info;

void setup()
{
	rec_info = jaln_record_info_create();
	rec_info->type = JALN_RTYPE_LOG;
	rec_info->serial_id = jal_strdup(SERIAL_ID);

	rec_info->sys_meta_len = 10;
	rec_info->app_meta_len = 20;
	rec_info->payload_len = 30;
}

void teardown()
{
	jaln_record_info_destroy(&rec_info);
}

void test_record_info_create_works()
{

	struct jaln_record_info *ri = jaln_record_info_create();
	assert_not_equals((void*)NULL, ri);
	assert_equals(0, ri->type);
	assert_equals((void*)NULL, ri->serial_id);
	assert_equals(0, ri->sys_meta_len);
	assert_equals(0, ri->app_meta_len);
	assert_equals(0, ri->payload_len);

	jaln_record_info_destroy(&ri);
	assert_pointer_equals((void*) NULL, ri);
}

void test_record_info_destroy_works()
{
	jaln_record_info_destroy(&rec_info);
	assert_equals((void*)NULL, rec_info);
}

void test_record_info_destroy_does_not_crash()
{
	struct jaln_record_info *ri = NULL;

	jaln_record_info_destroy(&ri);
	assert_pointer_equals((void*) NULL, ri);
	jaln_record_info_destroy(NULL);
}

void test_record_info_is_valid_fails_with_bad_type()
{
	rec_info->type = 0;
	assert_false(jaln_record_info_is_valid(rec_info));

	rec_info->type = 1 << 3;
	assert_false(jaln_record_info_is_valid(rec_info));
}

void test_record_info_is_valid_fails_with_bad_serial_id()
{
	free(rec_info->serial_id);
	rec_info->serial_id = NULL;
	assert_false(jaln_record_info_is_valid(rec_info));
}

void test_record_info_is_valid_fails_without_sys_meta()
{
	rec_info->type = JALN_RTYPE_JOURNAL;
	rec_info->sys_meta_len = 0;
	assert_false(jaln_record_info_is_valid(rec_info));

	rec_info->type = JALN_RTYPE_AUDIT;
	assert_false(jaln_record_info_is_valid(rec_info));

	rec_info->type = JALN_RTYPE_LOG;
	assert_false(jaln_record_info_is_valid(rec_info));
}

void test_record_info_is_valid_fails_when_missing_app_meta()
{
	rec_info->type = JALN_RTYPE_JOURNAL;
	rec_info->app_meta_len = 0;

	assert_true(jaln_record_info_is_valid(rec_info));

	rec_info->type = JALN_RTYPE_AUDIT;
	assert_true(jaln_record_info_is_valid(rec_info));

	rec_info->type = JALN_RTYPE_LOG;
	assert_true(jaln_record_info_is_valid(rec_info));
}

void test_record_info_is_valid_fails_for_journal_without_payload()
{
	rec_info->type = JALN_RTYPE_JOURNAL;
	rec_info->payload_len = 0;
	assert_false(jaln_record_info_is_valid(rec_info));
}

void test_record_info_is_valid_fails_when_record_info_is_null()
{
	assert_false(jaln_record_info_is_valid(NULL));
}

void test_record_info_is_valid_fails_for_audit_without_payload()
{
	rec_info->type = JALN_RTYPE_AUDIT;
	rec_info->payload_len = 0;
	assert_false(jaln_record_info_is_valid(rec_info));
}

void test_record_info_is_valid_fails_for_log_without_paylaod_or_app_meta()
{
	rec_info->type = JALN_RTYPE_LOG;
	rec_info->payload_len = 0;
	rec_info->app_meta_len = 0;
	assert_false(jaln_record_info_is_valid(rec_info));
}

void test_record_info_is_valid_works_for_log_without_paylaod()
{
	rec_info->type = JALN_RTYPE_LOG;
	rec_info->payload_len = 0;
	assert_true(jaln_record_info_is_valid(rec_info));
}
