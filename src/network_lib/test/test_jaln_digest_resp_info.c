/**
 * @file test_jaln_digest_resp_info.c This file contains tests for jaln_digest_resp_info.c functions.
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
#include "jaln_digest_resp_info.h"

static  char *sid = "some_sid";
static  char *sid_2 = "other_sid";

void setup()
{
}
void teardown()
{
}

void test_digest_resp_info_create_works_with_valid_input_for_confirmed()
{

	struct jaln_digest_resp_info *di = jaln_digest_resp_info_create(sid, JALN_DIGEST_STATUS_CONFIRMED);
	assert_not_equals((void*)NULL, di);

	assert_not_equals((void*)NULL, di->serial_id);
	assert_not_equals(sid, di->serial_id);
	assert_string_equals(sid, di->serial_id);

	assert_equals(JALN_DIGEST_STATUS_CONFIRMED, di->status);
	jaln_digest_resp_info_destroy(&di);
	assert_pointer_equals((void*) NULL, di);
}

void test_digest_resp_info_create_works_with_valid_input_for_invalid()
{

	struct jaln_digest_resp_info *di = jaln_digest_resp_info_create(sid, JALN_DIGEST_STATUS_INVALID);
	assert_not_equals((void*)NULL, di);

	assert_not_equals((void*)NULL, di->serial_id);
	assert_not_equals(sid, di->serial_id);
	assert_string_equals(sid, di->serial_id);

	assert_equals(JALN_DIGEST_STATUS_INVALID, di->status);
	jaln_digest_resp_info_destroy(&di);
	assert_pointer_equals((void*) NULL, di);
}

void test_digest_resp_info_create_works_with_valid_input_for_unknown()
{

	struct jaln_digest_resp_info *di = jaln_digest_resp_info_create(sid, JALN_DIGEST_STATUS_UNKNOWN);
	assert_not_equals((void*)NULL, di);

	assert_not_equals((void*)NULL, di->serial_id);
	assert_not_equals(sid, di->serial_id);
	assert_string_equals(sid, di->serial_id);

	assert_equals(JALN_DIGEST_STATUS_UNKNOWN, di->status);
	jaln_digest_resp_info_destroy(&di);
	assert_pointer_equals((void*) NULL, di);
}

void test_digest_resp_info_create_fails_with_invalid_input()
{
	struct jaln_digest_resp_info *di;

	di = jaln_digest_resp_info_create(NULL, JALN_DIGEST_STATUS_CONFIRMED);
	assert_pointer_equals((void*)NULL, di);

}
void test_digest_resp_info_destroy_does_not_crash()
{
	struct jaln_digest_resp_info *di = NULL;

	jaln_digest_resp_info_destroy(&di);
	assert_pointer_equals((void*) NULL, di);
	jaln_digest_resp_info_destroy(NULL);
}

void test_axl_digest_resp_info_destroy_works()
{
	struct jaln_digest_resp_info *di;
	di = jaln_digest_resp_info_create(sid, JALN_DIGEST_STATUS_CONFIRMED);
	axlPointer p = (axlPointer) di;

	jaln_axl_destroy_digest_resp_info(p);
}

void test_axl_digest_resp_info_destroy_does_not_crash()
{
	axlPointer p = NULL;
	jaln_axl_destroy_digest_resp_info(p);
}

void test_axl_equals_digest_returns_zero_when_equal() {
	struct jaln_digest_resp_info *di_a = jaln_digest_resp_info_create(sid, JALN_DIGEST_STATUS_CONFIRMED);
	struct jaln_digest_resp_info *di_b = jaln_digest_resp_info_create(sid, JALN_DIGEST_STATUS_UNKNOWN);
	assert_equals(0, jaln_axl_equals_func_digest_resp_info_serial_id(di_a, di_b));
	jaln_digest_resp_info_destroy(&di_a);
	jaln_digest_resp_info_destroy(&di_b);
}

void test_axl_equals_digest_returns_non_zero_when_not_equal() {
	struct jaln_digest_resp_info *di_a = jaln_digest_resp_info_create(sid, JALN_DIGEST_STATUS_CONFIRMED);
	struct jaln_digest_resp_info *di_b = jaln_digest_resp_info_create(sid_2, JALN_DIGEST_STATUS_CONFIRMED);
	assert_not_equals(0, jaln_axl_equals_func_digest_resp_info_serial_id(di_a, di_b));
	jaln_digest_resp_info_destroy(&di_a);
	jaln_digest_resp_info_destroy(&di_b);
}

void test_axl_equals_digest_returns_non_zero_with_bad_input() {
	struct jaln_digest_resp_info *di_a = jaln_digest_resp_info_create(sid, JALN_DIGEST_STATUS_CONFIRMED);
	struct jaln_digest_resp_info *di_b = jaln_digest_resp_info_create(sid, JALN_DIGEST_STATUS_CONFIRMED);


	assert_not_equals(0, jaln_axl_equals_func_digest_resp_info_serial_id(NULL, di_a));
	assert_not_equals(0, jaln_axl_equals_func_digest_resp_info_serial_id(di_a, NULL));

	free(di_a->serial_id);
	di_a->serial_id = NULL;

	assert_not_equals(0, jaln_axl_equals_func_digest_resp_info_serial_id(di_a, di_b));
	assert_not_equals(0, jaln_axl_equals_func_digest_resp_info_serial_id(di_b, di_a));

	jaln_digest_resp_info_destroy(&di_a);
	jaln_digest_resp_info_destroy(&di_b);
}

