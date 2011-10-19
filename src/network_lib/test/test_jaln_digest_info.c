/**
 * @file This file contains tests for jaln_digest_info.c functions.
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
#include "jaln_digest_info.h"

#define DGST_LEN 10
static  char *sid = "some_sid";
static uint8_t digest[DGST_LEN] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

void setup()
{
}
void teardown()
{
}

void test_digest_info_create_works_with_valid_input()
{

	struct jaln_digest_info *di = jaln_digest_info_create(sid, digest, DGST_LEN);
	assert_not_equals((void*)NULL, di);

	assert_not_equals((void*)NULL, di->serial_id);
	assert_not_equals(sid, di->serial_id);

	assert_not_equals((void*)NULL, di->digest);
	assert_not_equals(digest, di->digest);

	assert_equals(DGST_LEN, di->digest_len);

	assert_string_equals(sid, di->serial_id);
	assert_equals(0, memcmp(digest, di->digest, DGST_LEN));
	jaln_digest_info_destroy(&di);
	assert_pointer_equals((void*) NULL, di);
}
void test_digest_info_create_fails_with_invalid_input()
{
	struct jaln_digest_info *di;

	di = jaln_digest_info_create(NULL, digest, DGST_LEN);
	assert_pointer_equals((void*)NULL, di);

	di = jaln_digest_info_create(sid, NULL, DGST_LEN);
	assert_pointer_equals((void*)NULL, di);

	di = jaln_digest_info_create(sid, digest, 0);
	assert_pointer_equals((void*)NULL, di);
}
void test_digest_info_destroy_does_not_crash()
{
	struct jaln_digest_info *di = NULL;

	jaln_digest_info_destroy(&di);
	assert_pointer_equals((void*) NULL, di);
	jaln_digest_info_destroy(NULL);
}
