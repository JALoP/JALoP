/**
 * @file This file contains tests for jaln_string_utils.c functions.
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

#include "jaln_string_utils.h"
#include "jal_asprintf_internal.h"
#include <axl.h>
#include <test-dept.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#define VALID_NUMERIC_STRING "65"
#define NOT_VALID_NUMERIC_STRING "A"

static char *longer_than_max = NULL;
void setup()
{
	jal_asprintf(&longer_than_max, "%llu0", ULLONG_MAX);
}
void teardown()
{
	free(longer_than_max);
	longer_than_max = NULL;
}

void test_jaln_ascii_to_uint64_succeeds()
{
	axl_bool ret = axl_false;
	uint64_t out = 0;
	ret = jaln_ascii_to_uint64(VALID_NUMERIC_STRING, &out);
	assert_true(ret);
	assert_not_equals(axl_true, out);
	assert_equals(65, out);
}

void test_jaln_ascii_to_uint64_fails_when_not_ascii()
{
	axl_bool ret = axl_false;
	uint64_t out = 0;
	ret = jaln_ascii_to_uint64(NOT_VALID_NUMERIC_STRING, &out);
	assert_false(ret);
}

void test_jaln_ascii_to_uint64_fails_when_string_causing_overflow()
{
	axl_bool ret = axl_false;
	uint64_t out = 0;
	ret = jaln_ascii_to_uint64(longer_than_max, &out);
	assert_false(ret);
}

void test_jal_ascii_to_size_t_succeeds()
{
	axl_bool ret = axl_false;
	size_t out = 0;
	ret = jal_ascii_to_size_t(VALID_NUMERIC_STRING, &out);
	assert_equals(axl_true, ret);
	assert_equals(65, out);
}

void test_jal_ascii_to_size_t_fails_with_invalid_input()
{
	axl_bool ret = axl_false;
	size_t out = 0;
	ret = jal_ascii_to_size_t(NOT_VALID_NUMERIC_STRING, &out);
	assert_equals(axl_false, ret);
}
