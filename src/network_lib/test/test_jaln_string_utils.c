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

#include <axl.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <test-dept.h>

#include "jal_asprintf_internal.h"

#include "jaln_string_utils.h"

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
	uint64_t out = 0;
	assert_true(jaln_ascii_to_uint64(VALID_NUMERIC_STRING, &out));
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

void test_jaln_ascii_to_size_t_succeeds()
{
	axl_bool ret = axl_false;
	size_t out = 0;
	ret = jaln_ascii_to_size_t(VALID_NUMERIC_STRING, &out);
	assert_equals(axl_true, ret);
	assert_equals(65, out);
}

void test_jaln_ascii_to_size_t_fails_with_invalid_input()
{
	axl_bool ret = axl_false;
	size_t out = 0;
	ret = jaln_ascii_to_size_t(NOT_VALID_NUMERIC_STRING, &out);
	assert_equals(axl_false, ret);
}

void test_jaln_ascii_to_uint64_fails_with_null_inputs()
{
	uint64_t out = 0;
	assert_false(jaln_ascii_to_uint64(NULL, &out));
	assert_false(jaln_ascii_to_uint64(VALID_NUMERIC_STRING, NULL));
}

void test_jaln_hex_to_bin_fails_for_bad_input()
{
	uint8_t out;
	assert_equals(JAL_E_INVAL, jaln_hex_to_bin('\0', &out));
	assert_equals(JAL_E_INVAL, jaln_hex_to_bin('0' - 1, &out));
	assert_equals(JAL_E_INVAL, jaln_hex_to_bin('9' + 1, &out));
	assert_equals(JAL_E_INVAL, jaln_hex_to_bin('a' - 1, &out));
	assert_equals(JAL_E_INVAL, jaln_hex_to_bin('A' - 1, &out));
	assert_equals(JAL_E_INVAL, jaln_hex_to_bin('f' + 1, &out));
	assert_equals(JAL_E_INVAL, jaln_hex_to_bin('F' + 1, &out));
}

void test_jaln_hex_to_bin_works_for_valid_input()
{
	uint8_t out;
	assert_equals(JAL_OK, jaln_hex_to_bin('0', &out));
	assert_equals(0, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('1', &out));
	assert_equals(1, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('2', &out));
	assert_equals(2, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('3', &out));
	assert_equals(3, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('4', &out));
	assert_equals(4, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('5', &out));
	assert_equals(5, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('6', &out));
	assert_equals(6, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('7', &out));
	assert_equals(7, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('8', &out));
	assert_equals(8, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('9', &out));
	assert_equals(9, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('a', &out));
	assert_equals(10, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('A', &out));
	assert_equals(10, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('b', &out));
	assert_equals(11, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('B', &out));
	assert_equals(11, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('c', &out));
	assert_equals(12, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('C', &out));
	assert_equals(12, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('d', &out));
	assert_equals(13, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('D', &out));
	assert_equals(13, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('e', &out));
	assert_equals(14, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('E', &out));
	assert_equals(14, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('f', &out));
	assert_equals(15, out);

	assert_equals(JAL_OK, jaln_hex_to_bin('F', &out));
	assert_equals(15, out);
}

void test_hex_str_to_buf_works_for_00()
{
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_OK, jaln_hex_str_to_bin_buf("00", strlen("00"), &buf, &buf_len));
	assert_equals(buf_len, 1);
	assert_equals(0x00, buf[0]);
	free(buf);
}

void test_hex_str_to_buf_works_for_10()
{
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_OK, jaln_hex_str_to_bin_buf("10", strlen("10"), &buf, &buf_len));
	assert_equals(buf_len, 1);
	assert_equals(0x10, buf[0]);
	free(buf);
}

void test_hex_str_to_buf_works_for_ff()
{
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_OK, jaln_hex_str_to_bin_buf("ff", strlen("ff"), &buf, &buf_len));
	assert_equals(buf_len, 1);
	assert_equals(0xff, buf[0]);
	free(buf);
}

void test_hex_str_to_buf_works_for_f0()
{
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_OK, jaln_hex_str_to_bin_buf("f0", strlen("f0"), &buf, &buf_len));
	assert_equals(buf_len, 1);
	assert_equals(0xf0, buf[0]);
	free(buf);
}

void test_hex_str_to_buf_works_for_f()
{
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_OK, jaln_hex_str_to_bin_buf("f", strlen("f"), &buf, &buf_len));
	assert_equals(buf_len, 1);
	assert_equals(0xf, buf[0]);
	free(buf);
}
void test_hex_str_to_buf_works_for_5()
{
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_OK, jaln_hex_str_to_bin_buf("5", strlen("5"), &buf, &buf_len));
	assert_equals(buf_len, 1);
	assert_equals(0x5, buf[0]);
	free(buf);
}
void test_hex_str_to_buf_works_for_0()
{
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_OK, jaln_hex_str_to_bin_buf("0", strlen("0"), &buf, &buf_len));
	assert_equals(buf_len, 1);
	assert_equals(0x0, buf[0]);
	free(buf);
}
void test_hex_str_to_buf_works_for_long_even_cnt()
{
	const char *str = "abcd123411aaff22";
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_OK, jaln_hex_str_to_bin_buf(str, strlen(str), &buf, &buf_len));
	assert_equals(buf_len, 8);
	assert_equals(0xab, buf[0]);
	assert_equals(0xcd, buf[1]);
	assert_equals(0x12, buf[2]);
	assert_equals(0x34, buf[3]);
	assert_equals(0x11, buf[4]);
	assert_equals(0xaa, buf[5]);
	assert_equals(0xff, buf[6]);
	assert_equals(0x22, buf[7]);
	free(buf);
}

void test_hex_str_to_buf_works_for_long_even_cnt_fails_with_bad_string()
{
	const char *str = "bcd12341z1aaff22";
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_E_INVAL, jaln_hex_str_to_bin_buf(str, strlen(str), &buf, &buf_len));
}

void test_hex_str_to_buf_works_for_long_odd_cnt()
{
	const char *str = "abcd123411aaff223";
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_OK, jaln_hex_str_to_bin_buf(str, strlen(str), &buf, &buf_len));
	assert_equals(buf_len, 9);
	assert_equals(0x0a, buf[0]);
	assert_equals(0xbc, buf[1]);
	assert_equals(0xd1, buf[2]);
	assert_equals(0x23, buf[3]);
	assert_equals(0x41, buf[4]);
	assert_equals(0x1a, buf[5]);
	assert_equals(0xaf, buf[6]);
	assert_equals(0xf2, buf[7]);
	assert_equals(0x23, buf[8]);
	free(buf);
}

void test_hex_str_to_buf_works_for_long_odd_cnt_fails_with_bad_string()
{
	const char *str = "abcd12341z1aaff22";
	uint8_t *buf = NULL;
	size_t buf_len;
	assert_equals(JAL_E_INVAL, jaln_hex_str_to_bin_buf(str, strlen(str), &buf, &buf_len));
}

void test_hex_fails_with_null_inputs()
{
	const char *str = "abcd123411aaff223";
	uint8_t *buf = NULL;
	size_t buf_len;
	//assert_equals(JAL_E_INVAL, jaln_hex_str_to_bin_buf(str, strlen(str), &buf, &buf_len));
	assert_equals(JAL_E_INVAL, jaln_hex_str_to_bin_buf(NULL, strlen(str), &buf, &buf_len));
	assert_equals(JAL_E_INVAL, jaln_hex_str_to_bin_buf(str, 0, &buf, &buf_len));
	assert_equals(JAL_E_INVAL, jaln_hex_str_to_bin_buf(str, strlen(str), NULL, &buf_len));
	assert_equals(JAL_E_INVAL, jaln_hex_str_to_bin_buf(str, strlen(str), &buf, NULL));
	buf = (uint8_t*) 0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_hex_str_to_bin_buf(str, strlen(str), &buf, &buf_len));
}
