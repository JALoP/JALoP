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
#include <stdint.h>
#include <stdlib.h>

#include "jaldb_segment.h"
#include "jaldb_serialize_record.h"
#include "jaldb_record.h"

#define BUF_SIZE 4096
#define TEST_STRING "this is a test"
#define BASE_SIZE 145

#define SYS_META_ON_DISK_FD 100
#define SYS_META_ON_DISK_PAYLOAD "path/to/sys/disk"
#define SYS_META_ON_DISK_LENGTH  1234
#define SYS_META_ON_DISK_SSIZE (strlen(SYS_META_ON_DISK_PAYLOAD) + 1)

#define SYS_META_IN_RAM_FD -1
#define SYS_META_IN_RAM_PAYLOAD "sys_meta_in_ram"
#define SYS_META_IN_RAM_LENGTH (strlen(SYS_META_IN_RAM_PAYLOAD))
#define SYS_META_IN_RAM_SSIZE SYS_META_IN_RAM_LENGTH

#define APP_META_ON_DISK_FD 300
#define APP_META_ON_DISK_PAYLOAD "path/to/app/disk"
#define APP_META_ON_DISK_LENGTH 5678
#define APP_META_ON_DISK_SSIZE (strlen(APP_META_ON_DISK_PAYLOAD) + 1)

#define APP_META_IN_RAM_FD -1
#define APP_META_IN_RAM_PAYLOAD "app_meta_in_ram"
#define APP_META_IN_RAM_LENGTH (strlen(APP_META_IN_RAM_PAYLOAD))
#define APP_META_IN_RAM_SSIZE APP_META_IN_RAM_LENGTH

#define PAYLOAD_ON_DISK_FD 500
#define PAYLOAD_ON_DISK_PAYLOAD "path/to/payload/disk"
#define PAYLOAD_ON_DISK_LENGTH 9101112
#define PAYLOAD_ON_DISK_SSIZE (strlen(PAYLOAD_ON_DISK_PAYLOAD) + 1)

#define PAYLOAD_IN_RAM_FD -1
#define PAYLOAD_IN_RAM_PAYLOAD "paylaod_in_ram"
#define PAYLOAD_IN_RAM_LENGTH (strlen(PAYLOAD_IN_RAM_PAYLOAD))
#define PAYLOAD_IN_RAM_SSIZE PAYLOD_IN_RAM_LENGTH

#define EMPTY_SEGMENT_FD -1
#define EMPTY_SEGMENT_PAYLOAD (NULL)
#define EMPTY_SEGMENT_LENGTH 0
#define EMPTY_SEGMENT_SSIZE 0


struct jaldb_segment sys_meta_on_disk_sgmt;
struct jaldb_segment sys_meta_in_ram_sgmt;
struct jaldb_segment app_meta_on_disk_sgmt;
struct jaldb_segment app_meta_in_ram_sgmt;
struct jaldb_segment payload_on_disk_sgmt;
struct jaldb_segment payload_in_ram_sgmt;
struct jaldb_segment empty_sgmt;


#define INIT_SEGMENT(s, pref) \
	do {\
		memset(&s, 0, sizeof(s)); \
		s.fd = pref ## _FD; \
		s.length = pref ## _LENGTH; \
		s.payload = (uint8_t*) pref ## _PAYLOAD; \
	} while(0)

uint8_t *buffer;
void setup()
{
	buffer = NULL;
	INIT_SEGMENT(sys_meta_on_disk_sgmt, SYS_META_ON_DISK);
	INIT_SEGMENT(sys_meta_in_ram_sgmt, SYS_META_IN_RAM);
	INIT_SEGMENT(app_meta_on_disk_sgmt, APP_META_ON_DISK);
	INIT_SEGMENT(app_meta_in_ram_sgmt, APP_META_IN_RAM);
	INIT_SEGMENT(payload_on_disk_sgmt, PAYLOAD_ON_DISK);
	INIT_SEGMENT(payload_in_ram_sgmt, PAYLOAD_IN_RAM);
	INIT_SEGMENT(empty_sgmt, EMPTY_SEGMENT);
};

void teardown()
{
	free(buffer);
}
#define init_buffer(s) do { \
	buffer = (uint8_t*)malloc(s); \
	assert_not_equals((void*)NULL, buffer); \
} while(0)

void test_serialize_add_string_works_with_null_string()
{
	init_buffer(1);
	uint8_t *tbuf = buffer;
	jaldb_serialize_add_string(&tbuf, NULL);
	assert_equals(buffer + 1, tbuf);
	assert_equals('\0', buffer[0]);
}
void test_serialize_add_string_works_with_emtpy_string()
{
	init_buffer(1);
	uint8_t *tbuf = buffer;
	jaldb_serialize_add_string(&tbuf, "");
	assert_equals(buffer + 1, tbuf);
	assert_equals('\0', buffer[0]);
}
void test_serialize_add_string_works_with_non_empty_string()
{
	init_buffer(strlen(TEST_STRING) + 1);
	uint8_t *tbuf = buffer;
	jaldb_serialize_add_string(&tbuf, TEST_STRING);
	assert_equals(buffer + strlen(TEST_STRING) + 1, tbuf);
	assert_equals('\0', buffer[strlen(TEST_STRING)]);
	assert_string_equals(TEST_STRING, (char*)buffer);
}

void test_serialize_inc_by_string_works_with_non_null_string()
{
	size_t sz = BASE_SIZE;
	enum jaldb_status ret;
	ret = jaldb_serialize_inc_by_string(&sz, TEST_STRING);
	assert_equals(JALDB_OK, ret);
	assert_equals(BASE_SIZE + strlen(TEST_STRING) + 1, sz);
}

void test_serialize_inc_by_string_works_with_null_string()
{
	size_t sz = BASE_SIZE;
	enum jaldb_status ret;
	ret = jaldb_serialize_inc_by_string(&sz, NULL);
	assert_equals(JALDB_OK, ret);
	assert_equals(BASE_SIZE + 1, sz);
}

void test_serialize_inc_by_string_works_with_empty_string()
{
	size_t sz = BASE_SIZE;
	enum jaldb_status ret;
	ret = jaldb_serialize_inc_by_string(&sz, "");
	assert_equals(JALDB_OK, ret);
	assert_equals(BASE_SIZE + 1, sz);
}

void test_serialize_inc_by_string_fails_on_overflow()
{
	// there is not enough space for the null terminator
	size_t sz = SIZE_MAX - strlen(TEST_STRING);
	enum jaldb_status ret;
	ret = jaldb_serialize_inc_by_string(&sz, TEST_STRING);
	assert_not_equals(JALDB_OK, ret);
	assert_equals(SIZE_MAX - strlen(TEST_STRING), sz);

	sz = SIZE_MAX;
	ret = jaldb_serialize_inc_by_string(&sz, "");
	assert_not_equals(JALDB_OK, ret);
	assert_equals(SIZE_MAX, sz);

	sz = SIZE_MAX;
	ret = jaldb_serialize_inc_by_string(&sz, NULL);
	assert_not_equals(JALDB_OK, ret);
	assert_equals(SIZE_MAX, sz);
}

void test_serialize_inc_by_segment_on_disk()
{
	size_t sz = BASE_SIZE;
	enum jaldb_status ret;
	ret = jaldb_serialize_inc_by_segment_size(&sz, &sys_meta_on_disk_sgmt);
	assert_equals(JALDB_OK, ret);
	assert_equals((SYS_META_ON_DISK_SSIZE + BASE_SIZE), sz);
}

void test_serialize_inc_by_segment_in_ram()
{
	size_t sz = BASE_SIZE;
	enum jaldb_status ret;
	ret = jaldb_serialize_inc_by_segment_size(&sz, &sys_meta_in_ram_sgmt);
	assert_equals(JALDB_OK, ret);
	assert_equals((SYS_META_IN_RAM_SSIZE + BASE_SIZE), sz);
}

void test_serialize_inc_by_null_segment()
{
	size_t sz = BASE_SIZE;
	enum jaldb_status ret;
	ret = jaldb_serialize_inc_by_segment_size(&sz, NULL);
	assert_equals(JALDB_OK, ret);
	assert_equals(BASE_SIZE + 1, sz);
}

void test_serialize_inc_by_empty_segment()
{
	size_t sz = BASE_SIZE;
	enum jaldb_status ret;
	ret = jaldb_serialize_inc_by_segment_size(&sz, &empty_sgmt);
	assert_equals(JALDB_OK, ret);
	assert_equals(BASE_SIZE + EMPTY_SEGMENT_SSIZE, sz);
}

void test_serialize_add_segment_on_works_for_buffer_on_disk()
{
	init_buffer(SYS_META_ON_DISK_SSIZE);
	uint8_t *tbuf = buffer;
	jaldb_serialize_add_segment(&tbuf, &sys_meta_on_disk_sgmt);
	assert_equals(buffer + SYS_META_ON_DISK_SSIZE, tbuf);
	assert_equals(0, memcmp(buffer, SYS_META_ON_DISK_PAYLOAD, SYS_META_ON_DISK_SSIZE));
}

void test_serialize_add_segment_on_works_for_buffer_in_ram()
{
	init_buffer(SYS_META_IN_RAM_SSIZE);
	uint8_t *tbuf = buffer;
	jaldb_serialize_add_segment(&tbuf, &sys_meta_in_ram_sgmt);
	assert_equals(buffer + SYS_META_IN_RAM_SSIZE, tbuf);
	assert_equals(0, memcmp(buffer, SYS_META_IN_RAM_PAYLOAD, SYS_META_IN_RAM_SSIZE));
}

void test_serialize_add_segment_on_works_for_empty_segment()
{
	init_buffer(EMPTY_SEGMENT_SSIZE);
	uint8_t *tbuf = buffer;
	jaldb_serialize_add_segment(&tbuf, &empty_sgmt);
	assert_equals(buffer + EMPTY_SEGMENT_SSIZE, tbuf);
}

void test_serialize_add_segment_on_works_for_null()
{
	init_buffer(1);
	uint8_t *tbuf = buffer;
	jaldb_serialize_add_segment(&tbuf, NULL);
	assert_equals(buffer + 1, tbuf);
	assert_equals('\0', buffer[0]);
}
