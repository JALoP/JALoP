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

#define PID 12345678
#define UID 654321
#define SOURCE "the.source"
#define TIMESTAMP "2012-12-06T14:22:60.1234Z"
#define USERNAME "someuser"
#define HOSTNAME "some.host"
#define SEC_LABEL "sec:label"
#define HOST_UUID_STR "abcdef12-0011-5566-7788-0123456789ab"
#define UUID_STR "1b4e28ba-2fa1-11d2-883f-b9a761bde3fb"

uuid_t host_uuid;
uuid_t uuid;

struct jaldb_segment sys_meta_on_disk_sgmt;
struct jaldb_segment sys_meta_in_ram_sgmt;
struct jaldb_segment app_meta_on_disk_sgmt;
struct jaldb_segment app_meta_in_ram_sgmt;
struct jaldb_segment payload_on_disk_sgmt;
struct jaldb_segment payload_in_ram_sgmt;
struct jaldb_segment empty_sgmt;

uint8_t *buffer;
struct jaldb_record rec;

#define INIT_SEGMENT(s, pref) \
	do {\
		memset(&s, 0, sizeof(s)); \
		s.fd = pref ## _FD; \
		s.length = pref ## _LENGTH; \
		s.payload = (uint8_t*) pref ## _PAYLOAD; \
		s.on_disk = s.fd > -1 ? 1 : 0; \
	} while(0)

void setup()
{
	buffer = NULL;
	int err;

	err = uuid_parse(HOST_UUID_STR, host_uuid);
	assert_equals(0, err);
	err = uuid_parse(UUID_STR, uuid);
	assert_equals(0, err);

	INIT_SEGMENT(sys_meta_on_disk_sgmt, SYS_META_ON_DISK);
	INIT_SEGMENT(sys_meta_in_ram_sgmt, SYS_META_IN_RAM);
	INIT_SEGMENT(app_meta_on_disk_sgmt, APP_META_ON_DISK);
	INIT_SEGMENT(app_meta_in_ram_sgmt, APP_META_IN_RAM);
	INIT_SEGMENT(payload_on_disk_sgmt, PAYLOAD_ON_DISK);
	INIT_SEGMENT(payload_in_ram_sgmt, PAYLOAD_IN_RAM);
	INIT_SEGMENT(empty_sgmt, EMPTY_SEGMENT);

	memset(&rec, 0, sizeof(rec));
	rec.pid = PID;
	rec.uid = UID;
	rec.source = SOURCE;
	rec.timestamp = TIMESTAMP;
	rec.username = USERNAME;
	rec.hostname = HOSTNAME;
	rec.sec_lbl = SEC_LABEL;
	rec.synced = 1;
	rec.have_uid = 1;
	uuid_copy(rec.host_uuid, host_uuid);
	uuid_copy(rec.uuid, uuid);

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
	assert_equals(BASE_SIZE, sz);
}

void test_serialize_inc_by_empty_segment()
{
	size_t sz = BASE_SIZE;
	enum jaldb_status ret;
	ret = jaldb_serialize_inc_by_segment_size(&sz, &empty_sgmt);
	assert_equals(JALDB_OK, ret);
	assert_equals(BASE_SIZE + EMPTY_SEGMENT_SSIZE, sz);
}

void test_serialize_add_segment_works_for_buffer_on_disk()
{
	init_buffer(SYS_META_ON_DISK_SSIZE);
	uint8_t *tbuf = buffer;
	jaldb_serialize_add_segment(&tbuf, &sys_meta_on_disk_sgmt);
	assert_equals(buffer + SYS_META_ON_DISK_SSIZE, tbuf);
	assert_equals(0, memcmp(buffer, SYS_META_ON_DISK_PAYLOAD, SYS_META_ON_DISK_SSIZE));
}

void test_serialize_add_segment_works_for_buffer_in_ram()
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
	assert_equals(buffer, tbuf);
}

void test_deserialize_string()
{
	char *str = TEST_STRING;
	uint8_t *buffer = (uint8_t*) str;
	size_t len = strlen(str) + 1;
	char *res = NULL;
	enum jaldb_status ret = jaldb_deserialize_string(&buffer, &len, &res);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, len);
	assert_not_equals(NULL, res);
	assert_not_equals((char*) buffer, res);
	assert_equals(str + strlen(str) + 1, (char*) buffer);
	assert_string_equals(TEST_STRING, res);
	free(res);
}

void test_deserialize_string_fails_when_missing_null_terminator()
{
	char *str = TEST_STRING;
	uint8_t *buffer = (uint8_t*) str;
	size_t len = strlen(str);
	char *res = NULL;
	enum jaldb_status ret = jaldb_deserialize_string(&buffer, &len, &res);
	assert_not_equals(JALDB_OK, ret);
	assert_equals(strlen(str), len);
	assert_pointer_equals((void*)NULL, res);
	assert_equals((uint8_t*) str, buffer);
}

void test_deserialize_string_fails_on_bad_args()
{
	char *str = TEST_STRING;
	uint8_t *buffer = (uint8_t*) str;
	size_t len = strlen(str);
	char *res = NULL;
	enum jaldb_status ret;
	ret = jaldb_deserialize_string(NULL, &len, &res);
	assert_not_equals(JALDB_OK, ret);
	ret = jaldb_deserialize_string(&buffer, NULL, &res);
	assert_not_equals(JALDB_OK, ret);
	ret = jaldb_deserialize_string(&buffer, &len, NULL);
	assert_not_equals(JALDB_OK, ret);
	res = (char*) 0xbadf00d;
	ret = jaldb_deserialize_string(&buffer, &len, &res);
	assert_not_equals(JALDB_OK, ret);
	res = NULL;
}

void test_deserialize_segment_on_disk_works()
{
	enum jaldb_status ret;
	struct jaldb_segment *seg = NULL;
	uint64_t segment_len = 1024;
	char *str = TEST_STRING;
	uint8_t *buffer = (uint8_t*) str;
	size_t blen = strlen(str) + 1;

	ret = jaldb_deserialize_segment(1,
		segment_len,
		&buffer, &blen,
		&seg);
	assert_equals(JALDB_OK, ret);
	assert_equals((uint8_t* )str, buffer - strlen(TEST_STRING) -1);
	assert_equals(0, blen);

	assert_not_equals((void*) NULL, seg);
	assert_equals(1, seg->on_disk);
	assert_equals(segment_len, seg->length);
	assert_not_equals((void*) NULL, seg->payload);
	assert_string_equals(TEST_STRING, (char*)seg->payload);
	assert_equals(-1, seg->fd);
	jaldb_destroy_segment(&seg);
}

void test_deserialize_segment_not_on_disk_works()
{
	enum jaldb_status ret;
	struct jaldb_segment *seg = NULL;
	uint64_t segment_len = strlen(TEST_STRING);
	char *str = TEST_STRING;
	uint8_t *buffer = (uint8_t*) str;
	size_t blen = strlen(str) + 1;

	ret = jaldb_deserialize_segment(0,
		segment_len,
		&buffer, &blen,
		&seg);
	assert_equals(JALDB_OK, ret);
	assert_equals((uint8_t* )str, buffer - strlen(TEST_STRING));
	assert_equals(1, blen);

	assert_not_equals((void*) NULL, seg);
	assert_equals(0, seg->on_disk);
	assert_equals(segment_len, seg->length);
	assert_not_equals((void*) NULL, seg->payload);
	assert_equals(0, memcmp(TEST_STRING, seg->payload, seg->length));
	assert_equals(-1, seg->fd);
	jaldb_destroy_segment(&seg);
}

void test_deserialize_segment_not_on_disk_fails_if_payload_too_big()
{
	enum jaldb_status ret;
	struct jaldb_segment *seg = NULL;
	uint64_t segment_len = strlen(TEST_STRING);
	char *str = TEST_STRING;
	uint8_t *buffer = (uint8_t*) str;
	size_t blen = strlen(str) - 1;

	ret = jaldb_deserialize_segment(0,
		segment_len,
		&buffer, &blen,
		&seg);
	assert_not_equals(JALDB_OK, ret);
	assert_pointer_equals((void*)str, (void*)buffer);
	assert_equals(strlen(str) - 1, blen);
	assert_pointer_equals((void*) NULL, seg);
	jaldb_destroy_segment(&seg);
}

void test_deserialize_segment_not_on_disk_fails_on_bad_input()
{
	enum jaldb_status ret;
	struct jaldb_segment *seg = NULL;
	uint64_t segment_len = strlen(TEST_STRING);
	char *str = TEST_STRING;
	uint8_t *buffer = (uint8_t*) str;
	size_t blen = strlen(str) - 1;

	ret = jaldb_deserialize_segment(0, segment_len, NULL, &blen, &seg);
	assert_not_equals(JALDB_OK, ret);
	ret = jaldb_deserialize_segment(0, segment_len, &buffer, NULL, &seg);
	assert_not_equals(JALDB_OK, ret);
	ret = jaldb_deserialize_segment(0, segment_len, &buffer, &blen, NULL);
	assert_not_equals(JALDB_OK, ret);

	seg = (struct jaldb_segment*) 0xdeadbeef;
	ret = jaldb_deserialize_segment(0, segment_len, &buffer, &blen, &seg);
	assert_not_equals(JALDB_OK, ret);
	seg = NULL;
}

void test_serialize_record_returns_error()
{
	size_t res_size = 0;
	enum jaldb_status ret;
	uint8_t *srec = NULL;
	ret = jaldb_serialize_record(0, NULL, &srec, &res_size);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_serialize_record(0, &rec, NULL, &res_size);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_serialize_record(0, &rec, &srec, NULL);
	assert_equals(JALDB_E_INVAL, ret);

	srec = (uint8_t*)0xdeadbeef;
	ret = jaldb_serialize_record(0, &rec, &srec, &res_size);
	assert_equals(JALDB_E_INVAL, ret);
	srec = NULL;
}

void test_serialize_deserialize_record_works()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_pointer_equals((void*) NULL, dsr->sys_meta);
	assert_pointer_equals((void*) NULL, dsr->app_meta);
	assert_pointer_equals((void*) NULL, dsr->payload);
	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);
}

void test_serialize_deserialize_record_works_with_sys_meta_on_disk()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.sys_meta = &sys_meta_on_disk_sgmt;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_not_equals((void*) NULL, dsr->sys_meta);
	// the full check for deserializing the segments happens elsewhere,
	// just make sure the correct data is there.
	assert_string_equals(SYS_META_ON_DISK_PAYLOAD, (char*)dsr->sys_meta->payload);

	assert_pointer_equals((void*) NULL, dsr->app_meta);
	assert_pointer_equals((void*) NULL, dsr->payload);
	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);
}

void test_serialize_deserialize_record_works_with_sys_meta_in_ram()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.sys_meta = &sys_meta_in_ram_sgmt;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_not_equals((void*) NULL, dsr->sys_meta);
	// the full check for deserializing the segments happens elsewhere,
	// just make sure the correct data is there.
	assert_equals(SYS_META_IN_RAM_LENGTH, dsr->sys_meta->length);
	assert_equals(0, memcmp(SYS_META_IN_RAM_PAYLOAD, (char*)dsr->sys_meta->payload, SYS_META_IN_RAM_LENGTH));

	assert_pointer_equals((void*) NULL, dsr->app_meta);
	assert_pointer_equals((void*) NULL, dsr->payload);
	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);
}

void test_serialize_deserialize_record_works_with_app_meta_on_disk()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.app_meta = &app_meta_on_disk_sgmt;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_pointer_equals((void*) NULL, dsr->sys_meta);
	assert_not_equals((void*) NULL, dsr->app_meta);
	// the full check for deserializing the segments happens elsewhere,
	// just make sure the correct data is there.
	assert_string_equals(APP_META_ON_DISK_PAYLOAD, (char*)dsr->app_meta->payload);

	assert_pointer_equals((void*) NULL, dsr->payload);
	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);
}

void test_serialize_deserialize_record_works_with_app_meta_in_ram()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.app_meta = &app_meta_in_ram_sgmt;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_pointer_equals((void*) NULL, dsr->sys_meta);
	assert_not_equals((void*) NULL, dsr->app_meta);
	// the full check for deserializing the segments happens elsewhere,
	// just make sure the correct data is there.
	assert_equals(APP_META_IN_RAM_LENGTH, dsr->app_meta->length);
	assert_equals(0, memcmp(APP_META_IN_RAM_PAYLOAD, (char*)dsr->app_meta->payload, APP_META_IN_RAM_LENGTH));

	assert_pointer_equals((void*) NULL, dsr->payload);
	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);

}

void test_serialize_deserialize_record_works_with_payload_on_disk()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.payload = &payload_on_disk_sgmt;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_pointer_equals((void*) NULL, dsr->sys_meta);
	assert_pointer_equals((void*) NULL, dsr->app_meta);
	assert_not_equals((void*) NULL, dsr->payload);
	// the full check for deserializing the segments happens elsewhere,
	// just make sure the correct data is there.
	assert_string_equals(PAYLOAD_ON_DISK_PAYLOAD, (char*)dsr->payload->payload);

	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);
}

void test_serialize_deserialize_record_works_with_payload_in_ram()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.payload = &payload_in_ram_sgmt;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_pointer_equals((void*) NULL, dsr->sys_meta);
	assert_pointer_equals((void*) NULL, dsr->app_meta);
	assert_not_equals((void*) NULL, dsr->payload);
	// the full check for deserializing the segments happens elsewhere,
	// just make sure the correct data is there.
	assert_equals(PAYLOAD_IN_RAM_LENGTH, dsr->payload->length);
	assert_equals(0, memcmp(PAYLOAD_IN_RAM_PAYLOAD, (char*)dsr->payload->payload, PAYLOAD_IN_RAM_LENGTH));

	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);

}

void test_serialize_deserialize_record_works_with_all_segments()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.sys_meta = &sys_meta_on_disk_sgmt;
	rec.app_meta = &app_meta_on_disk_sgmt;
	rec.payload = &payload_in_ram_sgmt;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_not_equals((void*) NULL, dsr->sys_meta);
	assert_string_equals(SYS_META_ON_DISK_PAYLOAD, (char*)dsr->sys_meta->payload);
	assert_not_equals((void*) NULL, dsr->app_meta);
	assert_string_equals(APP_META_ON_DISK_PAYLOAD, (char*)dsr->app_meta->payload);
	assert_not_equals((void*) NULL, dsr->payload);
	// the full check for deserializing the segments happens elsewhere,
	// just make sure the correct data is there.
	assert_equals(PAYLOAD_IN_RAM_LENGTH, dsr->payload->length);
	assert_equals(0, memcmp(PAYLOAD_IN_RAM_PAYLOAD, (char*)dsr->payload->payload, PAYLOAD_IN_RAM_LENGTH));

	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);

}

void test_serialize_deserialize_record_works_missing_payload()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.sys_meta = &sys_meta_on_disk_sgmt;
	rec.app_meta = &app_meta_on_disk_sgmt;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_not_equals((void*) NULL, dsr->sys_meta);
	assert_string_equals(SYS_META_ON_DISK_PAYLOAD, (char*)dsr->sys_meta->payload);
	assert_not_equals((void*) NULL, dsr->app_meta);
	assert_string_equals(APP_META_ON_DISK_PAYLOAD, (char*)dsr->app_meta->payload);
	assert_equals((void*) NULL, dsr->payload);

	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);

}

void test_serialize_deserialize_record_works_missing_app_meta()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.sys_meta = &sys_meta_on_disk_sgmt;
	rec.payload = &payload_in_ram_sgmt;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_not_equals((void*) NULL, dsr->sys_meta);
	assert_string_equals(SYS_META_ON_DISK_PAYLOAD, (char*)dsr->sys_meta->payload);
	assert_pointer_equals((void*) NULL, dsr->app_meta);
	assert_not_equals((void*) NULL, dsr->payload);
	assert_equals(PAYLOAD_IN_RAM_LENGTH, dsr->payload->length);
	assert_equals(0, memcmp(PAYLOAD_IN_RAM_PAYLOAD, (char*)dsr->payload->payload, PAYLOAD_IN_RAM_LENGTH));

	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);

}

void test_serialize_deserialize_record_works_missing_sys_meta()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.app_meta = &app_meta_on_disk_sgmt;
	rec.payload = &payload_in_ram_sgmt;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(1, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_pointer_equals((void*) NULL, dsr->sys_meta);
	assert_not_equals((void*) NULL, dsr->app_meta);
	assert_string_equals(APP_META_ON_DISK_PAYLOAD, (char*)dsr->app_meta->payload);
	assert_not_equals((void*) NULL, dsr->payload);
	assert_equals(PAYLOAD_IN_RAM_LENGTH, dsr->payload->length);
	assert_equals(0, memcmp(PAYLOAD_IN_RAM_PAYLOAD, (char*)dsr->payload->payload, PAYLOAD_IN_RAM_LENGTH));

	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);
}

void test_serialize_deserialize_record_works_with_no_uid()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.have_uid = 0;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(0, dsr->have_uid);
	assert_equals(1, dsr->synced);
	assert_pointer_equals((void*) NULL, dsr->sys_meta);
	assert_pointer_equals((void*) NULL, dsr->app_meta);
	assert_pointer_equals((void*) NULL, dsr->payload);

	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);
}

void test_serialize_deserialize_record_works_when_not_synced()
{
	uint8_t *res_buf = NULL;
	size_t res_size = 0;
	struct jaldb_record *dsr = NULL;
	rec.synced = 0;

	enum jaldb_status ret;
	ret = jaldb_serialize_record(0, &rec, &res_buf, &res_size);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_deserialize_record(0, res_buf, res_size, &dsr);
	assert_equals(JALDB_OK, ret);

	assert_equals(rec.pid, dsr->pid);
	assert_equals(0, dsr->synced);
	assert_equals(1, dsr->have_uid);
	assert_equals(rec.uid, dsr->uid);
	assert_pointer_equals((void*) NULL, dsr->sys_meta);
	assert_pointer_equals((void*) NULL, dsr->app_meta);
	assert_pointer_equals((void*) NULL, dsr->payload);

	assert_string_equals(rec.source, dsr->source);
	assert_string_equals(rec.hostname, dsr->hostname);
	assert_string_equals(rec.timestamp, dsr->timestamp);
	assert_string_equals(rec.username, dsr->username);
	assert_string_equals(rec.sec_lbl, dsr->sec_lbl);
	assert_equals(1, dsr->version);
	assert_equals(JALDB_RTYPE_UNKNOWN, dsr->type);
}
