/**
 * @file test_jaldb_record_extract.c This file contains functions to test jaldb_record_extract.c.
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


#include <db.h>
#include <stdlib.h>
#include <test-dept.h>
#include <uuid/uuid.h>

#include "jaldb_record_extract.h"
#include "jaldb_serialize_record.h"


#define PADDING 1024
#define BUFFER_SIZE (sizeof(*headers) + PADDING)

static DBT record_dbt;
static struct jaldb_serialize_record_headers *headers;
static uuid_t a_uuid;
static uint8_t buffer[BUFFER_SIZE];

void setup()
{
	assert_equals(0, uuid_parse("01234567-89AB-CDEF-0123-456789ABCDEF", a_uuid));

	memset(&record_dbt, 0, sizeof(record_dbt));
	headers = (struct jaldb_serialize_record_headers *)buffer;
	headers->version = JALDB_DB_LAYOUT_VERSION;
	headers->flags = JALDB_RFLAGS_SENT;
	uuid_copy(headers->record_uuid, a_uuid);
	record_dbt.data = buffer;
	record_dbt.size = BUFFER_SIZE;
}

void teardown()
{
}

void test_extract_uuid_returns_error_for_bad_version()
{
	DBT result;
	memset(&result, 0, sizeof(result));
	headers->version = 1234;

	int ret = jaldb_extract_record_uuid(NULL, NULL, &record_dbt, &result);
	assert_not_equals(0, ret);
	assert_not_equals(DB_DONOTINDEX, ret);
}

void test_extract_uuid_works()
{
	uuid_t uuid_res;
	DBT result;
	memset(&result, 0, sizeof(result));

	int ret = jaldb_extract_record_uuid(NULL, NULL, &record_dbt, &result);
	assert_equals(0, ret);
	assert_equals(16, result.size);
	uuid_copy(uuid_res, result.data);
	assert_equals(0, uuid_compare(a_uuid, uuid_res));
	free(result.data);
}

void test_extract_uuid_returns_error_for_input()
{
	DBT result;
	memset(&result, 0, sizeof(result));
	headers->version = 1234;
	int ret;

	record_dbt.data = NULL;
	ret = jaldb_extract_record_uuid(NULL, NULL, &record_dbt, &result);
	record_dbt.data = buffer;
	assert_not_equals(0, ret);

	record_dbt.size = sizeof(*headers) - 1;;
	ret = jaldb_extract_record_uuid(NULL, NULL, &record_dbt, &result);
	record_dbt.size = BUFFER_SIZE;
	assert_not_equals(0, ret);

	ret = jaldb_extract_record_uuid(NULL, NULL, NULL, &result);
	assert_not_equals(0, ret);

	ret = jaldb_extract_record_uuid(NULL, NULL, &record_dbt, NULL);
	assert_not_equals(0, ret);
}

void test_extract_record_sent_flag_returns_error_for_bad_version()
{
	DBT result;
	memset(&result, 0, sizeof(result));
	headers->version = 1234;

	int ret = jaldb_extract_record_sent_flag(NULL, NULL, &record_dbt, &result);
	assert_not_equals(0, ret);
	assert_not_equals(DB_DONOTINDEX, ret);
}

void test_extract_record_sent_flag_works()
{
	DBT result;
	memset(&result, 0, sizeof(result));

	int ret = jaldb_extract_record_sent_flag(NULL, NULL, &record_dbt, &result);
	assert_equals(0, ret);
	assert_equals(sizeof(uint32_t), result.size);
	assert_equals(JALDB_RFLAGS_SENT,*((uint32_t*)result.data));

	free(result.data);
}

void test_extract_record_sent_flag_works_after_a_record_is_synced()
{
	DBT result;
	memset(&result, 0, sizeof(result));

	headers->flags |= JALDB_RFLAGS_SYNCED;

	int ret = jaldb_extract_record_sent_flag(NULL, NULL, &record_dbt, &result);
	assert_equals(0, ret);
	assert_equals(sizeof(uint32_t), result.size);
	assert_equals(JALDB_RFLAGS_SENT,*((uint32_t*)result.data));

	free(result.data);
}

void test_extract_record_sent_flag_returns_error_for_input()
{
	DBT result;
	memset(&result, 0, sizeof(result));
	headers->version = 1234;
	int ret;

	record_dbt.data = NULL;
	ret = jaldb_extract_record_sent_flag(NULL, NULL, &record_dbt, &result);
	record_dbt.data = buffer;
	assert_not_equals(0, ret);

	record_dbt.size = sizeof(*headers) - 1;;
	ret = jaldb_extract_record_sent_flag(NULL, NULL, &record_dbt, &result);
	record_dbt.size = BUFFER_SIZE;
	assert_not_equals(0, ret);

	ret = jaldb_extract_record_sent_flag(NULL, NULL, NULL, &result);
	assert_not_equals(0, ret);

	ret = jaldb_extract_record_sent_flag(NULL, NULL, &record_dbt, NULL);
	assert_not_equals(0, ret);
}

