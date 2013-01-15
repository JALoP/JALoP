/**
 * @file test_jaldb_datetime.c This file contains functions to test XML
 * DateTime related functions.
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

#include <db.h>
#include <jalop/jal_status.h>
#include <libxml/xmlschemastypes.h>
#include <test-dept.h>

#include "jal_error_callback_internal.h"

#include "jaldb_datetime.h"
#include "jaldb_serialize_record.h"

#define DT1 "2012-12-12T09:00:00Z"
#define DT2 "2012-12-12T09:00:01Z"
#define DT3 "2012-12-12T09:00:00+13:00"
#define DT4 "2012-12-12T09:00:00-13:00"

#define DT1_NO_TZ "2012-12-12T09:00:00"

#define BAD_DATETIME "Not a DateTime"

static DBT dbt1;
static DBT dbt2;
static DBT dbt1_no_tz;

static DBT dbt_record;

static int error_handler_called;

#define PADDING 1024
#define BUFFER_SIZE (sizeof(struct jaldb_serialize_record_headers) + PADDING)

uint8_t buffer[BUFFER_SIZE];
static struct jaldb_serialize_record_headers *headers;
char *datetime_in_buffer;

xmlSchemaTypePtr mock_xmlSchemaGetBuiltInType(xmlSchemaValType type)
{
	return NULL;
}

void mock_error_handler(enum jal_status s)
{
	error_handler_called = 1;
}

void setup()
{

	xmlSchemaInitTypes();

	memset(&dbt1, 0, sizeof(dbt1));
	dbt1.data = DT1;
	dbt1.size = strlen(DT1) + 1;

	memset(&dbt2, 0, sizeof(dbt2));
	dbt2.data = DT2;
	dbt2.size = strlen(DT2) + 1;

	memset(&dbt1_no_tz, 0, sizeof(dbt1_no_tz));
	dbt1_no_tz.data = DT1_NO_TZ;
	dbt1_no_tz.size = strlen(DT1_NO_TZ) + 1;

	error_handler_called = 0;

	headers = (struct jaldb_serialize_record_headers*) buffer;
	headers->version = JALDB_DB_LAYOUT_VERSION;
	datetime_in_buffer = (char*)(buffer + sizeof(*headers));

	memset(&dbt_record, 0, sizeof(dbt_record));
	dbt_record.data = buffer;
	dbt_record.size = BUFFER_SIZE;
}

void teardown()
{
	restore_function(xmlSchemaGetBuiltInType);
	restore_function(jal_error_handler);
	xmlSchemaCleanupTypes();
}

void test_xml_datetime_compare_works()
{
	assert_equals(-1, jaldb_xml_datetime_compare(NULL, &dbt1, &dbt2));
	assert_equals( 1, jaldb_xml_datetime_compare(NULL, &dbt2, &dbt1));
	assert_equals( 0, jaldb_xml_datetime_compare(NULL, &dbt1, &dbt1));
}

void test_xml_datetime_calls_error_handler_on_bad_parse()
{
	replace_function(jal_error_handler, mock_error_handler);

	dbt1.data = BAD_DATETIME;
	jaldb_xml_datetime_compare(NULL, &dbt1, &dbt2);
	assert_true(error_handler_called);

	error_handler_called = 0;
	jaldb_xml_datetime_compare(NULL, &dbt2, &dbt1);
	assert_true(error_handler_called);
}

void test_xml_datetime_calls_error_handler_on_indeterminates()
{
	replace_function(jal_error_handler, mock_error_handler);

	jaldb_xml_datetime_compare(NULL, &dbt1, &dbt1_no_tz);
	assert_true(error_handler_called);
}

void test_xml_datetime_calls_error_handler_with_bad_schema_type()
{
	replace_function(jal_error_handler, mock_error_handler);
	replace_function(xmlSchemaGetBuiltInType, mock_xmlSchemaGetBuiltInType);

	jaldb_xml_datetime_compare(NULL, &dbt1, &dbt2);
	assert_true(error_handler_called);
}

/////////////////////////////////////////////////////
// Unit tests for jaldb_extract_datetime_key_common
/////////////////////////////////////////////////////
void test_extract_datetime_common_calls_error_handler_on_bad_parse()
{
	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;
	char has_tz = 0;

	strcpy(datetime_in_buffer, BAD_DATETIME);

	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen, &has_tz);
	assert_not_equals(JALDB_OK, ret);
}

void test_extract_datetime_fails_with_bad_schema_type()
{
	replace_function(xmlSchemaGetBuiltInType, mock_xmlSchemaGetBuiltInType);

	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;;
	char has_tz = 0;

	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen, &has_tz);
	assert_not_equals(JALDB_OK, ret);

}

void test_extract_datetime_fails_for_bad_input()
{
	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;
	char has_tz = 0;

	ret = jaldb_extract_datetime_key_common(NULL, &dtString, &dtLen, &has_tz);
	assert_not_equals(JALDB_OK, ret);

	ret = jaldb_extract_datetime_key_common(buffer, NULL, &dtLen, &has_tz);
	assert_not_equals(JALDB_OK, ret);

	dtString = (char*) 0xdeadbeef;
	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen, &has_tz);
	assert_not_equals(JALDB_OK, ret);
	dtString = NULL;

	ret = jaldb_extract_datetime_key_common(buffer, &dtString, NULL, &has_tz);
	assert_not_equals(JALDB_OK, ret);

	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen, NULL);
	assert_not_equals(JALDB_OK, ret);
}

void test_extract_datetime_works_with_timezone()
{
	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;
	char has_tz = 0;

	strcpy(datetime_in_buffer, DT1);
	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen, &has_tz);
	assert_equals(JALDB_OK, ret);
	assert_equals(datetime_in_buffer, dtString);
	assert_equals(strlen(datetime_in_buffer), dtLen);
	assert_equals(1, has_tz);
}

void test_extract_datetime_works_with_postive_offset()
{
	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;
	char has_tz = 0;

	strcpy(datetime_in_buffer, DT3);
	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen, &has_tz);
	assert_equals(JALDB_OK, ret);
	assert_equals(datetime_in_buffer, dtString);
	assert_equals(strlen(datetime_in_buffer), dtLen);
	assert_equals(1, has_tz);
}

void test_extract_datetime_works_with_negative_offset()
{
	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;
	char has_tz = 0;

	strcpy(datetime_in_buffer, DT4);
	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen, &has_tz);
	assert_equals(JALDB_OK, ret);
	assert_equals(datetime_in_buffer, dtString);
	assert_equals(strlen(datetime_in_buffer), dtLen);
	assert_equals(1, has_tz);
}

void test_extract_datetime_works_without_timezone()
{
	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;
	char has_tz = 1;

	strcpy(datetime_in_buffer, DT1_NO_TZ);
	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen, &has_tz);
	assert_equals(JALDB_OK, ret);
	assert_equals(datetime_in_buffer, dtString);
	assert_equals(strlen(datetime_in_buffer), dtLen);
	assert_equals(0, has_tz);
}

void test_extract_datetime_w_tz_key_works()
{
	int ret;
	DBT result;
	memset(&result, 0, sizeof(result));

	strcpy(datetime_in_buffer, DT4);
	ret = jaldb_extract_datetime_w_tz_key(NULL, NULL, &dbt_record, &result);

	assert_equals(0, ret);
	assert_not_equals((void*) NULL, result.data);
	assert_equals(strlen(DT4) + 1, result.size);
	assert_equals(0, strcmp(result.data, DT4));
	free(result.data);
}

void test_extract_datetime_w_tz_key_returns_no_index_with_no_tz()
{
	int ret;
	DBT result;
	memset(&result, 0, sizeof(result));

	strcpy(datetime_in_buffer, DT1_NO_TZ);
	ret = jaldb_extract_datetime_w_tz_key(NULL, NULL, &dbt_record, &result);

	assert_equals(DB_DONOTINDEX, ret);
}

void test_extract_datetime_wo_tz_key_works()
{
	int ret;
	DBT result;
	memset(&result, 0, sizeof(result));

	strcpy(datetime_in_buffer, DT1_NO_TZ);
	ret = jaldb_extract_datetime_wo_tz_key(NULL, NULL, &dbt_record, &result);

	assert_equals(0, ret);
	assert_not_equals((void*) NULL, result.data);
	assert_equals(strlen(DT1_NO_TZ) + 1, result.size);
	assert_equals(0, strcmp(result.data, DT1_NO_TZ));
	free(result.data);
}

void test_extract_datetime_wo_tz_key_returns_no_index_with_tz()
{
	int ret;
	DBT result;
	memset(&result, 0, sizeof(result));

	strcpy(datetime_in_buffer, DT1);
	ret = jaldb_extract_datetime_wo_tz_key(NULL, NULL, &dbt_record, &result);

	assert_equals(DB_DONOTINDEX, ret);
}
