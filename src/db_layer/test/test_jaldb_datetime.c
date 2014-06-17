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
#include <jalop/jal_status.h>
#include <libxml/xmlschemastypes.h>
#include <test-dept.h>

#include "jal_error_callback_internal.h"

#include "jaldb_datetime.h"
#include "jaldb_serialize_record.h"

#define DT1 "2012-12-12T09:00:00.00001Z"
#define DT2 "2012-12-12T09:00:01.00001Z"
#define DT3 "2012-12-12T09:00:00.00001+13:00"
#define DT4 "2012-12-12T09:00:00.00001-13:00"
#define DT5 "2012-12-12T08:59:59.99999-08:00"
#define DT6 "2012-12-12T09:00:00.00000-08:00"
#define DT7 "2012-12-12T09:00:00.00001-08:00"

#define DT8 "2012-12-12T09:00:00.00001"

#define BAD_DATETIME "Not a DateTime"

static DBT dbt1;
static DBT dbt2;
static DBT dbt5;
static DBT dbt6;
static DBT dbt7;
static DBT dbt8;

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

	memset(&dbt5, 0, sizeof(dbt5));
	dbt5.data = DT5;
	dbt5.size = strlen(DT5) + 1;

	memset(&dbt6, 0, sizeof(dbt6));
	dbt6.data = DT6;
	dbt6.size = strlen(DT6) + 1;

	memset(&dbt7, 0, sizeof(dbt7));
	dbt7.data = DT7;
	dbt7.size = strlen(DT7) + 1;

	memset(&dbt8, 0, sizeof(dbt8));
	dbt8.data = DT8;
	dbt8.size = strlen(DT8) + 1;

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

	assert_equals( 0, jaldb_xml_datetime_compare(NULL, &dbt5, &dbt5));
	assert_equals( 0, jaldb_xml_datetime_compare(NULL, &dbt6, &dbt6));
	assert_equals( 0, jaldb_xml_datetime_compare(NULL, &dbt7, &dbt7));
	assert_equals(-1, jaldb_xml_datetime_compare(NULL, &dbt5, &dbt7));
	assert_equals(-1, jaldb_xml_datetime_compare(NULL, &dbt5, &dbt6));
	assert_equals(-1, jaldb_xml_datetime_compare(NULL, &dbt6, &dbt7));
	assert_equals( 1, jaldb_xml_datetime_compare(NULL, &dbt7, &dbt6));
	assert_equals( 1, jaldb_xml_datetime_compare(NULL, &dbt7, &dbt5));
	assert_equals( 1, jaldb_xml_datetime_compare(NULL, &dbt6, &dbt5));
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

	jaldb_xml_datetime_compare(NULL, &dbt1, &dbt8);
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

	strcpy(datetime_in_buffer, BAD_DATETIME);

	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen);
	assert_not_equals(JALDB_OK, ret);
}

void test_extract_datetime_fails_with_bad_schema_type()
{
	replace_function(xmlSchemaGetBuiltInType, mock_xmlSchemaGetBuiltInType);

	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;

	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen);
	assert_not_equals(JALDB_OK, ret);

}

void test_extract_datetime_fails_for_bad_input()
{
	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;

	ret = jaldb_extract_datetime_key_common(NULL, &dtString, &dtLen);
	assert_not_equals(JALDB_OK, ret);

	ret = jaldb_extract_datetime_key_common(buffer, NULL, &dtLen);
	assert_not_equals(JALDB_OK, ret);

	dtString = (char*) 0xdeadbeef;
	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen);
	assert_not_equals(JALDB_OK, ret);
	dtString = NULL;

	ret = jaldb_extract_datetime_key_common(buffer, &dtString, NULL);
	assert_not_equals(JALDB_OK, ret);
}

void test_extract_datetime_works()
{
	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;

	strcpy(datetime_in_buffer, DT8);
	ret = jaldb_extract_datetime_key_common(buffer, &dtString, &dtLen);
	assert_equals(JALDB_OK, ret);
	assert_equals(datetime_in_buffer, dtString);
	assert_equals(strlen(datetime_in_buffer), dtLen);
}

void test_extract_datetime_key_works()
{
	int ret;
	DBT result;
	memset(&result, 0, sizeof(result));

	strcpy(datetime_in_buffer, DT8);
	ret = jaldb_extract_datetime_key(NULL, NULL, &dbt_record, &result);

	assert_equals(0, ret);
	assert_not_equals((void*) NULL, result.data);
	assert_equals(strlen(DT8) + 1, result.size);
	assert_equals(0, strcmp(result.data, DT8));
	free(result.data);
}
