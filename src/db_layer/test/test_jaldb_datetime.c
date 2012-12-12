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

#define DT1 "2012-12-12T09:00:00Z"
#define DT2 "2012-12-12T09:00:01Z"

#define DT1_NO_TZ "2012-12-12T09:00:00"

#define BAD_DATETIME "Not a DateTime"

static DBT dbt1;
static DBT dbt2;
static DBT dbt1_no_tz;

static int error_handler_called;

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

