/**
 * @file test_jalp_syslog_metadata_xml.c This file contains functions to test jalp_syslog_metadata_to_elem.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <unistd.h> /* getpid */
#include <inttypes.h>
#include <jalop/jalp_context.h>

#include "jalp_syslog_metadata_xml.h"
#include "jal_asprintf_internal.h"
#include "jal_alloc.h"
#include "jal_xml_utils.h"
#include "xml_test_utils2.h"

struct jalp_syslog_metadata *syslog = NULL;
jalp_context *ctx = NULL;
xmlDocPtr doc = NULL;
xmlNodePtr new_elem;
xmlNodePtr node;

#define FACILITY_ATTR "Facility"
#define MIN_FACILITY_VAL 0
#define MIN_FACILITY_VAL_STR "0"
#define MAX_FACILITY_VAL 23
#define MAX_FACILITY_VAL_STR "23"
#define FACILITY_VAL 9
#define FACILITY_VAL_STR "9"
#define SEVERITY_ATTR "Severity"
#define MIN_SEVERITY_VAL 0
#define MIN_SEVERITY_VAL_STR "0"
#define MAX_SEVERITY_VAL 7
#define MAX_SEVERITY_VAL_STR "7"
#define SEVERITY_VAL 3
#define SEVERITY_VAL_STR "3"
#define TIMESTAMP_ATTR "Timestamp"
#define BAD_TIMESTAMP "lksajf sdajkl"
#define TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR "2011-06-05T08:02:04.12345+05:23"
#define EXPECTED_TIMESTAMP_FOR_GET_TIME "2011-11-25T14:55:52-05:00"
#define HOSTNAME_ATTR "Hostname"
#define HOSTNAME_VAL_STR "www.fakehost.com"
#define APP_NAME_ATTR "ApplicationName"
#define APP_NAME_VAL_STR "test_jalp_syslog_metadata_xml"
#define PROCESS_ID_ATTR "ProcessID"
#define MESSAGE_ID_ATTR "MessageID"
#define MESSAGE_ID_VAL_STR "Simple Message"

#define SYSLOG_TAG "Syslog"
#define ENTRY_TAG "Entry"
#define ENTRY_VAL "blah blah blah"
#define SD_TAG "StructuredData"
#define SD_ID_ATTR "SD_ID"
#define SD_ONE_ID "sd-one"
#define SD_TWO_ID "sd-two"

#define LEVEL_NUM 1
#define LEVEL_NAME "test-level"

#define APPLICATIONMETADATA "ApplicationMetadata"

#define SCHEMA_PATH "./schemas/"

char *pid_str = NULL;

void setup()
{
	// unfortunately, can't use test-dept mocking magic in c++ code
	// because of all the wonderful name mangling that goes on.
	jal_asprintf(&pid_str, "%" PRIdMAX, (intmax_t) getpid());
	jalp_init();
	ctx = jalp_context_create();
	jalp_context_init(ctx, NULL, HOSTNAME_VAL_STR, APP_NAME_VAL_STR, SCHEMA_PATH);
	syslog = jalp_syslog_metadata_create();
	syslog->timestamp = strdup(TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR);
	syslog->message_id = strdup(MESSAGE_ID_VAL_STR);
	syslog->entry = strdup(ENTRY_VAL);
	syslog->facility = FACILITY_VAL;
	syslog->severity = SEVERITY_VAL;
	struct jalp_structured_data *sd_one = syslog->sd_head =
			jalp_structured_data_append(NULL, SD_ONE_ID);
	struct jalp_structured_data *sd_two = jalp_structured_data_append(sd_one, SD_TWO_ID);

	sd_one->param_list = jalp_param_append(NULL, "foo1", "bar1");
	sd_two->param_list = jalp_param_append(NULL, "foo2", "bar2");

	doc = xmlNewDoc((xmlChar *)"1.0");
	node = xmlNewNode(NULL, (xmlChar *)"xyz");
}

void teardown()
{
	free(pid_str);
	jalp_syslog_metadata_destroy(&syslog);
	jalp_context_destroy(&ctx);
	xmlFreeDoc(doc);
	xmlFreeNode(node);
	jalp_shutdown();
	new_elem = NULL;
}

#if 0
void test_syslog_metadata_to_elem_returns_error_on_bad_input()
{
	enum jal_status ret;

	ret = jalp_syslog_metadata_to_elem(NULL, ctx, node, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jalp_syslog_metadata_to_elem(syslog, NULL, node, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);

	// an empty entry is not an error, so not adding anything here.

	ret = jalp_syslog_metadata_to_elem(syslog, ctx, NULL, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);

	xmlNodePtr bad_elem = (xmlNodePtr) 0xdeadbeef;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, NULL, &bad_elem);
	assert_equals((void*)NULL, new_elem);
	assert_not_equals(JAL_OK, ret);

	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, NULL);
	assert_equals((void*)NULL, new_elem);
	assert_not_equals(JAL_OK, ret);

	// errors for invalid elements.
	syslog->facility = -2;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);

	syslog->facility = MAX_FACILITY_VAL + 1;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);

	syslog->facility = FACILITY_VAL;
	syslog->severity = -2;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);

	syslog->severity = MAX_SEVERITY_VAL + 1;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);

	syslog->severity = SEVERITY_VAL;
	char *ts = syslog->timestamp;
	syslog->timestamp = strdup(BAD_TIMESTAMP);
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(-1, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	free(syslog->timestamp);
	syslog->timestamp = ts;
}
#endif

void test_syslog_metadata_to_elem_returns_valid_element_with_all_fields_filled()
{
	enum jal_status ret;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_missing_entry()
{
	enum jal_status ret;
	free(syslog->entry);
	syslog->entry = NULL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context 2 StructuredData tags...
	xmlNodePtr sd_one = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_single_structured_data()
{
	enum jal_status ret;
	jalp_structured_data_destroy(&syslog->sd_head->next);
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// context should have an Entry followed by 1 StructuredData tag
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr expected_null = sd_one->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_no_strucutred_data()
{
	enum jal_status ret;
	jalp_structured_data_destroy(&syslog->sd_head);
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// context should have an Entry followed by nothing
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	// assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr expected_null = entry_node->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_missing_timestamp()
{
	enum jal_status ret;
	free(syslog->timestamp);
	syslog->timestamp = NULL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	xmlChar *ts_attr = xmlGetProp(new_elem, (xmlChar *)TIMESTAMP_ATTR);
	assert_not_equals(NULL, ts_attr);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	// assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_no_facility()
{
	enum jal_status ret;
	syslog->facility = -1;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, NULL, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}
void test_syslog_metadata_to_elem_returns_valid_element_with_max_facility()
{
	enum jal_status ret;
	syslog->facility = MAX_FACILITY_VAL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, MAX_FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	// assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_min_facility()
{
	enum jal_status ret;
	syslog->facility = MIN_FACILITY_VAL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, MIN_FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_no_severity()
{
	enum jal_status ret;
	syslog->severity = -1;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	
	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, NULL, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	// assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_max_severity()
{
	enum jal_status ret;
	syslog->severity = MAX_SEVERITY_VAL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, MAX_SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_min_severity()
{
	enum jal_status ret;
	syslog->severity = MIN_SEVERITY_VAL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, MIN_SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_no_hostname()
{
	// not sure this is really valid since the hostname is taken from the
	// context and if the context hasn't been initialized then it won't be
	// set.
	enum jal_status ret;
	free(ctx->hostname);
	ctx->hostname = NULL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, NULL, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_no_app_name()
{
	enum jal_status ret;
	free(ctx->app_name);
	ctx->app_name = NULL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	
	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, NULL, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}

void test_syslog_metadata_to_elem_returns_valid_element_with_no_message_id()
{
	enum jal_status ret;
	free(syslog->message_id);
	syslog->message_id = NULL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	
	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, NULL, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	xmlNodePtr entry_node = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	// assert_content_equals(ENTRY_VAL, entry_node);

	xmlNodePtr sd_one = entry_node->next;
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	xmlNodePtr sd_two = sd_one->next;
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	xmlNodePtr expected_null = sd_two->next;
	assert_equals((void*)NULL, expected_null);
}
