/**
 * @file This file contains functions to test jalp_syslog_metadata_to_elem.
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

// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// c++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
extern "C" {
#include <test-dept.h>
}
#include <unistd.h> // getpid
#include <jalop/jalp_context.h>

#include "xml_test_utils.hpp"
#include "jalp_syslog_metadata_xml.hpp"
#include "jal_asprintf_internal.h"
#include "jal_alloc.h"

XERCES_CPP_NAMESPACE_USE
struct jalp_syslog_metadata *syslog = NULL;
jalp_context *ctx = NULL;
DOMDocument *doc = NULL;
DOMElement *new_elem;
XMLCh *expected_name_attr = NULL;
XMLCh *expectedLevelVal = NULL;
std::list<const char*> schemas;

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
char *pid_str = NULL;
// TODO: remove when API is fixed
extern enum jal_status jalp_syslog_metadata_to_elem(const struct jalp_syslog_metadata *syslog,
					const struct jalp_context_t *ctx,
					const char *entry,
					DOMDocument *doc,
					DOMElement **new_elem);
extern "C" void setup()
{
	// unfortunately, can't use test-dept mocking magic in c++ code
	// because of all the wonderful name mangling that goes on.
	jal_asprintf(&pid_str, "%" PRIdMAX, (intmax_t) getpid());
	jalp_init();
	ctx = jalp_context_create();
	jalp_context_init(ctx, NULL, HOSTNAME_VAL_STR, APP_NAME_VAL_STR);
	syslog = jalp_syslog_metadata_create();
	syslog->timestamp = strdup(TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR);
	syslog->message_id = strdup(MESSAGE_ID_VAL_STR);
	syslog->facility = FACILITY_VAL;
	syslog->severity = SEVERITY_VAL;
	struct jalp_structured_data *sd_one = syslog->sd_head =
			jalp_structured_data_append(NULL, SD_ONE_ID);
	struct jalp_structured_data *sd_two = jalp_structured_data_append(sd_one, SD_TWO_ID);

	sd_one->param_list = jalp_param_append(NULL, "foo1", "bar1");
	sd_two->param_list = jalp_param_append(NULL, "foo2", "bar2");

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();

	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);
}

extern "C" void teardown()
{
	free(pid_str);
	jalp_syslog_metadata_destroy(&syslog);
	jalp_context_destroy(&ctx);
	delete doc;
	schemas.clear();
	jalp_shutdown();
	new_elem = NULL;
}

extern "C" void test_syslog_metadata_to_elem_returns_error_on_bad_input()
{
	enum jal_status ret;

	ret = jalp_syslog_metadata_to_elem(NULL, ctx, ENTRY_VAL, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals(NULL, new_elem);

	ret = jalp_syslog_metadata_to_elem(syslog, NULL, ENTRY_VAL, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals(NULL, new_elem);

	// an empty entry is not an error, so not adding anything here.

	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, NULL, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals(NULL, new_elem);

	DOMElement *bad_elem = (DOMElement*) 0xdeadbeef;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, NULL, &bad_elem);
	assert_equals(NULL, new_elem);
	assert_not_equals(JAL_OK, ret);

	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, NULL);
	assert_equals(NULL, new_elem);
	assert_not_equals(JAL_OK, ret);

	// errors for invalid elements.
	syslog->facility = -2;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals(NULL, new_elem);

	syslog->facility = MAX_FACILITY_VAL + 1;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals(NULL, new_elem);

	syslog->facility = FACILITY_VAL;
	syslog->severity = -2;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals(NULL, new_elem);

	syslog->severity = MAX_SEVERITY_VAL + 1;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals(NULL, new_elem);

	syslog->severity = SEVERITY_VAL;
	char *ts = syslog->timestamp;
	syslog->timestamp = strdup(BAD_TIMESTAMP);
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals(NULL, new_elem);
	free(syslog->timestamp);
	syslog->timestamp = ts;
}

extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_all_fields_filled()
{
	enum jal_status ret;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_missing_entry()
{
	enum jal_status ret;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, NULL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context 2 StructuredData tags...
	DOMElement *sd_one = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_single_structured_data()
{
	enum jal_status ret;
	jalp_structured_data_destroy(&syslog->sd_head->next);
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// context should have an Entry followed by 1 StructuredData tag
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMNode *expected_null = sd_one->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_no_strucutred_data()
{
	enum jal_status ret;
	jalp_structured_data_destroy(&syslog->sd_head);
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// context should have an Entry followed by nothing
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMNode *expected_null = entry_node->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_missing_timestamp()
{
	enum jal_status ret;
	free(syslog->timestamp);
	syslog->timestamp = NULL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	XMLCh *ts_attr_name = XMLString::transcode(TIMESTAMP_ATTR);
	DOMNode *tsNode = new_elem->getAttributes()->getNamedItem(ts_attr_name);
	XMLString::release(&ts_attr_name);
	assert_not_equals(NULL, tsNode);
	assert_not_equals(NULL, tsNode->getTextContent());
	assert_not_equals(0, XMLString::stringLen(tsNode->getTextContent()));
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_no_facility()
{
	enum jal_status ret;
	syslog->facility = -1;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, NULL, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_max_facility()
{
	enum jal_status ret;
	syslog->facility = MAX_FACILITY_VAL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, MAX_FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_min_facility()
{
	enum jal_status ret;
	syslog->facility = MIN_FACILITY_VAL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, MIN_FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_no_severity()
{
	enum jal_status ret;
	syslog->severity = -1;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, NULL, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_max_severity()
{
	enum jal_status ret;
	syslog->severity = MAX_SEVERITY_VAL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, MAX_SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_min_severity()
{
	enum jal_status ret;
	syslog->severity = MIN_SEVERITY_VAL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, MIN_SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_no_hostname()
{
	// not sure this is really valid since the hostname is taken from the
	// context and if the context hasn't been initialized then it won't be
	// set.
	enum jal_status ret;
	free(ctx->hostname);
	ctx->hostname = NULL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, NULL, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_no_app_name()
{
	enum jal_status ret;
	free(ctx->app_name);
	ctx->app_name = NULL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, NULL, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, MESSAGE_ID_VAL_STR, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
extern "C" void test_syslog_metadata_to_elem_returns_valid_element_with_no_message_id()
{
	enum jal_status ret;
	free(syslog->message_id);
	syslog->message_id = NULL;
	ret = jalp_syslog_metadata_to_elem(syslog, ctx, ENTRY_VAL, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
	assert_attr_equals(FACILITY_ATTR, FACILITY_VAL_STR, new_elem);
	assert_attr_equals(SEVERITY_ATTR, SEVERITY_VAL_STR, new_elem);
	assert_attr_equals(TIMESTAMP_ATTR, TIMESTAMP_WITH_SINGLE_DIGIT_VALS_STR, new_elem);
	assert_attr_equals(HOSTNAME_ATTR, HOSTNAME_VAL_STR, new_elem);
	assert_attr_equals(APP_NAME_ATTR, APP_NAME_VAL_STR, new_elem);
	assert_attr_equals(PROCESS_ID_ATTR, pid_str, new_elem);
	assert_attr_equals(MESSAGE_ID_ATTR, NULL, new_elem);

	// default context should have an Entry followed by 2 StructuredData
	// tags...
	DOMElement *entry_node = dynamic_cast<DOMElement*>(new_elem->getFirstChild());
	assert_not_equals(NULL, entry_node);
	assert_tag_equals(ENTRY_TAG, entry_node);
	assert_content_equals(ENTRY_VAL, entry_node);

	DOMElement *sd_one = dynamic_cast<DOMElement*>(entry_node->getNextSibling());
	assert_not_equals(NULL, sd_one);
	assert_tag_equals(SD_TAG, sd_one);
	assert_attr_equals(SD_ID_ATTR, SD_ONE_ID, sd_one);

	DOMElement *sd_two = dynamic_cast<DOMElement*>(sd_one->getNextSibling());
	assert_not_equals(NULL, sd_two);
	assert_tag_equals(SD_TAG, sd_two);
	assert_attr_equals(SD_ID_ATTR, SD_TWO_ID, sd_two);

	DOMNode *expected_null = sd_two->getNextSibling();
	assert_equals(NULL, expected_null);
}
