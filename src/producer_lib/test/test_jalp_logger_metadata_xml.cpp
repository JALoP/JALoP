/**
 * @file This file contains functions to test jalp_logger_metadata_to_elem.
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

#include <unistd.h>

#include <jalop/jalp_context.h>
#include <jalop/jalp_logger_metadata.h>
#include <jalop/jalp_structured_data.h>

#include "jal_asprintf_internal.h"
#include "jalp_context_internal.h"
#include "xml_test_utils.hpp"
#include "jalp_log_severity_xml.hpp"
#include "jalp_stack_frame_xml.hpp"
#include "jalp_logger_metadata_xml.hpp"
#include "jal_alloc.h"

XERCES_CPP_NAMESPACE_USE
jalp_context *ctx = NULL;
struct jalp_logger_metadata *logger_metadata = NULL;
DOMDocument *doc = NULL;
DOMElement *new_elem = NULL;
enum jal_status ret;
std::list<const char*> schemas;

#define JALP_TEST_LMXML_LOGGER_NAME "name"
#define JALP_TEST_LMXML_TIMESTAMP "2011-07-14T09:00:00+04:00"
#define JALP_TEST_LMXML_BAD_TIMESTAMP "2011-07-14T09:00:00+0400"
#define JALP_TEST_LMXML_THREADID "threadid"
#define JALP_TEST_LMXML_MESSAGE "message"
#define JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT "ndc"
#define JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT "mdc"
#define JALP_TEST_LMXML_SF_DEPTH_GOOD 0
#define JALP_TEST_LMXML_SF_DEPTH_GOOD_STR "0"
#define JALP_TEST_LMXML_SD_ID "sdid"
#define JALP_TEST_LMXML_PARAM_NAME "param_name"
#define JALP_TEST_LMXML_PARAM_VALUE "param_value"
#define JALP_TEST_LMXML_HOSTNAME "hostname"
#define JALP_TEST_LMXML_APP_NAME "appname"

#define JALP_TEST_LMXML_LOGGERNAME_TAG "LoggerName"
#define JALP_TEST_LMXML_SEVERITY_TAG "Severity"
#define JALP_TEST_LMXML_TIMESTAMP_TAG "Timestamp"
#define JALP_TEST_LMXML_HOSTNAME_TAG "Hostname"
#define JALP_TEST_LMXML_APPLICATIONNAME_TAG "ApplicationName"
#define JALP_TEST_LMXML_PROCESSID_TAG "ProcessID"
#define JALP_TEST_LMXML_THREADID_TAG "ThreadID"
#define JALP_TEST_LMXML_MESSAGE_TAG "Message"
#define JALP_TEST_LMXML_LOCATION_TAG "Location"
#define JALP_TEST_LMXML_STACKFRAME_TAG "StackFrame"
#define JALP_TEST_LMXML_NDC_TAG "NestedDiagnosticContext"
#define JALP_TEST_LMXML_MDC_TAG "MappedDiagnosticContext"
#define JALP_TEST_LMXML_STRUCTUREDDATA_TAG "StructuredData"

extern "C" void setup()
{
	jalp_init();

	ctx = jalp_context_create();
	ctx->hostname = jal_strdup(JALP_TEST_LMXML_HOSTNAME);
	ctx->app_name = jal_strdup(JALP_TEST_LMXML_APP_NAME);

	logger_metadata = jalp_logger_metadata_create();
	logger_metadata->logger_name = jal_strdup(JALP_TEST_LMXML_LOGGER_NAME);
	logger_metadata->severity = jalp_log_severity_create();
	logger_metadata->timestamp = jal_strdup(JALP_TEST_LMXML_TIMESTAMP);
	logger_metadata->threadId = jal_strdup(JALP_TEST_LMXML_THREADID);
	logger_metadata->message = jal_strdup(JALP_TEST_LMXML_MESSAGE);
	logger_metadata->nested_diagnostic_context = jal_strdup(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT);
	logger_metadata->mapped_diagnostic_context = jal_strdup(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT);
	logger_metadata->stack = jalp_stack_frame_append(NULL);
	logger_metadata->stack->depth = JALP_TEST_LMXML_SF_DEPTH_GOOD;
	logger_metadata->sd = jalp_structured_data_append(NULL, JALP_TEST_LMXML_SD_ID);
	logger_metadata->sd->param_list = jalp_param_append(NULL, JALP_TEST_LMXML_PARAM_NAME, JALP_TEST_LMXML_PARAM_VALUE);

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();

	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);
}

extern "C" void teardown()
{
	jalp_context_destroy(&ctx);
	new_elem = NULL;
	jalp_logger_metadata_destroy(&logger_metadata);
	delete doc;
	schemas.clear();
	jalp_shutdown();
}

extern "C" void test_logger_metadata_to_elem_returns_null_for_null()
{
	ret = jalp_logger_metadata_to_elem(NULL, ctx, doc, &new_elem);
	assert_equals(new_elem, NULL);
	assert_equals(ret, JAL_E_XML_CONVERSION);

	ret = jalp_logger_metadata_to_elem(logger_metadata, NULL, doc, &new_elem);
	assert_equals(new_elem, NULL);
	assert_equals(ret, JAL_E_XML_CONVERSION);

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, NULL, &new_elem);
	assert_equals(new_elem, NULL);
	assert_equals(ret, JAL_E_XML_CONVERSION);

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, NULL);
	assert_equals(ret, JAL_E_XML_CONVERSION);
}

extern "C" void test_logger_metadata_to_elem_retuns_invalid_new_elem_non_null()
{
	new_elem = (DOMElement *)jal_malloc(4);
	DOMElement *temp = new_elem;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_equals(new_elem, temp);
	assert_equals(ret, JAL_E_XML_CONVERSION);

	free(new_elem);
}
extern "C" void test_logger_metadata_to_elem_returns_valid_element()
{

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_equals(ret, JAL_OK);
	assert_not_equals(new_elem, NULL);

	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);
	assert_content_equals(logger_metadata->timestamp, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_HOSTNAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_APP_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);
	char *pid_str;
	jal_asprintf(&pid_str, "%d", (intmax_t)getpid());
	assert_content_equals(pid_str, (DOMElement *)temp);
	free(pid_str);


	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_invalid_bad_sd()
{
	free(logger_metadata->sd->sd_id);
	logger_metadata->sd->sd_id = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_equals(ret, JAL_E_INVAL_STRUCTURED_DATA);
	assert_equals(new_elem, NULL);
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_logger_name()
{
	free(logger_metadata->logger_name);
	logger_metadata->logger_name = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_equals(ret, JAL_OK);
	assert_not_equals(new_elem, NULL);

	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_severity()
{
	jalp_log_severity_destroy(&logger_metadata->severity);
	logger_metadata->severity = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_not_equals(new_elem, NULL);
	assert_equals(ret, JAL_OK);


	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_invalid_element_bad_timestamp()
{
	free(logger_metadata->timestamp);
	logger_metadata->timestamp = jal_strdup(JALP_TEST_LMXML_BAD_TIMESTAMP);

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_equals(new_elem, NULL);
	assert_equals(ret, JAL_E_INVAL_TIMESTAMP);
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_timestamp()
{
	free(logger_metadata->timestamp);
	logger_metadata->timestamp = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_not_equals(new_elem, NULL);
	assert_equals(ret, JAL_OK);


	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_threadId()
{
	free(logger_metadata->threadId);
	logger_metadata->threadId = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_not_equals(new_elem, NULL);
	assert_equals(ret, JAL_OK);


	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_message()
{
	free(logger_metadata->message);
	logger_metadata->message = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_not_equals(new_elem, NULL);
	assert_equals(ret, JAL_OK);


	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_nested_diagnostic_context()
{
	free(logger_metadata->nested_diagnostic_context);
	logger_metadata->nested_diagnostic_context = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_not_equals(new_elem, NULL);
	assert_equals(ret, JAL_OK);


	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_mapped_diagnostic_context()
{
	free(logger_metadata->mapped_diagnostic_context);
	logger_metadata->mapped_diagnostic_context = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_not_equals(new_elem, NULL);
	assert_equals(ret, JAL_OK);


	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_stack_frame()
{
	jalp_stack_frame_destroy(&logger_metadata->stack);
	logger_metadata->stack = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_not_equals(new_elem, NULL);
	assert_equals(ret, JAL_OK);


	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_sd()
{
	jalp_structured_data_destroy(&logger_metadata->sd);
	logger_metadata->sd = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_not_equals(new_elem, NULL);
	assert_equals(ret, JAL_OK);


	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_hostname()
{
	free(ctx->hostname);
	ctx->hostname = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_not_equals(new_elem, NULL);
	assert_equals(ret, JAL_OK);


	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_logger_metadata_to_elem_returns_valid_element_null_app_name()
{
	free(ctx->app_name);
	ctx->app_name = NULL;

	ret = jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_not_equals(new_elem, NULL);
	assert_equals(ret, JAL_OK);


	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, (DOMElement *)temp);
	DOMNode *temp2 = temp->getFirstChild();
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, (DOMElement *)temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, (DOMElement *)temp2);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, (DOMElement *)temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, (DOMElement *)temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
