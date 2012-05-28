/**
 * @file test_jalp_logger_metadata_xml.cpp This file contains functions to test jalp_logger_metadata_to_elem.
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

#include <unistd.h>

#include <libxml/tree.h>

#include <jalop/jalp_context.h>
#include <jalop/jalp_logger_metadata.h>
#include <jalop/jalp_structured_data.h>

#include "jal_asprintf_internal.h"
#include "jalp_context_internal.h"
#include "jalp_log_severity_xml.h"
#include "jalp_stack_frame_xml.h"
#include "jalp_logger_metadata_xml.h"
#include "jal_alloc.h"
#include "jal_xml_utils.h"
#include "xml_test_utils2.h"

jalp_context *ctx = NULL;
struct jalp_logger_metadata *logger_metadata = NULL;
xmlDocPtr doc = NULL;
xmlNodePtr new_elem = NULL;
enum jal_status ret;

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

void setup()
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

	doc = xmlNewDoc((xmlChar *)"1.0");
}

void teardown()
{
	jalp_context_destroy(&ctx);
	new_elem = NULL;
	jalp_logger_metadata_destroy(&logger_metadata);
	xmlFreeDoc(doc);
	jalp_shutdown();
}

void test_logger_metadata_to_elem_returns_null_for_null()
{
	assert_equals(JAL_E_XML_CONVERSION,
			jalp_logger_metadata_to_elem(NULL, ctx, doc, &new_elem));
	assert_equals((void*)NULL, new_elem);

	assert_equals(JAL_E_XML_CONVERSION,
			jalp_logger_metadata_to_elem(logger_metadata, NULL, doc, &new_elem));
	assert_equals((void*)NULL, new_elem);

	assert_equals(JAL_E_XML_CONVERSION,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, NULL, &new_elem));
	assert_equals((void*)NULL, new_elem);

	assert_equals(JAL_E_XML_CONVERSION,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, NULL));
}

void test_logger_metadata_to_elem_returns_invalid_new_elem_non_null()
{
	new_elem = (xmlNodePtr)jal_malloc(4);
	xmlNodePtr temp = new_elem;

	assert_equals(JAL_E_XML_CONVERSION,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_equals(new_elem, temp);

	free(new_elem);
}

void test_logger_metadata_to_elem_returns_valid_element()
{

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);
	assert_content_equals(logger_metadata->timestamp, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_HOSTNAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_APP_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);
	char *pid_str;
	jal_asprintf(&pid_str, "%d", (intmax_t)getpid());
	assert_content_equals(pid_str, temp);
	free(pid_str);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_logger_metadata_to_elem_returns_invalid_bad_sd()
{
	free(logger_metadata->sd->sd_id);
	logger_metadata->sd->sd_id = NULL;

	assert_equals(JAL_E_INVAL_STRUCTURED_DATA,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_equals((void*)NULL, new_elem);
}

void test_logger_metadata_to_elem_returns_valid_element_null_logger_name()
{
	free(logger_metadata->logger_name);
	logger_metadata->logger_name = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_logger_metadata_to_elem_returns_valid_element_null_severity()
{
	jalp_log_severity_destroy(&logger_metadata->severity);
	logger_metadata->severity = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

/*
void test_logger_metadata_to_elem_returns_invalid_element_bad_timestamp()
{
	free(logger_metadata->timestamp);
	logger_metadata->timestamp = jal_strdup(JALP_TEST_LMXML_BAD_TIMESTAMP);

	assert_equals(JAL_E_INVAL_TIMESTAMP,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_equals((void*)NULL, new_elem);
}
*/
void test_logger_metadata_to_elem_returns_valid_element_null_timestamp()
{
	free(logger_metadata->timestamp);
	logger_metadata->timestamp = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_logger_metadata_to_elem_returns_valid_element_null_threadId()
{
	free(logger_metadata->threadId);
	logger_metadata->threadId = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_logger_metadata_to_elem_returns_valid_element_null_message()
{
	free(logger_metadata->message);
	logger_metadata->message = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_logger_metadata_to_elem_returns_valid_element_null_nested_diagnostic_context()
{
	free(logger_metadata->nested_diagnostic_context);
	logger_metadata->nested_diagnostic_context = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_logger_metadata_to_elem_returns_valid_element_null_mapped_diagnostic_context()
{
	free(logger_metadata->mapped_diagnostic_context);
	logger_metadata->mapped_diagnostic_context = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_logger_metadata_to_elem_returns_valid_element_null_stack_frame()
{
	jalp_stack_frame_destroy(&logger_metadata->stack);
	logger_metadata->stack = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_logger_metadata_to_elem_returns_valid_element_null_sd()
{
	jalp_structured_data_destroy(&logger_metadata->sd);
	logger_metadata->sd = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_logger_metadata_to_elem_returns_valid_element_null_hostname()
{
	free(ctx->hostname);
	ctx->hostname = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);


	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_APPLICATIONNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_logger_metadata_to_elem_returns_valid_element_null_app_name()
{
	free(ctx->app_name);
	ctx->app_name = NULL;

	assert_equals(JAL_OK,
			jalp_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOGGERNAME_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_LOGGER_NAME, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_SEVERITY_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_TIMESTAMP_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_HOSTNAME_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_PROCESSID_TAG, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_THREADID_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_THREADID, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MESSAGE_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MESSAGE, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_LOCATION_TAG, temp);
	
	xmlNodePtr temp2 = jal_get_first_element_child(temp);
	assert_not_equals(NULL, temp2);
	assert_tag_equals(JALP_TEST_LMXML_STACKFRAME_TAG, temp2);
	assert_attr_equals("Depth", JALP_TEST_LMXML_SF_DEPTH_GOOD_STR, temp2);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_NDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_NESTED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_MDC_TAG, temp);
	assert_content_equals(JALP_TEST_LMXML_MAPPED_DIAGNOSTIC_CONTEXT, temp);

	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_LMXML_STRUCTUREDDATA_TAG, temp);
	assert_attr_equals("SD_ID", JALP_TEST_LMXML_SD_ID, temp);

	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}
