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


#include <test-dept.h>

#include <unistd.h>

#include <libxml/tree.h>

#include <jalop/jalp_context.h>
#include <jalop/jalp_logger_metadata.h>
#include <jalop/jalp_structured_data.h>

#include "jal_asprintf_internal.h"
#include "jalp_context_internal.h"
#include "jalpx_log_severity_xml.h"
#include "jalpx_stack_frame_xml.h"
#include "jalpx_logger_metadata_xml.h"
#include "jal_alloc.h"

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

void test_logger_metadata_to_elem_returns_valid_element()
{

	ret = jalpx_logger_metadata_to_elem(logger_metadata, ctx, doc, &new_elem);
	assert_equals(ret, JAL_OK);
	assert_not_equals(new_elem, NULL);

	printf("\nNEW_LOGGER_METADATA\n");
	xmlDocSetRootElement(doc, new_elem);

	xmlChar *xmlbuff;
	int buffersize;

	/*
	* Dump the document to a buffer and print it
	* for demonstration purposes.
	*/
	xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);
	printf("%s", (char *) xmlbuff);

	/*
	* Free associated memory.
	*/
	xmlFree(xmlbuff);
}
