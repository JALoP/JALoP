/**
 * @file test_jalpx_syslog_metadata_xml.c This file contains functions to test jalp_syslog_metadata_to_elem.
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

#include <unistd.h> /* getpid */
#include <inttypes.h>
#include <jalop/jalp_context.h>

#include "jalpx_syslog_metadata_xml.h"
#include "jal_asprintf_internal.h"
#include "jal_alloc.h"

struct jalp_syslog_metadata *syslog = NULL;
jalp_context *ctx = NULL;
xmlDocPtr doc = NULL;
xmlNodePtr new_elem;

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

void setup()
{
	// unfortunately, can't use test-dept mocking magic in c++ code
	// because of all the wonderful name mangling that goes on.
	jal_asprintf(&pid_str, "%" PRIdMAX, (intmax_t) getpid());
	jalp_init();
	ctx = jalp_context_create();
	jalp_context_init(ctx, NULL, HOSTNAME_VAL_STR, APP_NAME_VAL_STR, NULL);
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
}

void teardown()
{
	free(pid_str);
	jalp_syslog_metadata_destroy(&syslog);
	jalp_context_destroy(&ctx);
	xmlFreeDoc(doc);
	jalp_shutdown();
	new_elem = NULL;
}

void test_syslog_metadata_to_elem_returns_valid_element_with_all_fields_filled()
{
	enum jal_status ret;
	free(syslog->message_id);
	syslog->message_id = NULL;
	ret = jalpx_syslog_metadata_to_elem(syslog, ctx, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	
	printf("\nNEW_SYSLOG_METADATA\n");
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


