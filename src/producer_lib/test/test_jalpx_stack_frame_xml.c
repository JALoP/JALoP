/**
 * @file test_jalpx_stack_frame_xml.c This file contains functions to test jalp_stack_frame_to_elem.
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

#include <stdint.h>
#include <jalop/jal_status.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_logger_metadata.h>
#include "jalpx_stack_frame_xml.h"
#include "jalp_stack_frame_internal.h"
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#define JALP_TEST_SF_CALLER_NAME "caller"
#define JALP_TEST_SF_FILE_NAME "file"
#define JALP_TEST_SF_LINE_NUMBER 1
#define JALP_TEST_SF_CLASS_NAME "class"
#define JALP_TEST_SF_METHOD_NAME "method"
#define JALP_TEST_SF_DEPTH 0
#define JALP_TEST_SF_DEPTH_STR "0"

#define JALP_TEST_SF2_CALLER_NAME "caller2"
#define JALP_TEST_SF2_FILE_NAME "file2"
#define JALP_TEST_SF2_LINE_NUMBER 10
#define JALP_TEST_SF2_CLASS_NAME "class2"
#define JALP_TEST_SF2_METHOD_NAME "method2"
#define JALP_TEST_SF2_DEPTH 1
#define JALP_TEST_SF2_DEPTH_STR "1"

xmlDocPtr doc = NULL;
xmlNodePtr new_elem = NULL;
struct jalp_stack_frame *frame = NULL;

void setup()
{
	jalp_init();

	frame = jalp_stack_frame_append(NULL);

	frame->caller_name = jal_strdup(JALP_TEST_SF_CALLER_NAME);
	frame->file_name = jal_strdup(JALP_TEST_SF_FILE_NAME);
	frame->line_number = JALP_TEST_SF_LINE_NUMBER;
	frame->class_name = jal_strdup(JALP_TEST_SF_CLASS_NAME);
	frame->method_name = jal_strdup(JALP_TEST_SF_METHOD_NAME);
	frame->depth = JALP_TEST_SF_DEPTH;

	doc = xmlNewDoc((xmlChar *)"1.0");
}

void teardown()
{
	new_elem = NULL;
	jalp_stack_frame_destroy(&frame);
	xmlFreeDoc(doc);
	jalp_shutdown();
}

void test_stack_frame_to_elem_returns_valid_element_with_multiple_node_list()
{
	struct jalp_stack_frame *frame2 = jalp_stack_frame_append(frame);

	frame2->caller_name = jal_strdup(JALP_TEST_SF2_CALLER_NAME);
	frame2->file_name = jal_strdup(JALP_TEST_SF2_FILE_NAME);
	frame2->line_number = JALP_TEST_SF2_LINE_NUMBER;
	frame2->class_name = jal_strdup(JALP_TEST_SF2_CLASS_NAME);
	frame2->method_name = jal_strdup(JALP_TEST_SF2_METHOD_NAME);
	frame2->depth = JALP_TEST_SF2_DEPTH;

	enum jal_status ret = jalpx_stack_frame_to_elem(frame, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	printf("\nNEW_STACK_FRAME\n");
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
