/**
 * @file test_jalp_stack_frame_xml.c This file contains functions to test jalp_stack_frame_to_elem.
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

#include <test-dept.h>

#include <stdint.h>
#include <limits.h>
#include <jalop/jal_status.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_logger_metadata.h>
#include "xml_test_utils2.h"
#include "jalp_stack_frame_xml.h"
#include "jalp_stack_frame_internal.h"
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jal_xml_utils.h"

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

void test_stack_frame_to_elem_returns_error_on_invalid_input()
{
	xmlNodePtr new_elem2 = (xmlNodePtr) 0xbadf00d;

	assert_equals(JAL_E_XML_CONVERSION,
			jalp_stack_frame_to_elem(NULL, doc, &new_elem));
	assert_equals(JAL_E_XML_CONVERSION,
			jalp_stack_frame_to_elem(frame, NULL, &new_elem));
	assert_equals(JAL_E_XML_CONVERSION,
			jalp_stack_frame_to_elem(frame, doc, &new_elem2));
}

void test_stack_frame_to_elem_returns_valid_element_with_single_node_list()
{
	assert_equals(JAL_OK,
			jalp_stack_frame_to_elem(frame, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, atoi((const char *)temp->children->content));
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
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

	assert_equals(JAL_OK,
			jalp_stack_frame_to_elem(frame, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, atoi((const char *)temp->children->content));
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_stack_frame_to_elem_correctly_supresses_line_number()
{
	frame->line_number = 0;

	assert_equals(JAL_OK,
			jalp_stack_frame_to_elem(frame, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_stack_frame_to_elem_returns_valid_element_with_null_caller_name()
{
	free(frame->caller_name);
	frame->caller_name = NULL;
	
	assert_equals(JAL_OK,
			jalp_stack_frame_to_elem(frame, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, atoi((const char *)temp->children->content));
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_stack_frame_to_elem_returns_valid_element_with_null_file_name()
{
	free(frame->file_name);
	frame->file_name = NULL;
	
	assert_equals(JAL_OK,
			jalp_stack_frame_to_elem(frame, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, atoi((const char *)temp->children->content));
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_stack_frame_to_elem_returns_valid_element_with_null_class_name()
{
	free(frame->class_name);
	frame->class_name = NULL;

	assert_equals(JAL_OK,
			jalp_stack_frame_to_elem(frame, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, temp);
	temp = temp->next;;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, atoi((const char *)temp->children->content));
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_stack_frame_to_elem_returns_valid_element_with_null_method_name()
{
	free(frame->method_name);
	frame->method_name = NULL;

	assert_equals(JAL_OK,
			jalp_stack_frame_to_elem(frame, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, temp);
	temp = temp->next;;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, atoi((const char *)temp->children->content));
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_stack_frame_to_elem_depth_INT_MAX()
{
	frame->depth = INT_MAX;
	char *str_int_max;
	jal_asprintf(&str_int_max, "%d", INT_MAX);

	assert_equals(JAL_OK,
			jalp_stack_frame_to_elem(frame, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, atoi((const char *)temp->children->content));
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, temp);
	assert_attr_equals("Depth", str_int_max, new_elem);
	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	
	free(str_int_max);
}

void test_stack_frame_to_elem_line_number_ULONG_MAX()
{
	frame->line_number = UINT64_MAX;
	char *str_uint64_max;
	jal_asprintf(&str_uint64_max, "%llu", UINT64_MAX);

	assert_equals(JAL_OK,
			jalp_stack_frame_to_elem(frame, doc, &new_elem));
	assert_not_equals(NULL, new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(str_uint64_max, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, temp);
	temp = temp->next;
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->next;
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	
	free(str_uint64_max);
}
