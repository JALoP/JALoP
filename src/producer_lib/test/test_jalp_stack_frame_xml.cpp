/**
 * @file This file contains functions to test jalp_stack_frame_to_elem.
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

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif

//C++ will not define the UINT64_MAX macro unless this is defined.
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#endif

extern "C" {
#include <test-dept.h>
}

#include <stdint.h>
#include <jalop/jal_status.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_logger_metadata.h>
#include "xml_test_utils.hpp"
#include "jalp_stack_frame_xml.hpp"
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

XERCES_CPP_NAMESPACE_USE

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

DOMDocument *doc = NULL;
DOMElement *new_elem = NULL;
std::list<const char*> schemas;
struct jalp_stack_frame *frame = NULL;

extern "C" void setup()
{
	jalp_init();

	frame = jalp_stack_frame_append(NULL);

	frame->caller_name = jal_strdup(JALP_TEST_SF_CALLER_NAME);
	frame->file_name = jal_strdup(JALP_TEST_SF_FILE_NAME);
	frame->line_number = JALP_TEST_SF_LINE_NUMBER;
	frame->class_name = jal_strdup(JALP_TEST_SF_CLASS_NAME);
	frame->method_name = jal_strdup(JALP_TEST_SF_METHOD_NAME);
	frame->depth = JALP_TEST_SF_DEPTH;

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();

	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);
}

extern "C" void teardown()
{
	new_elem = NULL;
	jalp_stack_frame_destroy(&frame);
	delete doc;
	schemas.clear();
	jalp_shutdown();
}


extern "C" void test_stack_frame_to_elem_returns_null_for_null()
{
	new_elem = (DOMElement *)NULL;
	enum jal_status ret = jalp_stack_frame_to_elem(NULL, NULL, &new_elem);
	assert_equals((DOMElement *)NULL, new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);

	ret = jalp_stack_frame_to_elem(frame, NULL, &new_elem);
	assert_equals((DOMElement *)NULL, new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);

	ret = jalp_stack_frame_to_elem(NULL, doc, &new_elem);
	assert_equals((DOMElement *)NULL, new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);

	ret = jalp_stack_frame_to_elem(NULL, NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
}

extern "C" void test_stack_frame_to_elem_returns_valid_element_with_single_node_list()
{
	enum jal_status ret = jalp_stack_frame_to_elem(frame, doc, &(new_elem));
	assert_equals(JAL_OK, ret);

	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, XMLString::parseInt(temp->getTextContent()));

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, (DOMElement *)temp);

	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, (DOMElement *)temp);

	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);

	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_stack_frame_to_elem_returns_valid_element_with_multiple_node_list()
{
	jalp_stack_frame *frame2 = jalp_stack_frame_append(frame);

	frame2->caller_name = jal_strdup(JALP_TEST_SF2_CALLER_NAME);
	frame2->file_name = jal_strdup(JALP_TEST_SF2_FILE_NAME);
	frame2->line_number = JALP_TEST_SF2_LINE_NUMBER;
	frame2->class_name = jal_strdup(JALP_TEST_SF2_CLASS_NAME);
	frame2->method_name = jal_strdup(JALP_TEST_SF2_METHOD_NAME);
	frame2->depth = JALP_TEST_SF2_DEPTH;

	enum jal_status ret = jalp_stack_frame_to_elem(frame, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, XMLString::parseInt(temp->getTextContent()));
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, (DOMElement *)temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_stack_frame_to_elem_correctly_suppresses_depth()
{
	frame->depth = -1;

	enum jal_status ret = jalp_stack_frame_to_elem(frame, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, XMLString::parseInt(temp->getTextContent()));
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, (DOMElement *)temp);
	assert_attr_equals("Depth", NULL, new_elem);
	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_stack_frame_to_elem_correctly_supresses_line_number()
{
	frame->line_number = 0;

	enum jal_status ret = jalp_stack_frame_to_elem(frame, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, (DOMElement *)temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_stack_frame_to_elem_returns_valid_element_with_null_caller_name()
{
	free(frame->caller_name);
	frame->caller_name = NULL;

	enum jal_status ret = jalp_stack_frame_to_elem(frame, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, XMLString::parseInt(temp->getTextContent()));
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, (DOMElement *)temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_stack_frame_to_elem_returns_valid_element_with_null_file_name()
{
	free(frame->file_name);
	frame->file_name = NULL;

	enum jal_status ret = jalp_stack_frame_to_elem(frame, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, XMLString::parseInt(temp->getTextContent()));
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, (DOMElement *)temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_stack_frame_to_elem_returns_valid_element_with_null_class_name()
{
	free(frame->class_name);
	frame->class_name = NULL;

	enum jal_status ret = jalp_stack_frame_to_elem(frame, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, XMLString::parseInt(temp->getTextContent()));
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, (DOMElement *)temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_stack_frame_to_elem_returns_valid_element_with_null_method_name()
{
	free(frame->method_name);
	frame->method_name = NULL;

	enum jal_status ret = jalp_stack_frame_to_elem(frame, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, XMLString::parseInt(temp->getTextContent()));
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, (DOMElement *)temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_stack_frame_to_elem_depth_INT_MAX()
{
	frame->depth = INT_MAX;
	char * str_int_max;
	jal_asprintf(&str_int_max, "%d", INT_MAX);

	enum jal_status ret = jalp_stack_frame_to_elem(frame, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_equals(JALP_TEST_SF_LINE_NUMBER, XMLString::parseInt(temp->getTextContent()));
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, (DOMElement *)temp);
	assert_attr_equals("Depth", str_int_max, new_elem);
	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));

	free(str_int_max);
}

extern "C" void test_stack_frame_to_elem_line_number_ULONG_MAX()
{
	frame->line_number = UINT64_MAX;
	char * str_uint64_max;
	jal_asprintf(&str_uint64_max, "%llu", UINT64_MAX);

	enum jal_status ret = jalp_stack_frame_to_elem(frame, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	DOMNode *temp = new_elem->getFirstChild();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CALLER_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_FILE_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(str_uint64_max, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_CLASS_NAME, (DOMElement *)temp);
	temp = temp->getNextSibling();
	assert_not_equals(NULL, temp);
	assert_content_equals(JALP_TEST_SF_METHOD_NAME, (DOMElement *)temp);
	assert_attr_equals("Depth", JALP_TEST_SF_DEPTH_STR, new_elem);
	temp = temp->getNextSibling();
	assert_equals(NULL, temp);

	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));

	free(str_uint64_max);
}
