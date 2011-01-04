/**
 * @file test_jalp_log_severity_xml.cpp This file contains functions to test jalp_log_severity_to_elem.
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
#include <jalop/jalp_context.h>

#include "xml_test_utils.hpp"
#include "jalp_log_severity_xml.hpp"
#include "jal_alloc.h"

XERCES_CPP_NAMESPACE_USE
struct jalp_log_severity *severity = NULL;
DOMDocument *doc = NULL;
DOMElement *new_elem;
XMLCh *expected_name_attr = NULL;
XMLCh *expectedLevelVal = NULL;
std::list<const char*> schemas;

#define LEVEL_NUM 1
#define LEVEL_NAME "test-level"

extern "C" void setup()
{
	jalp_init();
	severity = jalp_log_severity_create();
	severity->level_val = LEVEL_NUM;
	severity->level_str = jal_strdup(LEVEL_NAME);
	expected_name_attr = XMLString::transcode("Name");

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();


	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);
}

extern "C" void teardown()
{
	jalp_log_severity_destroy(&severity);
	delete doc;
	XMLString::release(&expected_name_attr);
	schemas.clear();
	jalp_shutdown();
	new_elem = NULL;
}

extern "C" void test_log_severity_to_elem_returns_error_on_bad_input()
{
	enum jal_status ret = jalp_log_severity_to_elem(NULL, NULL, &new_elem);
	assert_equals(NULL, new_elem);
	assert_not_equals(JAL_OK, ret);

	ret = jalp_log_severity_to_elem(severity, NULL, &new_elem);
	assert_equals(NULL, new_elem);
	assert_not_equals(JAL_OK, ret);

	ret = jalp_log_severity_to_elem(NULL, doc, &new_elem);
	assert_equals(NULL, new_elem);
	assert_not_equals(JAL_OK, ret);

	ret = jalp_log_severity_to_elem(severity, doc, NULL);
	assert_not_equals(JAL_OK, ret);

	jalp_log_severity_to_elem(severity, doc, &new_elem);
	DOMElement *temp = new_elem;
	ret = jalp_log_severity_to_elem(severity, doc, &new_elem);
	assert_equals(temp, new_elem);
	assert_not_equals(JAL_OK, ret);
}

extern "C" void test_log_severity_to_elem_returns_valid_element_when_name_is_not_empty()
{
	enum jal_status ret = jalp_log_severity_to_elem(severity, doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);

	assert_attr_equals("Name", LEVEL_NAME, new_elem);
	assert_equals(LEVEL_NUM, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_log_severity_to_elem_returns_valid_element_when_name_is_empty()
{
	free(severity->level_str);
	severity->level_str = jal_strdup("");
	enum jal_status ret = jalp_log_severity_to_elem(severity, doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);

	assert_attr_equals("Name", "", new_elem);
	assert_equals(LEVEL_NUM, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_log_severity_to_elem_works_when_name_is_null()
{
	free(severity->level_str);
	severity->level_str = NULL;
	enum jal_status ret = jalp_log_severity_to_elem(severity, doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Name", NULL, new_elem);
	assert_equals(LEVEL_NUM, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_log_severity_to_elem_works_with_negative_levels()
{
	severity->level_val = -10;
	enum jal_status ret = jalp_log_severity_to_elem(severity, doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);
	assert_equals(-10, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_log_severity_to_elem_works_with_int_max()
{
	severity->level_val = INT_MAX;
	enum jal_status ret = jalp_log_severity_to_elem(severity, doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);
	assert_equals(INT_MAX, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_log_severity_to_elem_works_with_int_min()
{
	severity->level_val = INT_MIN;
	enum jal_status ret = jalp_log_severity_to_elem(severity, doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);
	assert_equals(INT_MIN, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
