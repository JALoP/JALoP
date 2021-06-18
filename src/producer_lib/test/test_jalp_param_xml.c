/**
 * @file test_jalp_param_xml.c This file contains functions to test jalp_param_to_elem.
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

#include <jalop/jalp_context.h>
#include <jalop/jalp_logger_metadata.h>

#include <libxml/tree.h>

#include "jalp_param_xml.h"
#include "jal_alloc.h"
#include "xml_test_utils2.h"

#define P1_TAG "Field"
#define P1_ATTR "Key"
#define P1_ATTR_VAL "key1"
#define P1_CONTENT "val1"

#define P2_TAG "Parameter"
#define P2_ATTR "Name"
#define P2_ATTR_VAL "key2"
#define P2_CONTENT "val2"

struct jalp_param *param1 = NULL;
struct jalp_param *param2 = NULL;
xmlDocPtr doc;
xmlNodePtr node;

void setup()
{
	jalp_init();
	doc = xmlNewDoc((xmlChar *)"1.0");
	node = xmlNewNode(NULL, (xmlChar *)"xyz");
	param1 = jalp_param_append(NULL, P1_ATTR_VAL, P1_CONTENT);
	param2 = jalp_param_append(param1, P2_ATTR_VAL, P2_CONTENT);
}

void teardown()
{
	jalp_param_destroy(&param1);
	xmlFreeDoc(doc);
	xmlFreeNode(node);
	jalp_shutdown();
}

void test_param_to_elem_returns_null_with_null_inputs()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(NULL, NULL, NULL, NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);

	ret = jalp_param_to_elem(param2, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, node, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jalp_param_to_elem(param2, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jalp_param_to_elem(param2, (xmlChar *)P1_TAG, NULL, node, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jalp_param_to_elem(param2, NULL, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jalp_param_to_elem(NULL, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);
}

void test_param_to_elem_fails_does_not_overwrite_existing_elm_pointer()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param1, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlNodePtr orig = new_elem;
	ret = jalp_param_to_elem(param1, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
}
void test_param_to_elem_with_bad_inputs_does_not_overwrite_existing_elm_pointer()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param1, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlNodePtr orig = new_elem;
	ret = jalp_param_to_elem(param1, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_param_to_elem(param2, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_param_to_elem(param2, (xmlChar *)P1_TAG, NULL, node, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_param_to_elem(param2, NULL, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_param_to_elem(NULL, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
}
void test_param_to_elem_fails_with_missing_key()
{
	free(param1->key);
	param1->key = NULL;

	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param1, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_E_INVAL_PARAM, ret);
	assert_equals((void*)NULL, new_elem);
}
void test_param_to_elem_works_with_normal_param()
{
	// <Field Key="key1"/>val1</Field>
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param1, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_attr_equals(P1_ATTR, P1_ATTR_VAL, new_elem);
	assert_tag_equals(P1_TAG, new_elem);
	assert_content_equals(P1_CONTENT, new_elem);
	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}
void test_param_to_elem_works_with_normal_param_different_values()
{
	// <Field Key="key1"/>val1</Field>
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param2, (xmlChar *)P2_TAG, (xmlChar *)P2_ATTR, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_attr_equals(P2_ATTR, P2_ATTR_VAL, new_elem);
	assert_tag_equals(P2_TAG, new_elem);
	assert_content_equals(P2_CONTENT, new_elem);
	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_param_to_elem_works_with_missing_value()
{
	free(param1->value);
	param1->value = NULL;
	// should create
	// <Field Key="key1"/>
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param1, (xmlChar *)P1_TAG, (xmlChar *)P1_ATTR, node, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_attr_equals(P1_ATTR, P1_ATTR_VAL, new_elem);
	assert_content_equals(NULL, new_elem);
	assert_tag_equals(P1_TAG, new_elem);
	xmlDocSetRootElement(doc, new_elem);
	// assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

