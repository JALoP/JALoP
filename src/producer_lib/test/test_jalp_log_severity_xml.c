/**
 * @file test_jalp_log_severity_xml.c This file contains functions to test jalp_log_severity_to_elem.
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
#include <limits.h>
#include <jalop/jalp_context.h>

#include "jalp_log_severity_xml.h"
#include "jal_alloc.h"
#include "xml_test_utils2.h"

struct jalp_log_severity *severity = NULL;
xmlDocPtr new_doc;

#define LEVEL_NUM 1
#define LEVEL_NAME "test-level"
#define NAME_ATTR_NAME "Name"

void setup()
{
	jalp_init();
	severity = jalp_log_severity_create();
	severity->level_val = LEVEL_NUM;
	severity->level_str = jal_strdup(LEVEL_NAME);

	new_doc = xmlNewDoc((xmlChar *)"1.0");
}

void teardown()
{
	jalp_log_severity_destroy(&severity);
	xmlFreeDoc(new_doc);
	jalp_shutdown();
}

void test_log_severity_to_elem_success()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_log_severity_to_elem(severity, new_doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	assert_equals(1, new_doc != NULL);
	assert_equals(0, xmlStrcmp(new_doc->xmlChildrenNode->name, BAD_CAST "Severity"));
	ret_val = xmlGetProp(new_doc->xmlChildrenNode, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST LEVEL_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(new_doc->xmlChildrenNode);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST "1"));
	xmlFree(ret_val);
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_log_severity_to_elem_works_with_no_level_name()
{
	xmlNodePtr new_elem = NULL;
	free(severity->level_str);
	severity->level_str = NULL;
	enum jal_status ret = jalp_log_severity_to_elem(severity, new_doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	assert_equals(1, new_doc != NULL);
	assert_equals(0, xmlStrcmp(new_doc->xmlChildrenNode->name, BAD_CAST "Severity"));
	ret_val = xmlGetProp(new_doc->xmlChildrenNode, BAD_CAST NAME_ATTR_NAME);
	assert_equals(1, ret_val == NULL);
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(new_doc->xmlChildrenNode);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST "1"));
	xmlFree(ret_val);
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_log_severity_to_elem_works_with_empty_level_name()
{
	xmlNodePtr new_elem = NULL;
	free(severity->level_str);
	severity->level_str = jal_strdup("");;
	enum jal_status ret = jalp_log_severity_to_elem(severity, new_doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	assert_equals(1, new_doc != NULL);
	assert_equals(0, xmlStrcmp(new_doc->xmlChildrenNode->name, BAD_CAST "Severity"));
	ret_val = xmlGetProp(new_doc->xmlChildrenNode, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST ""));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(new_doc->xmlChildrenNode);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST "1"));
	xmlFree(ret_val);
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_log_severity_to_elem_works_with_negative_levels()
{
	severity->level_val = -10;
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_log_severity_to_elem(severity, new_doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	assert_equals(1, new_doc != NULL);
	assert_equals(0, xmlStrcmp(new_doc->xmlChildrenNode->name, BAD_CAST "Severity"));
	ret_val = xmlGetProp(new_doc->xmlChildrenNode, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST LEVEL_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(new_doc->xmlChildrenNode);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST "-10"));
	xmlFree(ret_val);
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_log_severity_to_elem_works_with_int_max()
{
	severity->level_val = INT_MAX;
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_log_severity_to_elem(severity, new_doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	assert_equals(1, new_doc != NULL);
	assert_equals(0, xmlStrcmp(new_doc->xmlChildrenNode->name, BAD_CAST "Severity"));
	ret_val = xmlGetProp(new_doc->xmlChildrenNode, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST LEVEL_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(new_doc->xmlChildrenNode);
	char *max = NULL;
	int check = asprintf(&max, "%d", INT_MAX);
	assert_equals(1, check > 0);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST max));
	xmlFree(ret_val);
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_log_severity_to_elem_works_with_int_min()
{
	severity->level_val = INT_MIN;
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_log_severity_to_elem(severity, new_doc, &new_elem);
	assert_not_equals(NULL, new_elem);
	assert_equals(JAL_OK, ret);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	assert_equals(1, new_doc != NULL);
	assert_equals(0, xmlStrcmp(new_doc->xmlChildrenNode->name, BAD_CAST "Severity"));
	ret_val = xmlGetProp(new_doc->xmlChildrenNode, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST LEVEL_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(new_doc->xmlChildrenNode);

	char *min = NULL;
	int check = asprintf(&min, "%d", INT_MIN);
	assert_equals(1, check > 0);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST min));
	xmlFree(ret_val);
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_log_severity_to_elem_fails_with_bad_input()
{

	xmlNodePtr new_elem = NULL;

	enum jal_status ret = jalp_log_severity_to_elem(severity, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, new_elem == NULL);

	ret = jalp_log_severity_to_elem(severity, new_doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);

	ret = jalp_log_severity_to_elem(NULL, new_doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, new_elem == NULL);

	ret = jalp_log_severity_to_elem(severity, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	xmlNodePtr temp = new_elem;
	ret = jalp_log_severity_to_elem(severity, new_doc, &new_elem);
	assert_equals(temp, new_elem);
        assert_not_equals(JAL_OK, ret);
}
