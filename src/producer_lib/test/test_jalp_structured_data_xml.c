/**
 * @file test_jalp_structured_data_xml.c This file contains tests for jalp_structured_data_to_elem
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
#include <jalop/jalp_structured_data.h>

#include "jalp_structured_data_xml.h"
#include "jal_alloc.h"
#include "xml_test_utils2.h"

struct jalp_structured_data *sd = NULL;
xmlDocPtr new_doc = NULL;

#define SD_ID "test-sd-id"
#define SD_ID_ATTR_NAME "SD_ID"
#define KEY_ATTR_NAME "Key"
#define P1_NAME "p1_name"
#define P1_VALUE "p1_value"
#define P2_NAME "p2_name"
#define P2_VALUE "p2_value"
#define P3_NAME "p3_name"
#define P3_VALUE "p3_value"

void setup()
{
	jalp_init();
	sd = jalp_structured_data_append(NULL, SD_ID);
	sd->param_list = jalp_param_append(NULL, P1_NAME, P1_VALUE);
	struct jalp_param *tmp_param = jalp_param_append(sd->param_list, P2_NAME, P2_VALUE);
	jalp_param_append(tmp_param, P3_NAME, P3_VALUE);
	new_doc = xmlNewDoc((xmlChar *)"1.0");
}

void teardown()
{
	jalp_structured_data_destroy(&sd);
	xmlFreeDoc(new_doc);
	jalp_shutdown();
}

void test_jalp_structured_data_to_elem()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalp_structured_data_to_elem(sd, new_doc, &new_elem);

	assert_equals(JAL_OK, ret);
	assert_equals(1, new_elem != NULL);

	xmlDocSetRootElement(new_doc, new_elem);

	xmlNodePtr cur_node = new_doc->xmlChildrenNode;
	xmlChar *ret_val = NULL;
	assert_equals(1, cur_node != NULL);

	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST "StructuredData"));
	ret_val = xmlGetProp(cur_node, BAD_CAST SD_ID_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST SD_ID));
	xmlFree(ret_val);

	cur_node = cur_node->xmlChildrenNode;
	assert_equals(1, cur_node != NULL);
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST "Field"));
	ret_val = xmlGetProp(cur_node, BAD_CAST KEY_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(1, cur_node != NULL);
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST "Field"));
	ret_val = xmlGetProp(cur_node, BAD_CAST KEY_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(1, cur_node != NULL);
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST "Field"));
	ret_val = xmlGetProp(cur_node, BAD_CAST KEY_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_VALUE));
	xmlFree(ret_val);

	xmlDocSetRootElement(new_doc, new_elem);
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}


void test_jalp_structured_data_to_elem_fails_with_bad_params()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jalp_structured_data_to_elem(sd, new_doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, new_doc != NULL);

	ret = jalp_structured_data_to_elem(sd, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, new_elem == NULL);
	assert_equals(1, new_doc != NULL);

	ret = jalp_structured_data_to_elem(NULL, new_doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, new_elem == NULL);
	assert_equals(1, new_doc != NULL);

	free(sd->sd_id);
	sd->sd_id = NULL;
	ret = jalp_structured_data_to_elem(sd, new_doc, &new_elem);
	assert_equals(JAL_E_INVAL_STRUCTURED_DATA, ret);
	assert_equals(1, new_elem == NULL);
	assert_equals(1, new_doc != NULL);
}

void test_jalp_structured_data_to_elem_fails_with_no_param_list()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	struct jalp_structured_data *bad_sd = jalp_structured_data_append(NULL, SD_ID);
	ret = jalp_structured_data_to_elem(bad_sd, new_doc, &new_elem);
	assert_equals(JAL_E_INVAL_STRUCTURED_DATA, ret);
	assert_equals(1, new_doc != NULL);
	assert_equals(1, new_elem == NULL);

	jalp_structured_data_destroy(&bad_sd);

}

void test_jalp_structured_data_to_elem_fails_with_bad_param_list()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	free(sd->param_list->next->key);
	sd->param_list->next->key = NULL;
	ret = jalp_structured_data_to_elem(sd, new_doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, new_doc != NULL);
	assert_equals(1, new_elem == NULL);

}

void test_jalp_structured_data_fails_when_new_elem_already_points_somewhere()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jalp_structured_data_to_elem(sd, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_equals(1, new_elem != NULL);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlNodePtr orig = new_elem;
	ret = jalp_structured_data_to_elem(sd, new_doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

}

void test_jalp_structured_data_fails_doesnt_overwrite_elem_ptr()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jalp_structured_data_to_elem(sd, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_equals(1, new_elem != NULL);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlNodePtr orig = new_elem;

	ret = jalp_structured_data_to_elem(sd, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
	assert_equals(1, new_doc != NULL);

	ret = jalp_structured_data_to_elem(NULL, new_doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
	assert_equals(1, new_doc != NULL);

	free(sd->sd_id);
	sd->sd_id = NULL;
	ret = jalp_structured_data_to_elem(sd, new_doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
	assert_equals(1, new_doc != NULL);
}
