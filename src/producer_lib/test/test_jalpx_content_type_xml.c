/**
 * @file test_jalpx_content_type_xml.c This file contains unit tests for the
 * functions that convert a jalp_content_type struct to a DOM element.
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
 * distributed under the License is distributed on an "AS IS" BASIS, * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <test-dept.h>

#include <jalop/jalp_context.h>
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jalp_structured_data.h>

#include "jalpx_content_type_xml.h"
#include "jal_alloc.h"
#include "xml2_test_utils.h"

struct jalp_content_type *ct = NULL;

#define SUB_TYPE "subtypeA"
#define P1_NAME "p1_name"
#define P1_VALUE "p1_value"
#define P2_NAME "p2_name"
#define P2_VALUE "p2_value"
#define P3_NAME "p3_name"
#define P3_VALUE "p3_value"

#define CONTENT_TYPE_TAG "Content-Type"
#define PARAMETER_TAG "Parameter"
#define MEDIA_TYPE_ATTR_NAME "MediaType"
#define SUB_TYPE_ATTR_NAME "SubType"
#define NAME_ATTR_NAME "Name"
#define APPLICATION "application"
#define AUDIO "audio"
#define EXAMPLE "example"
#define IMAGE "image"
#define MESSAGE "message"
#define MODEL "model"
#define TEXT "text"
#define VIDEO "video"

xmlDocPtr new_doc;

void setup()
{
	jalp_init();
	ct = jalp_content_type_create();
	ct->media_type = JALP_MT_APPLICATION;
	ct->subtype = jal_strdup(SUB_TYPE);

	ct->params = jalp_param_append(NULL, P1_NAME, P1_VALUE);
	struct jalp_param *tmp_param = jalp_param_append(ct->params, P2_NAME, P2_VALUE);
	jalp_param_append(tmp_param, P3_NAME, P3_VALUE);

	new_doc = xmlNewDoc((xmlChar *)"1.0");
}

void teardown()
{
	jalp_content_type_destroy(&ct);
	xmlFreeDoc(new_doc);
	jalp_shutdown();
}

void test_jalpx_content_type_to_elem_fails_with_bad_input()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_VIDEO;
	enum jal_status ret = jalpx_content_type_to_elem(ct, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jalpx_content_type_to_elem(ct, new_doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jalpx_content_type_to_elem(NULL, new_doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	free(ct->subtype);
	ct->subtype = NULL;
	ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_E_INVAL_CONTENT_TYPE, ret);
	assert_equals(NULL, new_elem);
}

void test_jalpx_content_type_to_elem_fails_with_bad_media_type()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = -1;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_E_INVAL_CONTENT_TYPE, ret);
	assert_equals(NULL, new_elem);

	ct->media_type = 8;
	ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_E_INVAL_CONTENT_TYPE, ret);
	assert_equals(NULL, new_elem);
}

void test_content_type_to_elem_works_with_no_param()
{
	xmlNodePtr new_elem = NULL;

	jalp_param_destroy(&ct->params);

	assert_equals(NULL, ct->params);

        enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);

	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	xmlNodePtr cur_node = NULL;

	assert_equals(1, new_elem != NULL);
	assert_equals(1, new_doc != NULL);
	cur_node = new_doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST CONTENT_TYPE_TAG));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST MEDIA_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST APPLICATION));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST SUB_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST SUB_TYPE));
	xmlFree(ret_val);

	cur_node = cur_node->xmlChildrenNode;
	assert_equals(NULL, cur_node);

	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_content_type_to_elem_fails_with_bad_param()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_VIDEO;
	free(ct->params->key);
	ct->params->key = NULL;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_E_INVAL_PARAM, ret);
	assert_equals(NULL, new_elem);
}


void test_content_type_to_elem_sets_correct_string_for_media_type_application()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_APPLICATION;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	xmlNodePtr cur_node = NULL;

	assert_equals(1, new_elem != NULL);
	assert_equals(1, new_doc != NULL);
	cur_node = new_doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST CONTENT_TYPE_TAG));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST MEDIA_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST APPLICATION));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST SUB_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST SUB_TYPE));
	xmlFree(ret_val);

	cur_node = cur_node->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_VALUE));
	xmlFree(ret_val);
	
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_content_type_to_elem_sets_correct_string_for_media_type_audio()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_AUDIO;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	xmlNodePtr cur_node = NULL;

	assert_equals(1, new_elem != NULL);
	assert_equals(1, new_doc != NULL);
	cur_node = new_doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST CONTENT_TYPE_TAG));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST MEDIA_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST AUDIO));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST SUB_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST SUB_TYPE));
	xmlFree(ret_val);

	cur_node = cur_node->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_VALUE));
	xmlFree(ret_val);
	
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_content_type_to_elem_sets_correct_string_for_media_type_example()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_EXAMPLE;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	xmlNodePtr cur_node = NULL;

	assert_equals(1, new_elem != NULL);
	assert_equals(1, new_doc != NULL);
	cur_node = new_doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST CONTENT_TYPE_TAG));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST MEDIA_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST EXAMPLE));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST SUB_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST SUB_TYPE));
	xmlFree(ret_val);

	cur_node = cur_node->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_VALUE));
	xmlFree(ret_val);
	
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_content_type_to_elem_sets_correct_string_for_media_type_image()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_IMAGE;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	xmlNodePtr cur_node = NULL;

	assert_equals(1, new_elem != NULL);
	assert_equals(1, new_doc != NULL);
	cur_node = new_doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST CONTENT_TYPE_TAG));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST MEDIA_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST IMAGE));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST SUB_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST SUB_TYPE));
	xmlFree(ret_val);

	cur_node = cur_node->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_VALUE));
	xmlFree(ret_val);
	
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_content_type_to_elem_sets_correct_string_for_media_type_message()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_MESSAGE;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	xmlNodePtr cur_node = NULL;

	assert_equals(1, new_elem != NULL);
	assert_equals(1, new_doc != NULL);
	cur_node = new_doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST CONTENT_TYPE_TAG));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST MEDIA_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST MESSAGE));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST SUB_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST SUB_TYPE));
	xmlFree(ret_val);

	cur_node = cur_node->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_VALUE));
	xmlFree(ret_val);

	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_content_type_to_elem_sets_correct_string_for_media_type_model()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_MODEL;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	xmlNodePtr cur_node = NULL;

	assert_equals(1, new_elem != NULL);
	assert_equals(1, new_doc != NULL);
	cur_node = new_doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST CONTENT_TYPE_TAG));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST MEDIA_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST MODEL));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST SUB_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST SUB_TYPE));
	xmlFree(ret_val);

	cur_node = cur_node->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_VALUE));
	xmlFree(ret_val);
	
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_content_type_to_elem_sets_correct_string_for_media_type_text()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_TEXT;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	xmlNodePtr cur_node = NULL;

	assert_equals(1, new_elem != NULL);
	assert_equals(1, new_doc != NULL);
	cur_node = new_doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST CONTENT_TYPE_TAG));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST MEDIA_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST TEXT));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST SUB_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST SUB_TYPE));
	xmlFree(ret_val);

	cur_node = cur_node->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_VALUE));
	xmlFree(ret_val);
	
	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_content_type_to_elem_sets_correct_string_for_media_type_video()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_VIDEO;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *ret_val = NULL;
	xmlNodePtr cur_node = NULL;

	assert_equals(1, new_elem != NULL);
	assert_equals(1, new_doc != NULL);
	cur_node = new_doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST CONTENT_TYPE_TAG));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST MEDIA_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST VIDEO));
	xmlFree(ret_val);
	ret_val = xmlGetProp(cur_node, BAD_CAST SUB_TYPE_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST SUB_TYPE));
	xmlFree(ret_val);

	cur_node = cur_node->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P1_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P2_VALUE));
	xmlFree(ret_val);

	cur_node = cur_node->next;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST PARAMETER_TAG));
	ret_val = xmlGetProp(cur_node, BAD_CAST NAME_ATTR_NAME);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_NAME));
	xmlFree(ret_val);
	ret_val = xmlNodeGetContent(cur_node);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST P3_VALUE));
	xmlFree(ret_val);

	assert_equals(0, validate(new_doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}
