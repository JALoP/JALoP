/**
 * @file test_jalpx_param_xml.c This file contains functions to test jalpx_param_to_elem.
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

#include <jalop/jalp_context.h>
#include <jalop/jalp_logger_metadata.h>

#include <libxml/tree.h>

#include "jalpx_param_xml.h"
#include "jal_alloc.h"

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
xmlDocPtr new_doc;

void setup()
{
	jalp_init();
	new_doc = xmlNewDoc((xmlChar *)"1.0");
	param1 = jalp_param_append(NULL, P1_ATTR_VAL, P1_CONTENT);
	param2 = jalp_param_append(param1, P2_ATTR_VAL, P2_CONTENT);
}

void teardown()
{
	jalp_param_destroy(&param1);
	xmlFreeDoc(new_doc);
	jalp_shutdown();
}

void test_jalp_param_to_elem_works()
{
	// Should create
	// <Parameter Name="key2">val2</Parameter>
	xmlNodePtr new_elem = NULL;
	const xmlChar *elem_name = (xmlChar *)P2_TAG;
	const xmlChar *attr_name = (xmlChar *)P2_ATTR;
	enum jal_status ret =
		jalpx_param_to_elem(
			param2,
			elem_name,
			attr_name,
			new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *xmlbuff;
	int buffersize;

	/*
	* Dump the document to a buffer and print it
	* for demonstration purposes.
	*/
	xmlDocDumpFormatMemory(new_doc, &xmlbuff, &buffersize, 1);
	printf("%s", (char *) xmlbuff);

	/*
	* Free associated memory.
	*/
	xmlFree(xmlbuff);
}

void test_jalp_param_to_elem_works_missing_val()
{
	free(param1->value);
	param1->value = NULL;

	// should create
	// <Field Key="key1"/>
	xmlNodePtr new_elem = NULL;
	const xmlChar *elem_name = (xmlChar *)P1_TAG;
	const xmlChar *attr_name = (xmlChar *)P1_ATTR;
	enum jal_status ret =
		jalpx_param_to_elem(
			param1,
			elem_name,
			attr_name,
			new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	xmlChar *xmlbuff;
	int buffersize;

	/*
	* Dump the document to a buffer and print it
	* for demonstration purposes.
	*/
	xmlDocDumpFormatMemory(new_doc, &xmlbuff, &buffersize, 1);
	printf("%s", (char *) xmlbuff);

	/*
	* Free associated memory.
	*/
	xmlFree(xmlbuff);
}
