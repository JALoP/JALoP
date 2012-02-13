/**
 * @file test_jalpx_structured_data_xml.cpp This file contains tests for jalp_structured_data_to_elem
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
#include <jalop/jalp_structured_data.h>

#include "jalpx_structured_data_xml.h"
#include "jal_alloc.h"

struct jalp_structured_data *sd = NULL;
xmlDocPtr new_doc = NULL;

#define SD_ID "test-sd-id"
#define SD_ID_ATTR_NAME "SD_ID"
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

void test_jalpx_structured_data_to_elem()
{
	printf("\ntest_jalpx_structured_data_to_elem\n");
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalpx_structured_data_to_elem(sd, new_doc, &new_elem);

	assert_equals(JAL_OK, ret);

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



