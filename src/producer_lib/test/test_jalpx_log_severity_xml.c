/**
 * @file test_jalpx_log_severity_xml.c This file contains functions to test jalp_log_severity_to_elem.
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

#include "jalpx_log_severity_xml.h"
#include "jal_alloc.h"

struct jalp_log_severity *severity = NULL;
xmlDocPtr new_doc;

#define LEVEL_NUM 1
#define LEVEL_NAME "test-level"

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

void test_log_severity_to_elem_works_with_negative_levels()
{
	printf("\nnegative_levels\n");
	severity->level_val = -10;
	xmlNodePtr new_elem = NULL;
	enum jal_status ret = jalpx_log_severity_to_elem(severity, new_doc, &new_elem);
	assert_not_equals(NULL, new_elem);
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

