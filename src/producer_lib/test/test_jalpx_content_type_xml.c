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

struct jalp_content_type *ct = NULL;

#define SUB_TYPE "subtypeA"
#define P1_NAME "p1_name"
#define P1_VALUE "p1_value"
#define P2_NAME "p2_name"
#define P2_VALUE "p2_value"
#define P3_NAME "p3_name"
#define P3_VALUE "p3_value"

#define CONTENT_TYPE_TAG "Content-Type"
#define MEDIA_TYPE_ATTR_NAME "MediaType"
#define SUB_TYPE_ATTR_NAME "SubType"
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

void test_content_type_to_elem_sets_correct_string_for_media_type_video()
{
	xmlNodePtr new_elem = NULL;
	ct->media_type = JALP_MT_VIDEO;
	enum jal_status ret = jalpx_content_type_to_elem(ct, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	xmlDocSetRootElement(new_doc, new_elem);

	printf("\nNEW_CONTENT-TYPE\n");

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
