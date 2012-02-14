/**
 * @file test_jalpx_file_info_xml.c This file contains functions to test jalp_file_info_to_elem.
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

#include <test-dept.h>

#include <stdint.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_journal_metadata.h>

#include "jalpx_file_info_xml.h"
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

static xmlDocPtr new_doc = NULL;

static struct jalp_file_info *file_info;

#define FILENAME "somefilename"

void setup()
{
	jalp_init();

	new_doc = xmlNewDoc((xmlChar *)"1.0");

	file_info = jalp_file_info_create();
	// make sure this is a valid file_info
	file_info->filename = jal_strdup(FILENAME);
}

void teardown()
{
	jalp_file_info_destroy(&file_info);

	xmlFreeDoc(new_doc);
	jalp_shutdown();
}

void test_file_info_to_elem_does_not_overwrite_existing_elem_pointer()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jalpx_file_info_to_elem(file_info, new_doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	printf("\nNEW_FILE_INFO\n");
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

