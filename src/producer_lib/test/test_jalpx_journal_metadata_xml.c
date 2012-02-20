/**
 * @file test_jalp_journal_metadata_xml.cpp This file contains unit tests for
 * converting the jalp_journal_metadata structure to a DOMElement
 * converting journal metadata to XML.
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

#include <jalop/jalp_context.h> // jalp_init

#include <test-dept.h>

#include "jal_alloc.h"
#include "jalpx_journal_metadata_xml.h"

static xmlDocPtr doc = NULL;
static xmlNodePtr new_elem = NULL;
static struct jalp_journal_metadata *jmeta = NULL;

#define JOURNAL_META_TAG "JournalMetadata"
#define ALGORITHM_ATTR "Algorithm"
#define XFORM_ONE_URI "schemaone:foobar"
#define XFORM_TWO_URI "schematwo:foobar"

void setup()
{
	jalp_init();
	jmeta = jalp_journal_metadata_create();
	jmeta->file_info = jalp_file_info_create();

	jmeta->file_info->original_size = 1024;
	jmeta->file_info->size = 512;
	jmeta->file_info->filename = jal_strdup(__FILE__);

	jmeta->transforms = jalp_transform_append_other(NULL, XFORM_ONE_URI, NULL);
	jalp_transform_append_other(jmeta->transforms, XFORM_TWO_URI, NULL);

	doc =  xmlNewDoc((xmlChar *)"1.0");
}

void teardown()
{
	jalp_journal_metadata_destroy(&jmeta);
	new_elem = NULL;
	xmlFreeDoc(doc);
	jalp_shutdown();
}

void test_jalp_journal_metadata_to_elem_returns_valid_elm_with_valid_input()
{
	printf("\nNEW_JOURNAL_METADATA\n");
	enum jal_status ret;
	ret = jalpx_journal_metadata_to_elem(jmeta, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlDocSetRootElement(doc, new_elem);

	xmlChar *xmlbuff;
	int buffersize;

	/*
	* Dump the document to a buffer and print it
	* for demonstration purposes.
	*/
	xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);
	printf("%s", (char *) xmlbuff);

	/*
	* Free associated memory.
	*/
	xmlFree(xmlbuff);

}

