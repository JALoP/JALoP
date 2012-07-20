/**
 * @file test_jalp_journal_metadata_xml.c This file contains unit tests for
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

#include <jalop/jalp_context.h> // jalp_init

#include <test-dept.h>

#include "jal_alloc.h"
#include "jal_xml_utils.h"
#include "jalp_journal_metadata_xml.h"
#include "xml_test_utils2.h"

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

void test_jalp_journal_metadata_to_elem_returns_error_for_bad_input()
{
	xmlNodePtr bad_elem = (xmlNodePtr) 0xbadf00d;
	enum jal_status ret;
	ret = jalp_journal_metadata_to_elem(NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_journal_metadata_to_elem(jmeta, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_journal_metadata_to_elem(NULL, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_journal_metadata_to_elem(jmeta, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_journal_metadata_to_elem(NULL, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_journal_metadata_to_elem(jmeta, NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_journal_metadata_to_elem(NULL, NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_journal_metadata_to_elem(jmeta, doc, &bad_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_journal_metadata_to_elem(NULL, doc, &bad_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_journal_metadata_to_elem(jmeta, NULL, &bad_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_journal_metadata_to_elem(NULL, NULL, &bad_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
}

void test_jalp_journal_metadata_to_elem_returns_error_when_missing_a_file_info_struct()
{
	enum jal_status ret;
	jalp_file_info_destroy(&jmeta->file_info);
	ret = jalp_journal_metadata_to_elem(jmeta, doc, &new_elem);
	assert_equals(JAL_E_INVAL_FILE_INFO, ret);
}

void test_jalp_journal_metadata_to_elem_fails_when_file_info_to_elem_fails()
{
	enum jal_status ret;
	// can't use test-dept to mock functions when dealing with C++.
	// setting file_name to NULL should cause the file_info_to_elem call
	// to fail.
	free(jmeta->file_info->filename);
	jmeta->file_info->filename = NULL;
	ret = jalp_journal_metadata_to_elem(jmeta, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
}
void test_jalp_journal_metadata_to_elem_returns_valid_elm_with_valid_input()
{
	enum jal_status ret;
	ret = jalp_journal_metadata_to_elem(jmeta, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_tag_equals(JOURNAL_META_TAG, new_elem);
	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	// schema validation checks the tag for us, just make sure there is an
	// element.
	xmlNodePtr file_info = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, file_info);

	// Again, schema validation ensures the structure is correct, just
	// make sure the order of transforms is right.
	xmlNodePtr transforms = file_info->next;
	assert_not_equals(NULL, transforms);

	xmlNodePtr xform1 = jal_get_first_element_child(transforms); 
	assert_not_equals(NULL, xform1);
	assert_attr_equals(ALGORITHM_ATTR, XFORM_ONE_URI, xform1);

	xmlNodePtr xform2 = xform1->next;
	assert_not_equals(NULL, xform2);
	assert_attr_equals(ALGORITHM_ATTR, XFORM_TWO_URI, xform2);
}

void test_jalp_journal_metadata_to_elem_returns_valid_elm_with_no_transforms()
{
	jalp_transform_destroy(&jmeta->transforms);

	enum jal_status ret;
	ret = jalp_journal_metadata_to_elem(jmeta, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_tag_equals(JOURNAL_META_TAG, new_elem);
	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	// schema validation ensures the file_info element is there, just need
	// to make sure there isn't Transforms element.
	xmlNodePtr file_info = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, file_info);
	xmlNodePtr should_be_null = file_info->next;
	assert_equals((void*)NULL, should_be_null);
}

