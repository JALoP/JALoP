/**
 * @file test_jalp_file_info_xml.c This file contains functions to test jalp_file_info_to_elem.
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

#include <stdint.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_journal_metadata.h>

#include "jalp_file_info_xml.h"
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jal_xml_utils.h"
#include "xml_test_utils2.h"

static xmlDocPtr doc = NULL;

static struct jalp_file_info *file_info;

#define FILENAME "somefilename"

void setup()
{
	jalp_init();

	doc = xmlNewDoc((xmlChar *)"1.0");

	file_info = jalp_file_info_create();
	// make sure this is a valid file_info
	file_info->filename = jal_strdup(FILENAME);
}

void teardown()
{
	jalp_file_info_destroy(&file_info);

	xmlFreeDoc(doc);
	jalp_shutdown();
}

void test_file_info_to_elem_returns_null_with_null_inputs()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jalp_file_info_to_elem(NULL, NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jalp_file_info_to_elem(NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);


	ret = jalp_file_info_to_elem(file_info, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jalp_file_info_to_elem(file_info, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);
}

void test_file_info_to_elem_returns_null_with_no_filename()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	static struct jalp_file_info *bad_file_info;
	bad_file_info = jalp_file_info_create();

	// this should fail, because file_info->filename is NULL
	ret = jalp_file_info_to_elem(bad_file_info, doc, &new_elem);
	assert_equals(JAL_E_INVAL_FILE_INFO, ret);
	assert_equals((void*)NULL, new_elem);

	jalp_file_info_destroy(&bad_file_info);
}

void test_file_info_to_elem_returns_null_with_bad_content_type()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	file_info->content_type = jalp_content_type_create();

	// this should fail, because file_info->content_type->subtype is NULL
	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_E_INVAL_CONTENT_TYPE, ret);
	assert_equals((void*)NULL, new_elem);
}

void test_file_info_to_elem_returns_null_with_bad_threat_level()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	file_info->threat_level = (enum jalp_threat_level) (JAL_THREAT_UNKNOWN - 1);

	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_E_INVAL_FILE_INFO, ret);
	assert_equals((void*)NULL, new_elem);
}

void test_file_info_to_elem_suceeds_with_no_content_type()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	file_info->original_size = 9876;
	file_info->size = 1234;
	file_info->threat_level = JAL_THREAT_SAFE;

	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_tag_equals("FileInfo", new_elem);
	assert_attr_equals("FileName", FILENAME, new_elem);
	assert_attr_equals("OriginalSize", "9876", new_elem);
	assert_attr_equals("Size", "1234", new_elem);
	assert_attr_equals("ThreatLevel", "safe", new_elem);
	
	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_equals((void*)NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_file_info_to_elem_suceeds_with_max_size()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	file_info->original_size = 9876;
	file_info->size = UINT64_MAX;
	file_info->threat_level = JAL_THREAT_SAFE;

	char *size_string = NULL;
	jal_asprintf(&size_string, "%llu", file_info->size);

	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_tag_equals("FileInfo", new_elem);
	assert_attr_equals("FileName", FILENAME, new_elem);
	assert_attr_equals("OriginalSize", "9876", new_elem);
	assert_attr_equals("Size", size_string, new_elem);
	assert_attr_equals("ThreatLevel", "safe", new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_equals((void*)NULL, temp);
	
	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	free(size_string);
}
void test_file_info_to_elem_suceeds_with_max_original_size()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	file_info->original_size = UINT64_MAX;
	file_info->size = 9876;
	file_info->threat_level = JAL_THREAT_SAFE;

	char *original_size_string = NULL;
	jal_asprintf(&original_size_string, "%llu", file_info->original_size);

	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_tag_equals("FileInfo", new_elem);
	assert_attr_equals("FileName", FILENAME, new_elem);
	assert_attr_equals("OriginalSize", original_size_string, new_elem);
	assert_attr_equals("Size", "9876", new_elem);
	assert_attr_equals("ThreatLevel", "safe", new_elem);

	xmlNodePtr temp = jal_get_first_element_child(new_elem);
	assert_equals((void*)NULL, temp);
	
	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	free(original_size_string);
}

void test_file_info_to_elem_suceeds_with_all_threat_levels()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	file_info->threat_level = JAL_THREAT_SAFE;

	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_attr_equals("ThreatLevel", "safe", new_elem);

	xmlFreeNode(new_elem);
	new_elem = NULL;

	file_info->threat_level = JAL_THREAT_UNKNOWN;

	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_attr_equals("ThreatLevel", "unknown", new_elem);

	xmlFreeNode(new_elem);
	new_elem = NULL;

	file_info->threat_level = JAL_THREAT_MALICIOUS;

	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_attr_equals("ThreatLevel", "malicious", new_elem);
}

void test_file_info_to_elem_suceeds_with_content_type()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;
	xmlNodePtr child_element = NULL;

	file_info->original_size = 9876;
	file_info->size = 1234;
	file_info->threat_level = JAL_THREAT_SAFE;
	file_info->content_type = jalp_content_type_create();
	file_info->content_type->subtype = jal_strdup("subtype");

	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_tag_equals("FileInfo", new_elem);
	assert_attr_equals("FileName", FILENAME, new_elem);
	assert_attr_equals("OriginalSize", "9876", new_elem);
	assert_attr_equals("Size", "1234", new_elem);
	assert_attr_equals("ThreatLevel", "safe", new_elem);

	child_element = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, child_element);
	assert_tag_equals("Content-Type", child_element);
	assert_attr_equals("MediaType", "application", child_element);
	assert_attr_equals("SubType", "subtype", child_element);

	child_element = jal_get_first_element_child(child_element);
	assert_equals((void*)NULL, child_element);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_file_info_to_elem_does_not_overwrite_existing_elem_pointer()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	ret = jalp_file_info_to_elem(file_info, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_not_equals(NULL, new_elem);
}
