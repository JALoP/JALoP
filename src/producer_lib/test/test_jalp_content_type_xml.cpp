/**
 * @test_jalp_content_type_xml.cpp This file contains unit tests for the
 * functions that convert a jalp_content_type struct to a DOM element.
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
 * distributed under the License is distributed on an "AS IS" BASIS, * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// c++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
extern "C" {
#include <test-dept.h>
}
#include <jalop/jalp_context.h>
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jalp_structured_data.h>

#include "xml_test_utils.hpp"
#include "jalp_content_type_xml.hpp"
#include "jal_alloc.h"

XERCES_CPP_NAMESPACE_USE
struct jalp_content_type *ct = NULL;
DOMDocument *doc = NULL;
std::list<const char*> schemas;

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

extern "C" void setup()
{
	jalp_init();
	ct = jalp_content_type_create();
	ct->media_type = JALP_MT_APPLICATION;
	ct->subtype = jal_strdup(SUB_TYPE);

	ct->params = jalp_param_append(NULL, P1_NAME, P1_VALUE);
	struct jalp_param *tmp_param = jalp_param_append(ct->params, P2_NAME, P2_VALUE);
	jalp_param_append(tmp_param, P3_NAME, P3_VALUE);

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();

	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);
}

extern "C" void teardown()
{
	jalp_content_type_destroy(&ct);
	delete doc;
	schemas.clear();
	jalp_shutdown();
}

extern "C" void test_content_type_to_elem_fails_with_null_inputs()
{
	enum jal_status ret = jalp_content_type_to_elem(NULL, NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_content_type_to_elem(ct, NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_content_type_to_elem(NULL, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_content_type_to_elem(ct, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);

	DOMElement *new_elm = NULL;
	ret = jalp_content_type_to_elem(NULL, NULL, &new_elm);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_content_type_to_elem(ct, NULL, &new_elm);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_content_type_to_elem(NULL, doc, &new_elm);
	assert_equals(JAL_E_XML_CONVERSION, ret);
}
extern "C" void test_content_type_to_elem_fails_when_new_elem_already_points_somewhere()
{
	DOMElement *new_elem = (DOMElement*) 0x8badf00d;
	enum jal_status ret = jalp_content_type_to_elem(NULL, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)0x8badf00d, new_elem);
	ret = jalp_content_type_to_elem(ct, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)0x8badf00d, new_elem);
	ret = jalp_content_type_to_elem(NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)0x8badf00d, new_elem);
	ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)0x8badf00d, new_elem);
}
extern "C" void test_content_type_to_elem_fails_with_illegal_content_type()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret;

	ct->media_type = static_cast<enum jalp_media_type>(JALP_MT_APPLICATION - 1);
	ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_E_INVAL_CONTENT_TYPE, ret);
	assert_equals((void*)NULL, new_elem);

	ct->media_type = static_cast<enum jalp_media_type>(JALP_MT_VIDEO + 1);
	ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_E_INVAL_CONTENT_TYPE, ret);
	assert_equals((void*)NULL, new_elem);

	ct->media_type = JALP_MT_APPLICATION;
	free(ct->subtype);
	ct->subtype = NULL;
	ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_E_INVAL_CONTENT_TYPE, ret);
	assert_equals((void*)NULL, new_elem);
}

extern "C" void test_content_type_to_elem_fails_when_jalp_param_to_elem_fails()
{
	// jalp_param elements must have a 'key'
	free(ct->params->key);
	ct->params->key = NULL;
	DOMElement *new_elem = NULL;
	enum jal_status ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);
}
extern "C" void test_content_type_to_elem_returns_valid_element()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_tag_equals(CONTENT_TYPE_TAG, new_elem);
	assert_attr_equals(SUB_TYPE_ATTR_NAME, SUB_TYPE, new_elem);

	// make sure there are only 3 params in the list.
	assert_not_equals(NULL, new_elem->getFirstChild());
	assert_not_equals(NULL, new_elem->getFirstChild()->getNextSibling());
	assert_not_equals(NULL, new_elem->getFirstChild()->getNextSibling()->getNextSibling());
	assert_equals((void*) NULL, new_elem->getFirstChild()->getNextSibling()->getNextSibling()->getNextSibling());
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_content_type_to_elem_sets_correct_string_for_media_type_application()
{
	DOMElement *new_elem = NULL;
	ct->media_type = JALP_MT_APPLICATION;
	enum jal_status ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals(MEDIA_TYPE_ATTR_NAME, APPLICATION, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
extern "C" void test_content_type_to_elem_sets_correct_string_for_media_type_audio()
{
	DOMElement *new_elem = NULL;
	ct->media_type = JALP_MT_AUDIO;
	enum jal_status ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals(MEDIA_TYPE_ATTR_NAME, AUDIO, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
extern "C" void test_content_type_to_elem_sets_correct_string_for_media_type_example()
{
	DOMElement *new_elem = NULL;
	ct->media_type = JALP_MT_EXAMPLE;
	enum jal_status ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals(MEDIA_TYPE_ATTR_NAME, EXAMPLE, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
extern "C" void test_content_type_to_elem_sets_correct_string_for_media_type_image()
{
	DOMElement *new_elem = NULL;
	ct->media_type = JALP_MT_IMAGE;
	enum jal_status ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals(MEDIA_TYPE_ATTR_NAME, IMAGE, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
extern "C" void test_content_type_to_elem_sets_correct_string_for_media_type_message()
{
	DOMElement *new_elem = NULL;
	ct->media_type = JALP_MT_MESSAGE;
	enum jal_status ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals(MEDIA_TYPE_ATTR_NAME, MESSAGE, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
extern "C" void test_content_type_to_elem_sets_correct_string_for_media_type_model()
{
	DOMElement *new_elem = NULL;
	ct->media_type = JALP_MT_MODEL;
	enum jal_status ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals(MEDIA_TYPE_ATTR_NAME, MODEL, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
extern "C" void test_content_type_to_elem_sets_correct_string_for_media_type_text()
{
	DOMElement *new_elem = NULL;
	ct->media_type = JALP_MT_TEXT;
	enum jal_status ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals(MEDIA_TYPE_ATTR_NAME, TEXT, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
extern "C" void test_content_type_to_elem_sets_correct_string_for_media_type_video()
{
	DOMElement *new_elem = NULL;
	ct->media_type = JALP_MT_VIDEO;
	enum jal_status ret = jalp_content_type_to_elem(ct, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals(MEDIA_TYPE_ATTR_NAME, VIDEO, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
