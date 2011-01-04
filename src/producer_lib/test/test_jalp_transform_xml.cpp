/**
 * @file test_jalp_transform_xml.cpp This file contains tests for
 * jal_transform functions
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
// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// c++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
extern "C" {
#include <test-dept.h>
}

#include "xml_test_utils.hpp"
#include "jalp_transform_xml.hpp"
#include "jal_alloc.h"
#include <jalop/jalp_context.h>

#include <arpa/inet.h>

XERCES_CPP_NAMESPACE_USE

static DOMDocument *doc = NULL;
static DOMImplementation *impl = NULL;
static struct jalp_transform *transform1 = NULL;
static struct jalp_transform *transform2 = NULL;

static XMLCh *namespace_uri = NULL;
static DOMElement *transform_elm = NULL;

static const char *jalp_xml_transform_ch = "Transform";
static XMLCh *xml_transform = NULL;

static std::list<const char*> schemas;

// keys for xor
static uint32_t xor_key = 1234;
static uint32_t net_order_xor_key;
static const char *b64_net_order_xor_key = "AAAE0g==";

// uris for aes
static const char *jalp_xml_aes128_uri_ch = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
static const char *jalp_xml_aes192_uri_ch = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
static const char *jalp_xml_aes256_uri_ch = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

static XMLCh *jalp_xml_aes128_uri = NULL;
static XMLCh *jalp_xml_aes192_uri = NULL;
static XMLCh *jalp_xml_aes256_uri = NULL;

// nodes for aes
static const char *jalp_xml_aes128_ch = "AES128";
static const char *jalp_xml_aes192_ch = "AES192";
static const char *jalp_xml_aes256_ch = "AES256";

static XMLCh *jalp_xml_aes128 = NULL;
static XMLCh *jalp_xml_aes192 = NULL;
static XMLCh *jalp_xml_aes256 = NULL;

// keys for aes
static const char *aes_128_key = "aaaaaaaabbbbbbbb";
static const char *b64_aes_128_key = "YWFhYWFhYWFiYmJiYmJiYg==";

static const char *aes_192_key = "aaaaaaaabbbbbbbbaaaaaaaa";
static const char *b64_aes_192_key = "YWFhYWFhYWFiYmJiYmJiYmFhYWFhYWFh";

static const char *aes_256_key = "aaaaaaaabbbbbbbbaaaaaaaabbbbbbbb";
static const char *b64_aes_256_key = "YWFhYWFhYWFiYmJiYmJiYmFhYWFhYWFhYmJiYmJiYmI=";

// iv for aes
static const char *aes_128_iv = "ccccccccdddddddd";
static const char *b64_aes_128_iv = "Y2NjY2NjY2NkZGRkZGRkZA==";


extern "C" void setup()
{
	jalp_init();

	impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();

	xml_transform = XMLString::transcode(jalp_xml_transform_ch);

	transform1 = jalp_transform_append_other(NULL, "http://uri.com/",
			"<some xmlns='foo:bar'>x</some>");
	transform2 = jalp_transform_append_other(transform1, "http://otheruri.com/",
			"<some2 xmlns='foo:bar'>x</some2>");

	namespace_uri = XMLString::transcode(JAL_APP_META_TYPES_NAMESPACE_URI);
	transform_elm = doc->createElementNS(namespace_uri, xml_transform);

	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);

	net_order_xor_key = htonl(xor_key);

	jalp_xml_aes128_uri = XMLString::transcode(jalp_xml_aes128_uri_ch);
	jalp_xml_aes192_uri = XMLString::transcode(jalp_xml_aes192_uri_ch);
	jalp_xml_aes256_uri = XMLString::transcode(jalp_xml_aes256_uri_ch);

	jalp_xml_aes128 = XMLString::transcode(jalp_xml_aes128_ch);
	jalp_xml_aes192 = XMLString::transcode(jalp_xml_aes192_ch);
	jalp_xml_aes256 = XMLString::transcode(jalp_xml_aes256_ch);
}

extern "C" void teardown()
{
	XMLString::release(&jalp_xml_aes256);
	XMLString::release(&jalp_xml_aes192);
	XMLString::release(&jalp_xml_aes128);

	XMLString::release(&jalp_xml_aes256_uri);
	XMLString::release(&jalp_xml_aes192_uri);
	XMLString::release(&jalp_xml_aes128_uri);

	schemas.clear();

	XMLString::release(&namespace_uri);

	jalp_transform_destroy(&transform1);

	XMLString::release(&xml_transform);

	delete doc;
	jalp_shutdown();
}


/**
 * General tests for transform_to_elem().
 */
extern "C" void test_transform_to_elem_returns_null_with_null_inputs()
{
	DOMElement *new_elem = NULL;
	jal_status ret;

	ret = jalp_transform_to_elem(transform2, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jalp_transform_to_elem(transform2, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jalp_transform_to_elem(NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);
}

extern "C" void test_transform_to_elem_fails_does_not_overwrite_existing_elm_pointer()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret;

	ret = jalp_transform_to_elem(transform2, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	DOMElement *orig = new_elem;
	ret = jalp_transform_to_elem(transform1, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
}

extern "C" void test_transform_to_elem_with_bad_inputs_does_not_overwrite_existing_elm_pointer()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret;

	ret = jalp_transform_to_elem(transform2, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	DOMElement *orig = new_elem;
	ret = jalp_transform_to_elem(transform1, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_transform_to_elem(NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_transform_to_elem(transform1, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_transform_to_elem(transform1, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
}

extern "C" void test_transform_to_elem_fails_with_bad_transform_type()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret;

	enum jalp_transform_type transform_type = transform2->type;
	transform2->type = (enum jalp_transform_type) 1000;

	ret = jalp_transform_to_elem(transform2, doc, &new_elem);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_equals(NULL, new_elem);

	transform2->type = transform_type;
}


/**
 * Tests for jalp_transform_other.
 */
extern "C" void test_transform_to_elem_handle_custom_succeeds_with_xml()
{
	enum jal_status ret;
	DOMElement *child_element = NULL;

	ret = jalp_transform_to_elem_handle_custom(transform_elm, transform1->other_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", transform1->other_info->uri, transform_elm);
	assert_equals(transform_elm->getChildElementCount(), 1);

	child_element = transform_elm->getFirstElementChild();
	assert_not_equals(NULL, child_element);
	assert_tag_equals("some", child_element);
	assert_content_equals("x", child_element);
	assert_equals(child_element->getChildElementCount(), 0);

	doc->appendChild(transform_elm);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_transform_to_elem_handle_custom_succeeds_without_xml()
{
	enum jal_status ret;
	struct jalp_transform_other_info *other_info = NULL;

	// make sure that if there is no xml then it doesn't get added
	other_info = jalp_transform_other_info_create("http://someother.com/url", NULL);

	ret = jalp_transform_to_elem_handle_custom(transform_elm, other_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", other_info->uri, transform_elm);
	assert_equals(transform_elm->getChildElementCount(), 0);

	doc->appendChild(transform_elm);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));

	jalp_transform_other_info_destroy(&other_info);
}

extern "C" void test_transform_to_elem_handle_custom_fails_with_no_other_info()
{
	enum jal_status ret;
	struct jalp_transform_other_info *other_info = NULL;

	ret = jalp_transform_to_elem_handle_custom(transform_elm, NULL);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_not_equals(NULL, transform_elm);

	ret = jalp_transform_to_elem_handle_custom(transform_elm, other_info);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_not_equals(NULL, transform_elm);
}

extern "C" void test_transform_to_elem_handle_custom_fails_with_bad_url()
{
	enum jal_status ret;
	struct jalp_transform_other_info *other_info = NULL;

	// make sure everything works like it is supposed to
	other_info = jalp_transform_other_info_create("not a url", "<some>xml</some>");

	ret = jalp_transform_to_elem_handle_custom(transform_elm, other_info);
	assert_equals(JAL_E_INVAL_URI, ret);
	assert_not_equals(NULL, transform_elm);
	assert_not_equals(NULL, other_info);

	jalp_transform_other_info_destroy(&other_info);
}

extern "C" void test_transform_to_elem_handle_custom_fails_with_bad_xml()
{
	enum jal_status ret;
	struct jalp_transform_other_info *other_info = NULL;

	// make sure everything works like it is supposed to
	other_info = jalp_transform_other_info_create("http://somegoodurl.com/", "<badxml</bad>>");

	ret = jalp_transform_to_elem_handle_custom(transform_elm, other_info);
	assert_equals(JAL_E_XML_PARSE, ret);
	assert_not_equals(NULL, transform_elm);
	assert_not_equals(NULL, other_info);

	jalp_transform_other_info_destroy(&other_info);
}

extern "C" void test_transform_to_elem_succeeds_with_custom()
{
	enum jal_status ret;
	static DOMDocument *doc2 = NULL;
	DOMElement *new_elem = NULL;
	static struct jalp_transform *transform_other = NULL;

	doc2 = impl->createDocument();
	transform_other = jalp_transform_append_other(NULL, "http://uri.com/", NULL);

	ret = jalp_transform_to_elem(transform_other, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", "http://uri.com/", new_elem);
	assert_equals(new_elem->getChildElementCount(), 0);

	doc2->appendChild(new_elem);
	assert_equals(true, validate(doc2, __FUNCTION__, schemas));

	jalp_transform_destroy(&transform_other);
	delete doc2;
}

extern "C" void test_transform_to_elem_fails_with_bad_custom()
{
	enum jal_status ret;
	static DOMDocument *doc2 = NULL;
	DOMElement *new_elem = NULL;
	static struct jalp_transform *transform_other = NULL;

	doc2 = impl->createDocument();
	transform_other = jalp_transform_append_other(NULL, "not a url", NULL);

	ret = jalp_transform_to_elem(transform_other, doc2, &new_elem);
	assert_equals(JAL_E_INVAL_URI, ret);
	assert_equals(NULL, new_elem);

	jalp_transform_destroy(&transform_other);
	delete doc2;
}


/**
 * Tests for jalp_transform_xor.
 */
extern "C" void test_transform_to_elem_handle_xor_succeeds_with_key()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	DOMElement *xor_element = NULL;
	DOMElement *xor_key_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create((uint8_t *) &net_order_xor_key,
			sizeof(net_order_xor_key), NULL, 0);

	ret = jalp_transform_to_elem_handle_xor(doc, transform_elm, namespace_uri, enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			"http://www.dod.mil/algorithms/encryption#xor32-ecb", transform_elm);
	assert_equals(transform_elm->getChildElementCount(), 1);

	xor_element = transform_elm->getFirstElementChild();
	assert_not_equals(NULL, xor_element);
	assert_tag_equals("XOR", xor_element);
	assert_equals(xor_element->getChildElementCount(), 1);

	xor_key_element = xor_element->getFirstElementChild();
	assert_not_equals(NULL, xor_key_element);
	assert_tag_equals("Key", xor_key_element);
	assert_content_equals(b64_net_order_xor_key, xor_key_element);
	assert_equals(xor_key_element->getChildElementCount(), 0);

	doc->appendChild(transform_elm);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));

	jalp_transform_encryption_info_destroy(&enc_info);
}

extern "C" void test_transform_to_elem_handle_xor_fails_with_incorrect_inputs()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;

	// create encryption info with only IV, no key
	enc_info = jalp_transform_encryption_info_create(NULL, 0,
			(uint8_t *) &net_order_xor_key, sizeof(net_order_xor_key));

	ret = jalp_transform_to_elem_handle_xor(doc, transform_elm, namespace_uri, enc_info);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_not_equals(NULL, transform_elm);

	jalp_transform_encryption_info_destroy(&enc_info);


	// create encryption info with both IV and key
	enc_info = jalp_transform_encryption_info_create(
			(uint8_t *) &net_order_xor_key, sizeof(net_order_xor_key),
			(uint8_t *) &net_order_xor_key, sizeof(net_order_xor_key));

	ret = jalp_transform_to_elem_handle_xor(doc, transform_elm, namespace_uri, enc_info);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_not_equals(NULL, transform_elm);

	jalp_transform_encryption_info_destroy(&enc_info);


	// now just pass in null for encryption info
	ret = jalp_transform_to_elem_handle_xor(doc, transform_elm, namespace_uri, NULL);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_not_equals(NULL, transform_elm);
}

extern "C" void test_transform_to_elem_succeeds_with_xor()
{
	enum jal_status ret;
	static DOMDocument *doc2 = NULL;
	DOMElement *new_elem = NULL;
	DOMElement *xor_element = NULL;
	DOMElement *xor_key_element = NULL;
	static struct jalp_transform *transform_xor = NULL;

	doc2 = impl->createDocument();
	transform_xor = jalp_transform_append_xor(NULL, xor_key);

	ret = jalp_transform_to_elem(transform_xor, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			"http://www.dod.mil/algorithms/encryption#xor32-ecb", new_elem);
	assert_equals(new_elem->getChildElementCount(), 1);

	xor_element = new_elem->getFirstElementChild();
	assert_not_equals(NULL, xor_element);
	assert_tag_equals("XOR", xor_element);
	assert_equals(xor_element->getChildElementCount(), 1);

	xor_key_element = xor_element->getFirstElementChild();
	assert_not_equals(NULL, xor_key_element);
	assert_tag_equals("Key", xor_key_element);
	assert_content_equals(b64_net_order_xor_key, xor_key_element);
	assert_equals(xor_key_element->getChildElementCount(), 0);

	doc2->appendChild(new_elem);
	assert_equals(true, validate(doc2, __FUNCTION__, schemas));

	jalp_transform_destroy(&transform_xor);
	delete doc2;
}

/**
 * Tests for jalp_transform_aes
 */
extern "C" void test_transform_to_elem_handle_aes_succeeds_with_no_key_no_iv()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	DOMElement *aes_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create(NULL, 0, NULL, 0);

	ret = jalp_transform_to_elem_handle_aes(doc, transform_elm, namespace_uri,
			jalp_xml_aes128, jalp_xml_aes128_uri, JALP_TRANSFORM_AES128_KEYSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes128_uri_ch, transform_elm);
	// there shouldn't be any child elements if there is no key or iv
	assert_equals(transform_elm->getChildElementCount(), 1);

	aes_element = transform_elm->getFirstElementChild();
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes128_ch, aes_element);
	assert_equals(aes_element->getChildElementCount(), 0);

	doc->appendChild(transform_elm);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));

	jalp_transform_encryption_info_destroy(&enc_info);
}

extern "C" void test_transform_to_elem_handle_aes_succeeds_with_128_key_no_iv()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	DOMElement *aes_element = NULL;
	DOMElement *aes_key_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create((uint8_t *)aes_128_key,
			JALP_TRANSFORM_AES128_KEYSIZE, NULL, 0);

	ret = jalp_transform_to_elem_handle_aes(doc, transform_elm, namespace_uri,
			jalp_xml_aes128, jalp_xml_aes128_uri, JALP_TRANSFORM_AES128_KEYSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes128_uri_ch, transform_elm);
	assert_equals(transform_elm->getChildElementCount(), 1);

	aes_element = transform_elm->getFirstElementChild();
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes128_ch, aes_element);
	assert_equals(aes_element->getChildElementCount(), 1);

	aes_key_element = aes_element->getFirstElementChild();
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_128_key, aes_key_element);
	assert_equals(aes_key_element->getChildElementCount(), 0);

	doc->appendChild(transform_elm);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));

	jalp_transform_encryption_info_destroy(&enc_info);
}

extern "C" void test_transform_to_elem_handle_aes_succeeds_with_192_key_no_iv()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	DOMElement *aes_element = NULL;
	DOMElement *aes_key_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create((uint8_t *)aes_192_key,
			JALP_TRANSFORM_AES192_KEYSIZE, NULL, 0);

	ret = jalp_transform_to_elem_handle_aes(doc, transform_elm, namespace_uri,
			jalp_xml_aes192, jalp_xml_aes192_uri, JALP_TRANSFORM_AES192_KEYSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes192_uri_ch, transform_elm);
	assert_equals(transform_elm->getChildElementCount(), 1);

	aes_element = transform_elm->getFirstElementChild();
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes192_ch, aes_element);
	assert_equals(aes_element->getChildElementCount(), 1);

	aes_key_element = aes_element->getFirstElementChild();
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_192_key, aes_key_element);
	assert_equals(aes_key_element->getChildElementCount(), 0);

	doc->appendChild(transform_elm);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));

	jalp_transform_encryption_info_destroy(&enc_info);
}

extern "C" void test_transform_to_elem_handle_aes_succeeds_with_256_key_no_iv()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	DOMElement *aes_element = NULL;
	DOMElement *aes_key_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create((uint8_t *)aes_256_key,
			JALP_TRANSFORM_AES256_KEYSIZE, NULL, 0);

	ret = jalp_transform_to_elem_handle_aes(doc, transform_elm, namespace_uri,
			jalp_xml_aes256, jalp_xml_aes256_uri, JALP_TRANSFORM_AES256_KEYSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes256_uri_ch, transform_elm);
	assert_equals(transform_elm->getChildElementCount(), 1);

	aes_element = transform_elm->getFirstElementChild();
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes256_ch, aes_element);
	assert_equals(aes_element->getChildElementCount(), 1);

	aes_key_element = aes_element->getFirstElementChild();
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_256_key, aes_key_element);
	assert_equals(aes_key_element->getChildElementCount(), 0);

	doc->appendChild(transform_elm);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));

	jalp_transform_encryption_info_destroy(&enc_info);
}

extern "C" void test_transform_to_elem_handle_aes_succeeds_with_iv_but_no_key()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	DOMElement *aes_element = NULL;
	DOMElement *aes_iv_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create(NULL, 0,
			(uint8_t *)aes_128_iv, JALP_TRANSFORM_AES_IVSIZE);

	ret = jalp_transform_to_elem_handle_aes(doc, transform_elm, namespace_uri,
			jalp_xml_aes128, jalp_xml_aes128_uri, JALP_TRANSFORM_AES_IVSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes128_uri_ch, transform_elm);
	assert_equals(transform_elm->getChildElementCount(), 1);

	aes_element = transform_elm->getFirstElementChild();
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes128_ch, aes_element);
	assert_equals(aes_element->getChildElementCount(), 1);

	aes_iv_element = aes_element->getFirstElementChild();
	assert_not_equals(NULL, aes_iv_element);
	assert_tag_equals("IV", aes_iv_element);
	assert_content_equals(b64_aes_128_iv, aes_iv_element);
	assert_equals(aes_iv_element->getChildElementCount(), 0);

	doc->appendChild(transform_elm);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));

	jalp_transform_encryption_info_destroy(&enc_info);
}

extern "C" void test_transform_to_elem_handle_aes_succeeds_with_key_and_iv()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	DOMElement *aes_element = NULL;
	DOMElement *aes_key_element = NULL;
	DOMElement *aes_iv_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create((uint8_t *)aes_192_key,
			JALP_TRANSFORM_AES192_KEYSIZE, (uint8_t *) aes_128_iv,
			JALP_TRANSFORM_AES_IVSIZE);

	ret = jalp_transform_to_elem_handle_aes(doc, transform_elm, namespace_uri,
			jalp_xml_aes192, jalp_xml_aes192_uri, JALP_TRANSFORM_AES192_KEYSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes192_uri_ch, transform_elm);
	assert_equals(transform_elm->getChildElementCount(), 1);

	aes_element = transform_elm->getFirstElementChild();
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes192_ch, aes_element);
	assert_equals(aes_element->getChildElementCount(), 2);

	aes_key_element = aes_element->getFirstElementChild();
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_192_key, aes_key_element);
	assert_equals(aes_key_element->getChildElementCount(), 0);

	aes_iv_element = aes_key_element->getNextElementSibling();
	assert_not_equals(NULL, aes_iv_element);
	assert_tag_equals("IV", aes_iv_element);
	assert_content_equals(b64_aes_128_iv, aes_iv_element);
	assert_equals(aes_iv_element->getChildElementCount(), 0);

	doc->appendChild(transform_elm);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));

	jalp_transform_encryption_info_destroy(&enc_info);
}

extern "C" void test_transform_to_elem_succeeds_with_128_aes()
{
	enum jal_status ret;
	static DOMDocument *doc2 = NULL;
	static struct jalp_transform *transform_aes = NULL;
	DOMElement *new_elem = NULL;
	DOMElement *aes_element = NULL;
	DOMElement *aes_key_element = NULL;

	doc2 = impl->createDocument();
	transform_aes = jalp_transform_append_aes(NULL, JALP_AES128, (uint8_t *)aes_128_key, NULL);

	ret = jalp_transform_to_elem(transform_aes, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", jalp_xml_aes128_uri_ch, new_elem);
	assert_equals(new_elem->getChildElementCount(), 1);

	aes_element = new_elem->getFirstElementChild();
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes128_ch, aes_element);
	assert_equals(aes_element->getChildElementCount(), 1);

	aes_key_element = aes_element->getFirstElementChild();
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_128_key, aes_key_element);
	assert_equals(aes_key_element->getChildElementCount(), 0);

	doc2->appendChild(new_elem);
	assert_equals(true, validate(doc2, __FUNCTION__, schemas));

	jalp_transform_destroy(&transform_aes);
	delete doc2;
}

extern "C" void test_transform_to_elem_succeeds_with_192_aes()
{
	enum jal_status ret;
	static DOMDocument *doc2 = NULL;
	static struct jalp_transform *transform_aes = NULL;
	DOMElement *new_elem = NULL;
	DOMElement *aes_element = NULL;
	DOMElement *aes_key_element = NULL;

	doc2 = impl->createDocument();
	transform_aes = jalp_transform_append_aes(NULL, JALP_AES192, (uint8_t *)aes_192_key, NULL);

	ret = jalp_transform_to_elem(transform_aes, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", jalp_xml_aes192_uri_ch, new_elem);
	assert_equals(new_elem->getChildElementCount(), 1);

	aes_element = new_elem->getFirstElementChild();
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes192_ch, aes_element);
	assert_equals(aes_element->getChildElementCount(), 1);

	aes_key_element = aes_element->getFirstElementChild();
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_192_key, aes_key_element);
	assert_equals(aes_key_element->getChildElementCount(), 0);

	doc2->appendChild(new_elem);
	assert_equals(true, validate(doc2, __FUNCTION__, schemas));

	jalp_transform_destroy(&transform_aes);
	delete doc2;
}

extern "C" void test_transform_to_elem_succeeds_with_256_aes()
{
	enum jal_status ret;
	static DOMDocument *doc2 = NULL;
	static struct jalp_transform *transform_aes = NULL;
	DOMElement *new_elem = NULL;
	DOMElement *aes_element = NULL;
	DOMElement *aes_key_element = NULL;

	doc2 = impl->createDocument();
	transform_aes = jalp_transform_append_aes(NULL, JALP_AES256, (uint8_t *)aes_256_key, NULL);

	ret = jalp_transform_to_elem(transform_aes, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", jalp_xml_aes256_uri_ch, new_elem);
	assert_equals(new_elem->getChildElementCount(), 1);

	aes_element = new_elem->getFirstElementChild();
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes256_ch, aes_element);
	assert_equals(aes_element->getChildElementCount(), 1);

	aes_key_element = aes_element->getFirstElementChild();
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_256_key, aes_key_element);
	assert_equals(aes_key_element->getChildElementCount(), 0);

	doc2->appendChild(new_elem);
	assert_equals(true, validate(doc2, __FUNCTION__, schemas));

	jalp_transform_destroy(&transform_aes);
	delete doc2;
}


/**
 * Tests for jalp_transform_deflate
 */
extern "C" void test_transform_to_elem_succeeds_with_deflate()
{
	enum jal_status ret;
	static DOMDocument *doc2 = NULL;
	static struct jalp_transform *transform_deflate = NULL;
	DOMElement *new_elem = NULL;

	doc2 = impl->createDocument();
	transform_deflate = jalp_transform_append_deflate(NULL);

	ret = jalp_transform_to_elem(transform_deflate, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			"http://www.dod.mil/algorithms/compression#deflate", new_elem);
	assert_equals(new_elem->getChildElementCount(), 0);

	doc2->appendChild(new_elem);
	assert_equals(true, validate(doc2, __FUNCTION__, schemas));

	jalp_transform_destroy(&transform_deflate);
	delete doc2;
}
