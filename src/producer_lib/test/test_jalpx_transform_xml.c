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

#include <test-dept.h>

#include <jalop/jalp_context.h>

#include "jalpx_transform_xml.h"
#include "jal_alloc.h"
#include "xml2_test_utils.h"

#include <arpa/inet.h>

static xmlDocPtr doc = NULL;
static struct jalp_transform *transform1 = NULL;
static struct jalp_transform *transform2 = NULL;

static xmlChar *namespace_uri = NULL;
static xmlNodePtr transform_elm = NULL;

static const char *jalp_xml_transform_ch = "Transform";
static xmlChar *xml_transform = NULL;

// keys for xor
static uint32_t xor_key = 1234;
static uint32_t net_order_xor_key;
static const char *b64_net_order_xor_key = "AAAE0g==";

// uris for aes
static const char *jalp_xml_aes128_uri_ch = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
static const char *jalp_xml_aes192_uri_ch = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
static const char *jalp_xml_aes256_uri_ch = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";

static xmlChar *jalp_xml_aes128_uri = NULL;
static xmlChar *jalp_xml_aes192_uri = NULL;
static xmlChar *jalp_xml_aes256_uri = NULL;

// nodes for aes
static const char *jalp_xml_aes128_ch = "AES128";
static const char *jalp_xml_aes192_ch = "AES192";
static const char *jalp_xml_aes256_ch = "AES256";

static xmlChar *jalp_xml_aes128 = NULL;
static xmlChar *jalp_xml_aes192 = NULL;
static xmlChar *jalp_xml_aes256 = NULL;

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


void setup()
{
	jalp_init();

	doc = xmlNewDoc((xmlChar *)"1.0");

	xml_transform = (xmlChar *)jalp_xml_transform_ch;

	transform1 = jalp_transform_append_other(NULL, "http://uri.com/",
			"<some xmlns='foo:bar'>x</some>");
	transform2 = jalp_transform_append_other(transform1, "http://otheruri.com/",
			"<some2 xmlns='foo:bar'>x</some2>");

	namespace_uri = (xmlChar *)JAL_APP_META_TYPES_NAMESPACE_URI;
	transform_elm = xmlNewDocNode(doc, NULL, xml_transform, NULL);
	xmlNsPtr ns = xmlNewNs(transform_elm, namespace_uri, NULL);
	xmlSetNs(transform_elm, ns);

	net_order_xor_key = htonl(xor_key);

	jalp_xml_aes128_uri = (xmlChar *)jalp_xml_aes128_uri_ch;
	jalp_xml_aes192_uri = (xmlChar *)jalp_xml_aes192_uri_ch;
	jalp_xml_aes256_uri = (xmlChar *)jalp_xml_aes256_uri_ch;

	jalp_xml_aes128 = (xmlChar *)jalp_xml_aes128_ch;
	jalp_xml_aes192 = (xmlChar *)jalp_xml_aes192_ch;
	jalp_xml_aes256 = (xmlChar *)jalp_xml_aes256_ch;
}

void teardown()
{
	//XMLString::release(&jalp_xml_aes256);
	//XMLString::release(&jalp_xml_aes192);
	//XMLString::release(&jalp_xml_aes128);

	//XMLString::release(&jalp_xml_aes256_uri);
	//XMLString::release(&jalp_xml_aes192_uri);
	//XMLString::release(&jalp_xml_aes128_uri);

	//XMLString::release(&namespace_uri);

	jalp_transform_destroy(&transform1);

	//XMLString::release(&xml_transform);

	xmlFreeDoc(doc);
	jalp_shutdown();
}

/**
 * General tests for transform_to_elem().
 */
void test_transform_to_elem_returns_null_with_null_inputs()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jalpx_transform_to_elem(transform2, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jalpx_transform_to_elem(transform2, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jalpx_transform_to_elem(NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);
}

void test_transform_to_elem_fails_does_not_overwrite_existing_elm_pointer()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jalpx_transform_to_elem(transform2, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlNodePtr orig = new_elem;
	ret = jalpx_transform_to_elem(transform1, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
}

void test_transform_to_elem_with_bad_inputs_does_not_overwrite_existing_elm_pointer()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jalpx_transform_to_elem(transform2, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlNodePtr orig = new_elem;
	ret = jalpx_transform_to_elem(transform1, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalpx_transform_to_elem(NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalpx_transform_to_elem(transform1, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalpx_transform_to_elem(transform1, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
}

void test_transform_to_elem_fails_with_bad_transform_type()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	enum jalp_transform_type transform_type = transform2->type;
	transform2->type = (enum jalp_transform_type) 1000;

	ret = jalpx_transform_to_elem(transform2, doc, &new_elem);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_equals(NULL, new_elem);

	transform2->type = transform_type;
}


/**
 * Tests for jalp_transform_other.
 */
void test_transform_to_elem_handle_custom_succeeds_with_xml()
{
	enum jal_status ret;
	xmlNodePtr child_element = NULL;

	ret = jalpx_transform_to_elem_handle_custom(&transform_elm, transform1->other_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", transform1->other_info->uri, transform_elm);

	child_element = xmlFirstElementChild(transform_elm);
	assert_not_equals(NULL, child_element);
	assert_tag_equals("some", child_element);
	assert_content_equals("x", child_element);

	xmlNodePtr temp = xmlFirstElementChild(child_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, transform_elm);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
}

void test_transform_to_elem_handle_custom_succeeds_without_xml()
{
	enum jal_status ret;
	struct jalp_transform_other_info *other_info = NULL;

	// make sure that if there is no xml then it doesn't get added
	other_info = jalp_transform_other_info_create("http://someother.com/url", NULL);

	ret = jalpx_transform_to_elem_handle_custom(&transform_elm, other_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", other_info->uri, transform_elm);

	xmlNodePtr temp = xmlFirstElementChild(transform_elm);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, transform_elm);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_other_info_destroy(&other_info);
}

void test_transform_to_elem_handle_custom_fails_with_no_other_info()
{
	enum jal_status ret;
	struct jalp_transform_other_info *other_info = NULL;

	ret = jalpx_transform_to_elem_handle_custom(&transform_elm, NULL);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_not_equals(NULL, transform_elm);

	ret = jalpx_transform_to_elem_handle_custom(&transform_elm, other_info);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_not_equals(NULL, transform_elm);
}

void test_transform_to_elem_handle_custom_fails_with_bad_url()
{
	enum jal_status ret;
	struct jalp_transform_other_info *other_info = NULL;

	// make sure everything works like it is supposed to
	other_info = jalp_transform_other_info_create("not a url", "<some>xml</some>");

	ret = jalpx_transform_to_elem_handle_custom(&transform_elm, other_info);
	assert_equals(JAL_E_INVAL_URI, ret);
	assert_not_equals(NULL, transform_elm);
	assert_not_equals(NULL, other_info);

	jalp_transform_other_info_destroy(&other_info);
}

void test_transform_to_elem_handle_custom_fails_with_bad_xml()
{
	enum jal_status ret;
	struct jalp_transform_other_info *other_info = NULL;

	// make sure everything works like it is supposed to
	other_info = jalp_transform_other_info_create("http://somegoodurl.com/", "<badxml</bad>>");

	ret = jalpx_transform_to_elem_handle_custom(&transform_elm, other_info);
	assert_equals(JAL_E_XML_PARSE, ret);
	assert_not_equals(NULL, transform_elm);
	assert_not_equals(NULL, other_info);

	jalp_transform_other_info_destroy(&other_info);
}

void test_transform_to_elem_succeeds_with_custom()
{
	enum jal_status ret;
	static xmlDocPtr doc2 = NULL;
	xmlNodePtr new_elem = NULL;
	static struct jalp_transform *transform_other = NULL;

	doc2 = xmlNewDoc((xmlChar *)"1.0");
	transform_other = jalp_transform_append_other(NULL, "http://uri.com/", NULL);

	ret = jalpx_transform_to_elem(transform_other, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", "http://uri.com/", new_elem);

	xmlNodePtr temp = xmlFirstElementChild(new_elem);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_destroy(&transform_other);
	xmlFreeDoc(doc2);
}

void test_transform_to_elem_fails_with_bad_custom()
{
	enum jal_status ret;
	static xmlDocPtr doc2 = NULL;
	xmlNodePtr new_elem = NULL;
	static struct jalp_transform *transform_other = NULL;

	doc2 = xmlNewDoc((xmlChar *)"1.0");
	transform_other = jalp_transform_append_other(NULL, "not a url", NULL);

	ret = jalpx_transform_to_elem(transform_other, doc2, &new_elem);
	assert_equals(JAL_E_INVAL_URI, ret);
	assert_equals(NULL, new_elem);

	jalp_transform_destroy(&transform_other);
	xmlFreeDoc(doc2);
}

/**
 * Tests for jalp_transform_xor.
 */
void test_transform_to_elem_handle_xor_succeeds_with_key()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	xmlNodePtr xor_element = NULL;
	xmlNodePtr xor_key_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create((uint8_t *) &net_order_xor_key,
			sizeof(net_order_xor_key), NULL, 0);

	ret = jalpx_transform_to_elem_handle_xor(doc, &transform_elm, namespace_uri, enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			"http://www.dod.mil/algorithms/encryption#xor32-ecb", transform_elm);

	xor_element = xmlFirstElementChild(transform_elm);
	assert_not_equals(NULL, xor_element);
	assert_tag_equals("XOR", xor_element);

	xor_key_element = xmlFirstElementChild(xor_element);
	assert_not_equals(NULL, xor_key_element);
	assert_tag_equals("Key", xor_key_element);
	assert_content_equals(b64_net_order_xor_key, xor_key_element);

	xmlNodePtr temp = xmlFirstElementChild(xor_key_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, transform_elm);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_encryption_info_destroy(&enc_info);
}

void test_transform_to_elem_handle_xor_fails_with_incorrect_inputs()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;

	// create encryption info with only IV, no key
	enc_info = jalp_transform_encryption_info_create(NULL, 0,
			(uint8_t *) &net_order_xor_key, sizeof(net_order_xor_key));

	ret = jalpx_transform_to_elem_handle_xor(doc, &transform_elm, namespace_uri, enc_info);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_not_equals(NULL, transform_elm);

	jalp_transform_encryption_info_destroy(&enc_info);


	// create encryption info with both IV and key
	enc_info = jalp_transform_encryption_info_create(
			(uint8_t *) &net_order_xor_key, sizeof(net_order_xor_key),
			(uint8_t *) &net_order_xor_key, sizeof(net_order_xor_key));

	ret = jalpx_transform_to_elem_handle_xor(doc, &transform_elm, namespace_uri, enc_info);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_not_equals(NULL, transform_elm);

	jalp_transform_encryption_info_destroy(&enc_info);


	// now just pass in null for encryption info
	ret = jalpx_transform_to_elem_handle_xor(doc, &transform_elm, namespace_uri, NULL);
	assert_equals(JAL_E_INVAL_TRANSFORM, ret);
	assert_not_equals(NULL, transform_elm);
}

void test_transform_to_elem_succeeds_with_xor()
{
	enum jal_status ret;
	static xmlDocPtr doc2 = NULL;
	xmlNodePtr new_elem = NULL;
	xmlNodePtr xor_element = NULL;
	xmlNodePtr xor_key_element = NULL;
	static struct jalp_transform *transform_xor = NULL;

	doc2 = xmlNewDoc((xmlChar *)"1.0");
	transform_xor = jalp_transform_append_xor(NULL, xor_key);

	ret = jalpx_transform_to_elem(transform_xor, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			"http://www.dod.mil/algorithms/encryption#xor32-ecb", new_elem);

	xor_element = xmlFirstElementChild(new_elem);
	assert_not_equals(NULL, xor_element);
	assert_tag_equals("XOR", xor_element);

	xor_key_element = xmlFirstElementChild(xor_element);
	assert_not_equals(NULL, xor_key_element);
	assert_tag_equals("Key", xor_key_element);
	assert_content_equals(b64_net_order_xor_key, xor_key_element);

	xmlNodePtr temp = xmlFirstElementChild(xor_key_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_destroy(&transform_xor);
	xmlFreeDoc(doc2);
}

/**
 * Tests for jalp_transform_aes
 */
void test_transform_to_elem_handle_aes_succeeds_with_no_key_no_iv()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	xmlNodePtr aes_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create(NULL, 0, NULL, 0);

	ret = jalpx_transform_to_elem_handle_aes(doc, &transform_elm, namespace_uri,
			jalp_xml_aes128, jalp_xml_aes128_uri, JALP_TRANSFORM_AES128_KEYSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes128_uri_ch, transform_elm);
	// there shouldn't be any child elements if there is no key or iv

	aes_element = xmlFirstElementChild(transform_elm);
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes128_ch, aes_element);

	xmlNodePtr temp = xmlFirstElementChild(aes_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, transform_elm);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_encryption_info_destroy(&enc_info);
}

void test_transform_to_elem_handle_aes_succeeds_with_128_key_no_iv()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	xmlNodePtr aes_element = NULL;
	xmlNodePtr aes_key_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create((uint8_t *)aes_128_key,
			JALP_TRANSFORM_AES128_KEYSIZE, NULL, 0);

	ret = jalpx_transform_to_elem_handle_aes(doc, &transform_elm, namespace_uri,
			jalp_xml_aes128, jalp_xml_aes128_uri, JALP_TRANSFORM_AES128_KEYSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes128_uri_ch, transform_elm);

	aes_element = xmlFirstElementChild(transform_elm);
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes128_ch, aes_element);

	aes_key_element = xmlFirstElementChild(aes_element);
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_128_key, aes_key_element);

	xmlNodePtr temp = xmlFirstElementChild(aes_key_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, transform_elm);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_encryption_info_destroy(&enc_info);
}

void test_transform_to_elem_handle_aes_succeeds_with_192_key_no_iv()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	xmlNodePtr aes_element = NULL;
	xmlNodePtr aes_key_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create((uint8_t *)aes_192_key,
			JALP_TRANSFORM_AES192_KEYSIZE, NULL, 0);

	ret = jalpx_transform_to_elem_handle_aes(doc, &transform_elm, namespace_uri,
			jalp_xml_aes192, jalp_xml_aes192_uri, JALP_TRANSFORM_AES192_KEYSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes192_uri_ch, transform_elm);

	aes_element = xmlFirstElementChild(transform_elm);
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes192_ch, aes_element);

	aes_key_element = xmlFirstElementChild(aes_element);
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_192_key, aes_key_element);

	xmlNodePtr temp = xmlFirstElementChild(aes_key_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, transform_elm);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_encryption_info_destroy(&enc_info);
}

void test_transform_to_elem_handle_aes_succeeds_with_256_key_no_iv()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	xmlNodePtr aes_element = NULL;
	xmlNodePtr aes_key_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create((uint8_t *)aes_256_key,
			JALP_TRANSFORM_AES256_KEYSIZE, NULL, 0);

	ret = jalpx_transform_to_elem_handle_aes(doc, &transform_elm, namespace_uri,
			jalp_xml_aes256, jalp_xml_aes256_uri, JALP_TRANSFORM_AES256_KEYSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes256_uri_ch, transform_elm);

	aes_element = xmlFirstElementChild(transform_elm);
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes256_ch, aes_element);

	aes_key_element = xmlFirstElementChild(aes_element);
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_256_key, aes_key_element);

	xmlNodePtr temp = xmlFirstElementChild(aes_key_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, transform_elm);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_encryption_info_destroy(&enc_info);
}

void test_transform_to_elem_handle_aes_succeeds_with_iv_but_no_key()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	xmlNodePtr aes_element = NULL;
	xmlNodePtr aes_iv_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create(NULL, 0,
			(uint8_t *)aes_128_iv, JALP_TRANSFORM_AES_IVSIZE);

	ret = jalpx_transform_to_elem_handle_aes(doc, &transform_elm, namespace_uri,
			jalp_xml_aes128, jalp_xml_aes128_uri, JALP_TRANSFORM_AES_IVSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes128_uri_ch, transform_elm);

	aes_element = xmlFirstElementChild(transform_elm);
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes128_ch, aes_element);

	aes_iv_element = xmlFirstElementChild(aes_element);
	assert_not_equals(NULL, aes_iv_element);
	assert_tag_equals("IV", aes_iv_element);
	assert_content_equals(b64_aes_128_iv, aes_iv_element);

	xmlNodePtr temp = xmlFirstElementChild(aes_iv_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, transform_elm);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_encryption_info_destroy(&enc_info);
}

void test_transform_to_elem_handle_aes_succeeds_with_key_and_iv()
{
	enum jal_status ret;
	struct jalp_transform_encryption_info *enc_info = NULL;
	xmlNodePtr aes_element = NULL;
	xmlNodePtr aes_key_element = NULL;
	xmlNodePtr aes_iv_element = NULL;

	// make sure everything works like it is supposed to
	enc_info = jalp_transform_encryption_info_create((uint8_t *)aes_192_key,
			JALP_TRANSFORM_AES192_KEYSIZE, (uint8_t *) aes_128_iv,
			JALP_TRANSFORM_AES_IVSIZE);

	ret = jalpx_transform_to_elem_handle_aes(doc, &transform_elm, namespace_uri,
			jalp_xml_aes192, jalp_xml_aes192_uri, JALP_TRANSFORM_AES192_KEYSIZE,
			enc_info);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			jalp_xml_aes192_uri_ch, transform_elm);

	aes_element = xmlFirstElementChild(transform_elm);
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes192_ch, aes_element);

	aes_key_element = xmlFirstElementChild(aes_element);
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_192_key, aes_key_element);

	aes_iv_element = aes_key_element->next;
	assert_not_equals(NULL, aes_iv_element);
	assert_tag_equals("IV", aes_iv_element);
	assert_content_equals(b64_aes_128_iv, aes_iv_element);

	xmlNodePtr temp = xmlFirstElementChild(aes_iv_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, transform_elm);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_encryption_info_destroy(&enc_info);
}

void test_transform_to_elem_succeeds_with_128_aes()
{
	enum jal_status ret;
	static xmlDocPtr doc2 = NULL;
	static struct jalp_transform *transform_aes = NULL;
	xmlNodePtr new_elem = NULL;
	xmlNodePtr aes_element = NULL;
	xmlNodePtr aes_key_element = NULL;

	doc2 = xmlNewDoc((xmlChar *)"1.0");
	transform_aes = jalp_transform_append_aes(NULL, JALP_AES128, (uint8_t *)aes_128_key, NULL);

	ret = jalpx_transform_to_elem(transform_aes, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", jalp_xml_aes128_uri_ch, new_elem);

	aes_element = xmlFirstElementChild(new_elem);
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes128_ch, aes_element);

	aes_key_element = xmlFirstElementChild(aes_element);
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_128_key, aes_key_element);

	xmlNodePtr temp = xmlFirstElementChild(aes_key_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_destroy(&transform_aes);
	xmlFreeDoc(doc2);
}

void test_transform_to_elem_succeeds_with_192_aes()
{
	enum jal_status ret;
	static xmlDocPtr doc2 = NULL;
	static struct jalp_transform *transform_aes = NULL;
	xmlNodePtr new_elem = NULL;
	xmlNodePtr aes_element = NULL;
	xmlNodePtr aes_key_element = NULL;

	doc2 = xmlNewDoc((xmlChar *)"1.0");
	transform_aes = jalp_transform_append_aes(NULL, JALP_AES192, (uint8_t *)aes_192_key, NULL);

	ret = jalpx_transform_to_elem(transform_aes, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", jalp_xml_aes192_uri_ch, new_elem);

	aes_element = xmlFirstElementChild(new_elem);
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes192_ch, aes_element);

	aes_key_element = xmlFirstElementChild(aes_element);
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_192_key, aes_key_element);

	xmlNodePtr temp = xmlFirstElementChild(aes_key_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_destroy(&transform_aes);
	xmlFreeDoc(doc2);
}

void test_transform_to_elem_succeeds_with_256_aes()
{
	enum jal_status ret;
	static xmlDocPtr doc2 = NULL;
	static struct jalp_transform *transform_aes = NULL;
	xmlNodePtr new_elem = NULL;
	xmlNodePtr aes_element = NULL;
	xmlNodePtr aes_key_element = NULL;

	doc2 = xmlNewDoc((xmlChar *)"1.0");
	transform_aes = jalp_transform_append_aes(NULL, JALP_AES256, (uint8_t *)aes_256_key, NULL);

	ret = jalpx_transform_to_elem(transform_aes, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm", jalp_xml_aes256_uri_ch, new_elem);

	aes_element = xmlFirstElementChild(new_elem);
	assert_not_equals(NULL, aes_element);
	assert_tag_equals(jalp_xml_aes256_ch, aes_element);

	aes_key_element = xmlFirstElementChild(aes_element);
	assert_not_equals(NULL, aes_key_element);
	assert_tag_equals("Key", aes_key_element);
	assert_content_equals(b64_aes_256_key, aes_key_element);

	xmlNodePtr temp = xmlFirstElementChild(aes_key_element);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_destroy(&transform_aes);
	xmlFreeDoc(doc2);
}


/**
 * Tests for jalp_transform_deflate
 */
void test_transform_to_elem_succeeds_with_deflate()
{
	enum jal_status ret;
	static xmlDocPtr doc2 = NULL;
	static struct jalp_transform *transform_deflate = NULL;
	xmlNodePtr new_elem = NULL;

	doc2 = xmlNewDoc((xmlChar *)"1.0");
	transform_deflate = jalp_transform_append_deflate(NULL);

	ret = jalpx_transform_to_elem(transform_deflate, doc2, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_attr_equals("Algorithm",
			"http://www.dod.mil/algorithms/compression#deflate", new_elem);
	
	xmlNodePtr temp = xmlFirstElementChild(new_elem);
	assert_equals(NULL, temp);

	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	jalp_transform_destroy(&transform_deflate);
	xmlFreeDoc(doc2);
}
