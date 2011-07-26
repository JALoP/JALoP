/**
 * @file test_jal_xml_utils.cpp This file contains unit tests for a
 * variety of utilities dealing with generating XML data.
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
#include <jalop/jal_namespaces.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "jal_alloc.h"
#include "xml_test_utils.hpp"
#include "jal_xml_utils.hpp"
#include "jal_alloc.h"

XERCES_CPP_NAMESPACE_USE

static std::list<const char*> schemas;

static DOMDocument *doc = NULL;

static const char *string = "asdf";
static const char *base64_string = "YXNkZg==";
static XMLCh *tag = NULL;
static struct jal_digest_ctx *dgst_ctx = NULL;

#define ALGORITHM "Algorithm"
#define DIGEST_METHOD "DigestMethod"
#define DIGEST_VALUE "DigestValue"
#define REFERENCE "Reference"
#define URI "URI"

#define EXAMPLE_URI "file:///somefile"
#define EXAMPLE_BAD_URI "bad uri"
#define EXAMPLE_DIGEST_METHOD "some digest method"

#define NAMESPACE "http://foo.org/bar/"
#define COMMENT "This is a comment, but should still show up in the canonicalized document"
#define TAG "sometag"
static const uint8_t EXPECTED_DGST[] = { 0xca, 0x60, 0x88, 0xd0, 0xab,
	0x26, 0x59, 0x66, 0xa7, 0x5b, 0xbf, 0xc2, 0x24, 0xc8, 0xb3,
	0xaa, 0x29, 0x85, 0xcb, 0x67, 0xfb, 0x3d, 0xd8, 0xbf, 0x8d,
	0x48, 0xf0, 0x16, 0xff, 0xfd, 0xf7, 0x76};

#define JALP_TEST_XMLUTILS_TRANSFORMS "Transforms"
#define JALP_TEST_XMLUTILS_TRANSFORM "Transform"
#define JALP_TEST_XMLUTILS_ALGORITHM "Algorithm"
#define JALP_TEST_XMLUTILS_CANON_ALG "http://www.w3.org/2006/12/xml-c14n11#WithComments"


XMLCh *namespace_uri;

extern "C" void setup()
{
	XMLPlatformUtils::Initialize();
	SSL_library_init();

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	namespace_uri = XMLString::transcode(JALP_APP_META_TYPES_NAMESPACE_URI);
	doc = impl->createDocument();

	tag = XMLString::transcode(TAG);

	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);

	dgst_ctx = jal_sha256_ctx_create();
}

static void generate_doc_for_canon() {
	XMLCh* a_xml_namespace = XMLString::transcode(NAMESPACE);
	XMLCh* a_xml_tag = XMLString::transcode(TAG);
	XMLCh* a_xml_comment = XMLString::transcode(COMMENT);

	DOMElement *root = doc->createElementNS(a_xml_namespace, a_xml_tag);
	doc->appendChild(root);
	DOMComment *comment = doc->createComment(a_xml_comment);
	root->appendChild(comment);

	XMLString::release(&a_xml_namespace);
	XMLString::release(&a_xml_tag);
	XMLString::release(&a_xml_comment);
}
extern "C" void teardown()
{
	schemas.clear();
	delete doc;
	jal_digest_ctx_destroy(&dgst_ctx);

	XMLString::release(&tag);
	XMLString::release(&namespace_uri);

	XMLPlatformUtils::Terminate();

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

extern "C" void test_create_base64_element_returns_null_with_null_inputs()
{
	DOMElement *new_elem = NULL;
	jal_status ret;

	ret = create_base64_element(NULL, (uint8_t *) string, strlen(string), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = create_base64_element(doc, NULL, strlen(string), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = create_base64_element(doc, (uint8_t *) string, 0, namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), NULL, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), namespace_uri, NULL, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), namespace_uri, tag, NULL);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);
}

extern "C" void test_create_base64_element_fails_does_not_overwrite_existing_elm_pointer()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret;

	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), namespace_uri, tag, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	DOMElement *orig = new_elem;
	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(orig, new_elem);
}

extern "C" void test_create_base64_element_works_with_normal_value()
{
	// <SomeTag>YXNkZg==</SomeTag>
	DOMElement *new_elem = NULL;
	enum jal_status ret;

	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), namespace_uri, tag, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_tag_equals(TAG, new_elem);
	assert_content_equals(base64_string, new_elem);
	assert_namespace_equals(JALP_APP_META_TYPES_NAMESPACE_URI, new_elem);
}

extern "C" void test_jal_create_reference_elem_returns_null_with_null_inputs()
{
	DOMElement *new_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem(NULL, NULL, NULL, 0, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, NULL,
			(uint8_t *)string, strlen(string), doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, (char *) EXAMPLE_DIGEST_METHOD,
			NULL, strlen(string), doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);
}

extern "C" void test_jal_create_reference_elem_succeeds_with_good_input()
{
	DOMElement *reference_elem = NULL;
	DOMElement *digest_method_elem = NULL;
	DOMElement *digest_value_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)string, strlen(string), doc, &reference_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, reference_elem);
	assert_tag_equals(REFERENCE, reference_elem);
	assert_attr_equals(URI, EXAMPLE_URI, reference_elem);
	assert_equals(reference_elem->getChildElementCount(), 2);

	digest_method_elem = reference_elem->getFirstElementChild();
	assert_not_equals(NULL, digest_method_elem);
	assert_tag_equals(DIGEST_METHOD, digest_method_elem);
	assert_attr_equals(ALGORITHM, EXAMPLE_DIGEST_METHOD, digest_method_elem);

	digest_value_elem = digest_method_elem->getNextElementSibling();
	assert_not_equals(NULL, digest_value_elem);
	assert_tag_equals(DIGEST_VALUE, digest_value_elem);
	assert_content_equals(base64_string, digest_value_elem);

	doc->appendChild(reference_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_jal_create_reference_elem_succeeds_with_no_uri()
{
	DOMElement *reference_elem = NULL;
	DOMElement *digest_method_elem = NULL;
	DOMElement *digest_value_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem(NULL, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)string, strlen(string), doc, &reference_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, reference_elem);
	assert_tag_equals(REFERENCE, reference_elem);
	assert_equals(reference_elem->getChildElementCount(), 2);

	digest_method_elem = reference_elem->getFirstElementChild();
	assert_not_equals(NULL, digest_method_elem);
	assert_tag_equals(DIGEST_METHOD, digest_method_elem);
	assert_attr_equals(ALGORITHM, EXAMPLE_DIGEST_METHOD, digest_method_elem);

	digest_value_elem = digest_method_elem->getNextElementSibling();
	assert_not_equals(NULL, digest_value_elem);
	assert_tag_equals(DIGEST_VALUE, digest_value_elem);
	assert_content_equals(base64_string, digest_value_elem);

	doc->appendChild(reference_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_jal_create_reference_elem_fails_does_not_overwrite_existing_pointer()
{
	DOMElement *reference_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)string, strlen(string), doc, &reference_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, reference_elem);

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)string, strlen(string), doc, &reference_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_not_equals(NULL, reference_elem);
}

extern "C" void test_jal_create_reference_elem_fails_bad_url()
{
	DOMElement *reference_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem((char *) EXAMPLE_BAD_URI, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)string, strlen(string), doc, &reference_elem);
	assert_equals(JAL_E_INVAL_URI, ret);
	assert_equals(NULL, reference_elem);
}

extern "C" void test_jal_digest_xml_data_returns_inval_for_null()
{
	generate_doc_for_canon();
	uint8_t *dgst = NULL;
	int dgst_len = 0;
	enum jal_status ret = jal_digest_xml_data(NULL, NULL, NULL, NULL);

	ret = jal_digest_xml_data(NULL, doc, &dgst, &dgst_len);
	assert_not_equals(ret, JAL_OK);
	assert_equals(dgst, NULL);
	assert_equals(0, dgst_len);

	ret = jal_digest_xml_data(dgst_ctx, NULL, &dgst, &dgst_len);
	assert_not_equals(ret, JAL_OK);
	assert_equals(dgst, NULL);
	assert_equals(0, dgst_len);

	ret = jal_digest_xml_data(dgst_ctx, doc, NULL, &dgst_len);
	assert_not_equals(ret, JAL_OK);
	assert_equals(dgst, NULL);
	assert_equals(0, dgst_len);

	ret = jal_digest_xml_data(dgst_ctx, doc, &dgst, NULL);
	assert_not_equals(ret, JAL_OK);
	assert_equals(dgst, NULL);
	assert_equals(0, dgst_len);
}

extern "C" void test_jal_digest_xml_data_returns_inval_for_bad_digest_ctx()
{
	generate_doc_for_canon();
	uint8_t *dgst = NULL;
	int dgst_len = 0;

	free(dgst_ctx->algorithm_uri);
	dgst_ctx->algorithm_uri = NULL;
	enum jal_status ret = jal_digest_xml_data(dgst_ctx, doc, &dgst, &dgst_len);
	assert_not_equals(ret, JAL_OK);
	assert_equals(dgst, NULL);
	assert_equals(0, dgst_len);

	jal_digest_ctx_destroy(&dgst_ctx);
	dgst_ctx = jal_sha256_ctx_create();
	dgst_ctx->init = NULL;
	ret = jal_digest_xml_data(dgst_ctx, doc, &dgst, &dgst_len);
	assert_not_equals(ret, JAL_OK);
	assert_equals(dgst, NULL);
	assert_equals(0, dgst_len);

}

extern "C" void test_jal_digest_xml_data_returns_inval_for_allocated_dgst_buffer()
{
	generate_doc_for_canon();
	uint8_t *dgst = (uint8_t *)jal_malloc(4);
	uint8_t *tmp = dgst;
	int dgst_len = 0;
	enum jal_status ret = jal_digest_xml_data(dgst_ctx, doc, &dgst, &dgst_len);
	assert_not_equals(ret, JAL_OK);
	assert_equals(dgst, tmp);
	assert_equals(0, dgst_len);
	free(tmp);
}

extern "C" void test_jal_digest_xml_data_canonicalizes_and_digests()
{
	generate_doc_for_canon();
	uint8_t *dgst = NULL;
	int dgst_len = 0;
	enum jal_status ret = jal_digest_xml_data(dgst_ctx, doc, &dgst, &dgst_len);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, dgst);
	assert_not_equals(0, dgst_len);

	assert_equals(32, dgst_len);
	assert_true(0 == memcmp(EXPECTED_DGST, dgst, dgst_len));

	free(dgst);
}

extern "C" void test_jal_create_audit_transforms_elem_null_inputs()
{
	DOMElement *elem = NULL;
	enum jal_status ret;
	ret = jal_create_audit_transforms_elem(NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);

	ret = jal_create_audit_transforms_elem(doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);

	ret = jal_create_audit_transforms_elem(NULL, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
}

extern "C" void test_jal_create_audit_transforms_elem_does_not_overwrite_elem()
{
	DOMElement *elem = (DOMElement *)jal_malloc(4);
	DOMElement *temp = elem;
	enum jal_status ret;
	ret = jal_create_audit_transforms_elem(doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(elem, temp);
	free(elem);
}

extern "C" void test_jal_create_audit_transforms_elem_outputs_correctly()
{
	DOMElement *transforms_elem = NULL;
	DOMElement *temp;
	enum jal_status ret;

	ret = jal_create_audit_transforms_elem(doc, &transforms_elem);
	assert_equals(JAL_OK, ret);

	assert_not_equals(NULL, transforms_elem);
	assert_tag_equals(JALP_TEST_XMLUTILS_TRANSFORMS, transforms_elem);

	temp = transforms_elem->getFirstElementChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(JALP_TEST_XMLUTILS_TRANSFORM, temp);
	assert_attr_equals(JALP_TEST_XMLUTILS_ALGORITHM, JALP_TEST_XMLUTILS_CANON_ALG, temp);

	doc->appendChild(transforms_elem);
	assert_true(validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_jal_xml_output_bad_inputs()
{
	MemBufFormatTarget * buf = NULL;
	enum jal_status ret = JAL_OK;

	ret = jal_xml_output(NULL, NULL);
	assert_equals(JAL_E_INVAL, ret);

	ret = jal_xml_output(doc, NULL);
	assert_equals(JAL_E_INVAL, ret);


	ret = jal_xml_output(NULL, &buf);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((MemBufFormatTarget *)NULL, buf);

	void *temp = jal_malloc(4);
	buf = (MemBufFormatTarget *)temp;

	ret = jal_xml_output(doc, &buf);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((MemBufFormatTarget *)temp, buf);
	free(temp);

}

extern "C" void test_jal_xml_output_good_inputs()
{
	MemBufFormatTarget * buf = NULL;
	enum jal_status ret = jal_xml_output(doc, &buf);
	assert_equals(JAL_OK, ret);
	assert_not_equals((MemBufFormatTarget *)NULL, buf);
	delete buf;
}
