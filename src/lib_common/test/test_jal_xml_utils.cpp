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
#include <xsec/framework/XSECException.hpp>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "jal_alloc.h"
#include "xml_test_utils.hpp"
#include "jal_xml_utils.hpp"
#include "jal_alloc.h"

XERCES_CPP_NAMESPACE_USE

#define EVENT_ID "event-123-xyz"

#define TEST_RSA_KEY  TEST_INPUT_ROOT "rsa_key"
#define TEST_CERT  TEST_INPUT_ROOT "cert"
#define TEST_CERT_AND_KEY  TEST_INPUT_ROOT "cert_and_key"

#define ID_NAME "xml:" LOCLA_ID_NAME
#define LOCAL_ID_NAME "id"
#define ID_NS "http://www.w3.org/XML/1998/namespace"

#define TRANSFORM "Transform"
#define TRANSFORMS "Transforms"
#define CANON_ALG "http://www.w3.org/2006/12/xml-c14n11#WithComments"
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

#define ID_STR "foobar_123444"
#define XPOINTER_ID_STR "#xpointer(id('" ID_STR "'))"

#define EXPECTED_SIGNING_DGST_VALUE "Tv+xVpQnAxQYuhWNG8hG2zBXRG5Z5kThWM5UGEaA/jQ="
#define EXPECTED_MODULUS "3PRI+qegjHCd70xtRMPzknUDqY6iH93XJwfuGqXguiEB8n3dxaZu1ZNzMe1BHpGje2RPaRr5EXBK\nAXMPnw6MXQ=="
#define EXPECTED_EXPONENT "AQAB"
static DOMDocument *doc = NULL;

static const char *base64_input_str = "asdf";
static const char *base64_string = "YXNkZg==";
static XMLCh *tag = NULL;
static struct jal_digest_ctx *dgst_ctx = NULL;

static X509 *cert;
static RSA *key;


static XMLCh *id_val = NULL;

static const uint8_t EXPECTED_DGST[] = { 0xca, 0x60, 0x88, 0xd0, 0xab,
	0x26, 0x59, 0x66, 0xa7, 0x5b, 0xbf, 0xc2, 0x24, 0xc8, 0xb3,
	0xaa, 0x29, 0x85, 0xcb, 0x67, 0xfb, 0x3d, 0xd8, 0xbf, 0x8d,
	0x48, 0xf0, 0x16, 0xff, 0xfd, 0xf7, 0x76};



XMLCh *namespace_uri;

std::list<const char*> schemas;
void load_key_and_cert()
{
	FILE *fp;
	fp = fopen(TEST_CERT, "r");
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	fp = fopen(TEST_RSA_KEY, "r");
	key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
}

static void build_dom_for_signing()
{
	XMLCh *ns = XMLString::transcode(NAMESPACE);
	XMLCh *elem = XMLString::transcode("elem1");
	XMLCh *achild = XMLString::transcode("achild");
	XMLCh *bchild = XMLString::transcode("bchild");
	XMLCh *id_name = XMLString::transcode("xml:id");
	XMLCh *local_id_name = XMLString::transcode("id");
	XMLCh *id_ns = XMLString::transcode(ID_NS);
	DOMElement *root_elem = doc->createElementNS(ns, elem);
	root_elem->setAttributeNS(id_ns, id_name, id_val);
	root_elem->setIdAttributeNS(id_ns, local_id_name, true);

	DOMElement *achild_elem = doc->createElementNS(ns, achild);
	DOMElement *bchild_elem = doc->createElementNS(ns, bchild);
	root_elem->appendChild(achild_elem);
	root_elem->appendChild(bchild_elem);
	doc->appendChild(root_elem);
	XMLString::release(&ns);
	XMLString::release(&elem);
	XMLString::release(&achild);
	XMLString::release(&bchild);
	XMLString::release(&id_name);
	XMLString::release(&local_id_name);
	XMLString::release(&id_ns);
}
extern "C" void setup()
{
	XMLPlatformUtils::Initialize();
#ifndef XSEC_NO_XALAN
	XalanTransformer::initialize();
#endif
	XSECPlatformUtils::Initialise();

	SSL_library_init();

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	namespace_uri = XMLString::transcode(JAL_APP_META_TYPES_NAMESPACE_URI);
	id_val = XMLString::transcode(ID_STR);
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
	XMLString::release(&id_val);

	XMLPlatformUtils::Terminate();
#ifndef XSEC_NO_XALAN
	XalanTransformer::terminate();
#endif
	XMLPlatformUtils::Terminate();

	X509_free(cert);
	RSA_free(key);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

extern "C" void test_jal_create_base64_element_returns_null_with_null_inputs()
{
	DOMElement *new_elem = NULL;
	jal_status ret;

	ret = jal_create_base64_element(NULL, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_base64_element(doc, NULL, strlen(base64_input_str), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, 0, namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), NULL, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, NULL, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, tag, NULL);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);
}

extern "C" void test_jal_create_base64_element_fails_does_not_overwrite_existing_elm_pointer()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret;

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, tag, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	DOMElement *orig = new_elem;
	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(orig, new_elem);
}

extern "C" void test_jal_create_base64_element_works_with_normal_value()
{
	// <SomeTag>YXNkZg==</SomeTag>
	DOMElement *new_elem = NULL;
	enum jal_status ret;

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, tag, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_tag_equals(TAG, new_elem);
	assert_content_equals(base64_string, new_elem);
	assert_namespace_equals(JAL_APP_META_TYPES_NAMESPACE_URI, new_elem);
}

extern "C" void test_jal_create_reference_elem_returns_null_with_null_inputs()
{
	DOMElement *new_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem(NULL, NULL, NULL, 0, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, NULL,
			(uint8_t *)base64_input_str, strlen(base64_input_str), doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, (char *) EXAMPLE_DIGEST_METHOD,
			NULL, strlen(base64_input_str), doc, &new_elem);
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
			(uint8_t *)base64_input_str, strlen(base64_input_str), doc, &reference_elem);
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
			(uint8_t *)base64_input_str, strlen(base64_input_str), doc, &reference_elem);
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
			(uint8_t *)base64_input_str, strlen(base64_input_str), doc, &reference_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, reference_elem);

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)base64_input_str, strlen(base64_input_str), doc, &reference_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_not_equals(NULL, reference_elem);
}

extern "C" void test_jal_create_reference_elem_fails_bad_url()
{
	DOMElement *reference_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem((char *) EXAMPLE_BAD_URI, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)base64_input_str, strlen(base64_input_str), doc, &reference_elem);
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
	assert_tag_equals(TRANSFORMS, transforms_elem);

	temp = transforms_elem->getFirstElementChild();
	assert_not_equals(NULL, temp);
	assert_tag_equals(TRANSFORM, temp);
	assert_attr_equals(ALGORITHM, CANON_ALG, temp);

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

extern "C" void test_add_signature_block()
{
	enum jal_status ret = JAL_OK;
	load_key_and_cert();
	build_dom_for_signing();

	assert_not_equals((void *) NULL, cert);
	assert_not_equals((void *) NULL, key);

	// sign document
	ret = jal_add_signature_block(key, cert, doc, doc->getDocumentElement(), NULL, id_val);
	assert_equals(JAL_OK, ret);

	//make sure the signature got added in the right place
	DOMElement *sig_node = doc->getDocumentElement()->getLastElementChild();
	assert_not_equals((void*) NULL, sig_node);
	assert_tag_equals("ds:Signature", sig_node);

	DOMElement *signed_info = sig_node->getFirstElementChild();
	assert_not_equals((void*) NULL, signed_info);
	assert_tag_equals("ds:SignedInfo", signed_info);

	DOMElement *canon_method = signed_info->getFirstElementChild();
	assert_not_equals((void*) NULL, canon_method);
	assert_tag_equals("ds:CanonicalizationMethod", canon_method);

	DOMElement *sig_method = canon_method->getNextElementSibling();
	assert_not_equals((void*) NULL, sig_method);
	assert_tag_equals("ds:SignatureMethod", sig_method);

	// check the reference element...
	DOMElement *ref_elem = sig_method->getNextElementSibling();
	assert_not_equals((void*) NULL, ref_elem);
	assert_tag_equals("ds:Reference", ref_elem);
	assert_attr_equals("URI", XPOINTER_ID_STR, ref_elem);

	DOMElement *xforms = ref_elem->getFirstElementChild();
	assert_not_equals((void*) NULL, xforms);
	assert_tag_equals("ds:Transforms", xforms);

	DOMElement *xform = xforms->getFirstElementChild();
	assert_not_equals((void*) NULL, xform);
	assert_tag_equals("ds:Transform", xform);
	assert_attr_equals("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", xform);
	xform = xform->getNextElementSibling();
	assert_equals((void*) NULL, xform);

	DOMElement *dgst_method = xforms->getNextElementSibling();
	assert_not_equals((void*) NULL, dgst_method);
	assert_tag_equals("ds:DigestMethod", dgst_method);
	assert_attr_equals("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256", dgst_method);

	DOMElement *dgst_value = dgst_method->getNextElementSibling();
	assert_not_equals((void*) NULL, dgst_value);
	assert_tag_equals("ds:DigestValue", dgst_value);
	assert_content_equals(EXPECTED_SIGNING_DGST_VALUE, dgst_value);

	DOMElement *sig_value = signed_info->getNextElementSibling();
	assert_not_equals((void*) NULL, sig_value);
	assert_tag_equals("ds:SignatureValue", sig_value);

	DOMElement *key_info = sig_value->getNextElementSibling();
	assert_not_equals((void*) NULL, key_info);
	assert_tag_equals("ds:KeyInfo", key_info);

	DOMElement *key_val = key_info->getFirstElementChild();
	assert_not_equals((void*) NULL, key_val);
	assert_tag_equals("ds:KeyValue", key_val);

	DOMElement *rsa_key_val = key_val->getFirstElementChild();
	assert_not_equals((void*) NULL, rsa_key_val);
	assert_tag_equals("ds:RSAKeyValue", rsa_key_val);

	DOMElement *modulus = rsa_key_val->getFirstElementChild();
	assert_not_equals((void*) NULL, modulus);
	assert_tag_equals("ds:Modulus", modulus);
	assert_content_equals(EXPECTED_MODULUS, modulus);
	
	DOMElement *exponent = modulus->getNextElementSibling();
	assert_not_equals((void*) NULL, exponent);
	assert_tag_equals("ds:Exponent", exponent);
	assert_content_equals(EXPECTED_EXPONENT, exponent);

	DOMElement *x509_data = key_val->getNextElementSibling();
	assert_not_equals((void*) NULL, x509_data);
	assert_tag_equals("ds:X509Data", x509_data);

	DOMElement *x509_subject = x509_data->getFirstElementChild();
	assert_not_equals((void*) NULL, x509_subject);
	assert_tag_equals("ds:X509SubjectName", x509_subject);
	assert_content_equals("C=US, ST=MD, L=Columbia, CN=www.tresys.com", x509_subject);

	DOMElement *x509_serial = x509_subject->getNextElementSibling();
	assert_not_equals((void*) NULL, x509_serial);
	assert_tag_equals("ds:X509IssuerSerial", x509_serial);

	DOMElement *x509_issuer = x509_serial->getFirstElementChild();
	assert_not_equals((void*) NULL, x509_issuer);
	assert_tag_equals("ds:X509IssuerName", x509_issuer);
	assert_content_equals("C=US, ST=MD, L=Columbia, CN=www.tresys.com", x509_issuer);

	DOMElement *x509_number = x509_issuer->getNextElementSibling();
	assert_not_equals((void*) NULL, x509_number);
	assert_tag_equals("ds:X509SerialNumber", x509_number);
	assert_content_equals("17415892367561384562", x509_number);

	DOMElement *x509_cert = x509_serial->getNextElementSibling();
	assert_not_equals((void*) NULL, x509_cert);
	assert_tag_equals("ds:X509Certificate", x509_cert);
}

extern "C" void test_add_signature_block_works_with_prev()
{
	enum jal_status ret;
	load_key_and_cert();
	build_dom_for_signing();

	assert_not_equals((void *) NULL, cert);
	assert_not_equals((void *) NULL, key);

	// sign document
	ret = jal_add_signature_block(key, cert, doc, doc->getDocumentElement(),
			doc->getDocumentElement()->getLastElementChild(), id_val);
	assert_equals(JAL_OK, ret);

	//make sure the signature got added in the right place, it should be
	//right before the 'belemnt' child.
	DOMElement *elm2 = doc->getDocumentElement()->getLastElementChild();
	assert_not_equals((void*) NULL, elm2);
	assert_tag_equals("bchild", elm2);

	DOMElement *sig_node = elm2->getPreviousElementSibling();
	assert_not_equals((void*) NULL, sig_node);
	assert_tag_equals("ds:Signature", sig_node);

	DOMElement *signed_info = sig_node->getFirstElementChild();
	assert_not_equals((void*) NULL, signed_info);
	assert_tag_equals("ds:SignedInfo", signed_info);

	DOMElement *canon_method = signed_info->getFirstElementChild();
	assert_not_equals((void*) NULL, canon_method);
	assert_tag_equals("ds:CanonicalizationMethod", canon_method);

	DOMElement *sig_method = canon_method->getNextElementSibling();
	assert_not_equals((void*) NULL, sig_method);
	assert_tag_equals("ds:SignatureMethod", sig_method);

	// check the reference element...
	DOMElement *ref_elem = sig_method->getNextElementSibling();
	assert_not_equals((void*) NULL, ref_elem);
	assert_tag_equals("ds:Reference", ref_elem);
	assert_attr_equals("URI", XPOINTER_ID_STR, ref_elem);

	DOMElement *xforms = ref_elem->getFirstElementChild();
	assert_not_equals((void*) NULL, xforms);
	assert_tag_equals("ds:Transforms", xforms);

	DOMElement *xform = xforms->getFirstElementChild();
	assert_not_equals((void*) NULL, xform);
	assert_tag_equals("ds:Transform", xform);
	assert_attr_equals("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", xform);
	xform = xform->getNextElementSibling();
	assert_equals((void*) NULL, xform);

	DOMElement *dgst_method = xforms->getNextElementSibling();
	assert_not_equals((void*) NULL, dgst_method);
	assert_tag_equals("ds:DigestMethod", dgst_method);
	assert_attr_equals("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256", dgst_method);

	DOMElement *dgst_value = dgst_method->getNextElementSibling();
	assert_not_equals((void*) NULL, dgst_value);
	assert_tag_equals("ds:DigestValue", dgst_value);
	assert_content_equals(EXPECTED_SIGNING_DGST_VALUE, dgst_value);

	DOMElement *sig_value = signed_info->getNextElementSibling();
	assert_not_equals((void*) NULL, sig_value);
	assert_tag_equals("ds:SignatureValue", sig_value);

	DOMElement *key_info = sig_value->getNextElementSibling();
	assert_not_equals((void*) NULL, key_info);
	assert_tag_equals("ds:KeyInfo", key_info);

	DOMElement *key_val = key_info->getFirstElementChild();
	assert_not_equals((void*) NULL, key_val);
	assert_tag_equals("ds:KeyValue", key_val);

	DOMElement *rsa_key_val = key_val->getFirstElementChild();
	assert_not_equals((void*) NULL, rsa_key_val);
	assert_tag_equals("ds:RSAKeyValue", rsa_key_val);

	DOMElement *modulus = rsa_key_val->getFirstElementChild();
	assert_not_equals((void*) NULL, modulus);
	assert_tag_equals("ds:Modulus", modulus);
	assert_content_equals(EXPECTED_MODULUS, modulus);
	
	DOMElement *exponent = modulus->getNextElementSibling();
	assert_not_equals((void*) NULL, exponent);
	assert_tag_equals("ds:Exponent", exponent);
	assert_content_equals(EXPECTED_EXPONENT, exponent);

	DOMElement *x509_data = key_val->getNextElementSibling();
	assert_not_equals((void*) NULL, x509_data);
	assert_tag_equals("ds:X509Data", x509_data);

	DOMElement *x509_subject = x509_data->getFirstElementChild();
	assert_not_equals((void*) NULL, x509_subject);
	assert_tag_equals("ds:X509SubjectName", x509_subject);
	assert_content_equals("C=US, ST=MD, L=Columbia, CN=www.tresys.com", x509_subject);

	DOMElement *x509_serial = x509_subject->getNextElementSibling();
	assert_not_equals((void*) NULL, x509_serial);
	assert_tag_equals("ds:X509IssuerSerial", x509_serial);

	DOMElement *x509_issuer = x509_serial->getFirstElementChild();
	assert_not_equals((void*) NULL, x509_issuer);
	assert_tag_equals("ds:X509IssuerName", x509_issuer);
	assert_content_equals("C=US, ST=MD, L=Columbia, CN=www.tresys.com", x509_issuer);

	DOMElement *x509_number = x509_issuer->getNextElementSibling();
	assert_not_equals((void*) NULL, x509_number);
	assert_tag_equals("ds:X509SerialNumber", x509_number);
	assert_content_equals("17415892367561384562", x509_number);

	DOMElement *x509_cert = x509_serial->getNextElementSibling();
	assert_not_equals((void*) NULL, x509_cert);
	assert_tag_equals("ds:X509Certificate", x509_cert);
}

extern "C" void test_add_signature_fails_with_bad_input()
{
	enum jal_status ret;
	load_key_and_cert();
	build_dom_for_signing();
	assert_not_equals((void *) NULL, cert);
	assert_not_equals((void *) NULL, key);

	assert_not_equals((void *) NULL, key);
	ret = jal_add_signature_block(NULL, NULL, doc, doc->getDocumentElement(), NULL, id_val);
	assert_equals(JAL_E_INVAL, ret);
	ret = jal_add_signature_block(key, NULL, NULL, doc->getDocumentElement(), NULL, id_val);
	assert_equals(JAL_E_INVAL, ret);
	ret = jal_add_signature_block(key, NULL, doc, NULL, NULL, id_val);
	assert_equals(JAL_E_INVAL, ret);
	ret = jal_add_signature_block(key, NULL, doc, doc->getDocumentElement(), NULL, NULL);
	assert_equals(JAL_E_INVAL, ret);
}
extern "C" void test_add_signature_works_without_cert()
{
	enum jal_status ret;
	load_key_and_cert();
	build_dom_for_signing();

	assert_not_equals((void *) NULL, key);

	// sign document
	ret = jal_add_signature_block(key, NULL, doc, doc->getDocumentElement(), NULL, id_val);
	assert_equals(JAL_OK, ret);

	//make sure the signature got added in the right place
	DOMElement *sig_node = doc->getDocumentElement()->getLastElementChild();
	assert_not_equals((void*) NULL, sig_node);
	assert_tag_equals("ds:Signature", sig_node);

	DOMElement *signed_info = sig_node->getFirstElementChild();
	assert_not_equals((void*) NULL, signed_info);
	assert_tag_equals("ds:SignedInfo", signed_info);

	DOMElement *canon_method = signed_info->getFirstElementChild();
	assert_not_equals((void*) NULL, canon_method);
	assert_tag_equals("ds:CanonicalizationMethod", canon_method);

	DOMElement *sig_method = canon_method->getNextElementSibling();
	assert_not_equals((void*) NULL, sig_method);
	assert_tag_equals("ds:SignatureMethod", sig_method);

	// check the reference element...
	DOMElement *ref_elem = sig_method->getNextElementSibling();
	assert_not_equals((void*) NULL, ref_elem);
	assert_tag_equals("ds:Reference", ref_elem);
	assert_attr_equals("URI", XPOINTER_ID_STR, ref_elem);

	DOMElement *xforms = ref_elem->getFirstElementChild();
	assert_not_equals((void*) NULL, xforms);
	assert_tag_equals("ds:Transforms", xforms);

	DOMElement *xform = xforms->getFirstElementChild();
	assert_not_equals((void*) NULL, xform);
	assert_tag_equals("ds:Transform", xform);
	assert_attr_equals("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", xform);
	xform = xform->getNextElementSibling();
	assert_equals((void*) NULL, xform);

	DOMElement *dgst_method = xforms->getNextElementSibling();
	assert_not_equals((void*) NULL, dgst_method);
	assert_tag_equals("ds:DigestMethod", dgst_method);
	assert_attr_equals("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256", dgst_method);

	DOMElement *dgst_value = dgst_method->getNextElementSibling();
	assert_not_equals((void*) NULL, dgst_value);
	assert_tag_equals("ds:DigestValue", dgst_value);
	assert_content_equals(EXPECTED_SIGNING_DGST_VALUE, dgst_value);

	DOMElement *sig_value = signed_info->getNextElementSibling();
	assert_not_equals((void*) NULL, sig_value);
	assert_tag_equals("ds:SignatureValue", sig_value);

	DOMElement *key_info = sig_value->getNextElementSibling();
	assert_not_equals((void*) NULL, key_info);
	assert_tag_equals("ds:KeyInfo", key_info);

	DOMElement *key_val = key_info->getFirstElementChild();
	assert_not_equals((void*) NULL, key_val);
	assert_tag_equals("ds:KeyValue", key_val);

	DOMElement *rsa_key_val = key_val->getFirstElementChild();
	assert_not_equals((void*) NULL, rsa_key_val);
	assert_tag_equals("ds:RSAKeyValue", rsa_key_val);

	DOMElement *modulus = rsa_key_val->getFirstElementChild();
	assert_not_equals((void*) NULL, modulus);
	assert_tag_equals("ds:Modulus", modulus);
	assert_content_equals(EXPECTED_MODULUS, modulus);
	
	DOMElement *exponent = modulus->getNextElementSibling();
	assert_not_equals((void*) NULL, exponent);
	assert_tag_equals("ds:Exponent", exponent);
	assert_content_equals(EXPECTED_EXPONENT, exponent);

	// make sure there is no cert data...
	assert_equals((void*) NULL, key_val->getNextElementSibling());
}
