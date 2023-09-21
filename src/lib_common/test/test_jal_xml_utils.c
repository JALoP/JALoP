/**
 * @file test_jal_xml_utils.c This file contains unit tests for a
 * variety of utilities dealing with generating XML data.
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
 * distributed under the License is distributed on an "AS IS" BASIS, * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// c++.

#include <test-dept.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include <jalop/jal_status.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>

#include <xmlsec/openssl/evp.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>

#include "jal_xml_utils.h"
#include "jal_alloc.h"
#include "xml_test_utils2.h"

#define EVENT_ID "event-123-xyz"

#define TEST_RSA_KEY  TEST_INPUT_ROOT "TLS_Unit_Test_Files/rsa_key"
#define TEST_CERT  TEST_INPUT_ROOT "TLS_Unit_Test_Files/cert"
#define TEST_CERT_AND_KEY  TEST_INPUT_ROOT "TLS_Unit_Test_Files/cert_and_key"

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

//#define EXPECTED_SIGNING_DGST_VALUE "Tv+xVpQnAxQYuhWNG8hG2zBXRG5Z5kThWM5UGEaA/jQ="
#define EXPECTED_SIGNING_DGST_VALUE "zqfv/c2dvejx20CIJ5Kg7j+HxlB95r1q8XqL74aeWCk="
#define EXPECTED_MODULUS "\n3PRI+qegjHCd70xtRMPzknUDqY6iH93XJwfuGqXguiEB8n3dxaZu1ZNzMe1BHpGj\ne2RPaRr5EXBKAXMPnw6MXQ==\n"
#define EXPECTED_EXPONENT "\nAQAB\n"

static const uint8_t EXPECTED_DGST[] = { 0xca, 0x60, 0x88, 0xd0, 0xab,
	0x26, 0x59, 0x66, 0xa7, 0x5b, 0xbf, 0xc2, 0x24, 0xc8, 0xb3,
	0xaa, 0x29, 0x85, 0xcb, 0x67, 0xfb, 0x3d, 0xd8, 0xbf, 0x8d,
	0x48, 0xf0, 0x16, 0xff, 0xfd, 0xf7, 0x76};

xmlDocPtr doc = NULL;
const char *base64_input_str = "asdf";
static const char *base64_string = "YXNkZg==";
static struct jal_digest_ctx *dgst_ctx = NULL;

static X509 *cert;
static RSA *key;

xmlChar *namespace_uri;
xmlChar *tag;
const char *id_val;

static xmlNodePtr get_next_element(xmlNodePtr elem)
{
	xmlNodePtr next = elem->next;
	while (next != NULL &&
		next->type != XML_ELEMENT_NODE) {
		next = next->next;
	}
	return next;
}

static void generate_doc_for_canon() {
	xmlChar *a_xml_namespace = (xmlChar *)NAMESPACE;
	xmlChar *a_xml_tag = (xmlChar *)TAG;
	xmlChar *a_xml_comment = (xmlChar *)COMMENT;

	xmlNodePtr root = xmlNewDocNode(doc, NULL, a_xml_tag, NULL);
	xmlNsPtr ns = xmlNewNs(root, a_xml_namespace, NULL);
	xmlSetNs(root, ns);
	xmlDocSetRootElement(doc, root);
	xmlNodePtr comment_node = xmlNewDocComment(doc, a_xml_comment);
	xmlAddChild(root, comment_node);
}

static void load_key_and_cert()
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
	xmlNodePtr elem = xmlNewDocNode(doc, NULL, (xmlChar *)"elem1", NULL);
	xmlNsPtr ns = xmlNewNs(elem, (xmlChar *)ID_NS, NULL);
	xmlSetNs(elem, ns);
	xmlSetProp(elem, (xmlChar *)"xml:id", (xmlChar *)ID_STR);
	
	xmlNodePtr achild = xmlNewDocNode(doc, NULL, (xmlChar *)"achild", NULL);
	xmlNodePtr bchild = xmlNewDocNode(doc, NULL, (xmlChar *)"bchild", NULL);

	xmlAddChild(elem, achild);
	xmlAddChild(elem, bchild);

	xmlDocSetRootElement(doc, elem);
}

void setup()
{
	doc =  xmlNewDoc((xmlChar *)"1.0");
	namespace_uri = (xmlChar *)JAL_APP_META_TYPES_NAMESPACE_URI;
	tag = (xmlChar *)TAG;
	id_val = ID_STR;

	SSL_library_init();
	xmlSecInit();

	xmlSecCryptoDLLoadLibrary(BAD_CAST "openssl");

	xmlSecCryptoAppInit(NULL);
	xmlSecCryptoInit();
	
	dgst_ctx = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);
}

void teardown()
{
	xmlFreeDoc(doc);

	xmlSecCryptoShutdown();
	xmlSecCryptoAppShutdown();
	xmlSecShutdown();
}

void test_jal_create_base64_element_returns_null_with_null_inputs()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jal_create_base64_element(NULL, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jal_create_base64_element(doc, NULL, strlen(base64_input_str), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, 0, namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), NULL, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, NULL, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, tag, NULL);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*)NULL, new_elem);
}

void test_jal_create_base64_element_fails_does_not_overwrite_existing_elm_pointer()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, tag, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	xmlNodePtr orig = new_elem;
	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(orig, new_elem);
	xmlFreeNodeList(new_elem);
}

void test_jal_create_base64_element_works_with_normal_value()
{
	// <SomeTag>YXNkZg==</SomeTag>
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jal_create_base64_element(doc, (uint8_t *) base64_input_str, strlen(base64_input_str), namespace_uri, tag, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_tag_equals(TAG, new_elem);
	assert_content_equals(base64_string, new_elem);
	assert_namespace_equals(JAL_APP_META_TYPES_NAMESPACE_URI, new_elem);
	xmlFreeNodeList(new_elem);
}

void test_jal_create_reference_elem_returns_null_with_null_inputs()
{
	xmlNodePtr elem = NULL;

	char * null_input_string = NULL;

	//null input string
	enum jal_status ret = jal_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) null_input_string,
				strlen(base64_input_str),
				doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, elem);

	//null doc
	ret = jal_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				NULL, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, elem);

	//unallocated doc
	xmlDocPtr bad_doc = NULL;
	ret = jal_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				bad_doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, elem);

	//0 string length
	ret = jal_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				0,
				doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, elem);

	//null elem
	ret = jal_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
}

void test_jal_create_reference_elem_succeeds_with_good_input()
{
	xmlNodePtr elem = NULL;
	enum jal_status ret = jal_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				doc, &elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);
	xmlDocSetRootElement(doc, elem);

	xmlChar * ret_val;
	xmlNodePtr temp = doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(temp->name, BAD_CAST REFERENCE));
	ret_val = xmlGetProp(temp, BAD_CAST URI);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST EXAMPLE_URI));
	xmlFree(ret_val);

	temp = temp->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(temp->name, BAD_CAST DIGEST_METHOD));
	ret_val = xmlGetProp(temp, BAD_CAST ALGORITHM);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST "some digest method"));
	xmlFree(ret_val);

	temp = temp->next;
	assert_equals(0, xmlStrcmp(temp->name, BAD_CAST DIGEST_VALUE));
	ret_val = xmlNodeGetContent(temp);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST "YXNkZg=="));
	xmlFree(ret_val);
}

void test_jal_create_reference_elem_succeeds_with_no_uri()
{
	xmlNodePtr elem = NULL;
	enum jal_status ret = jal_create_reference_elem(NULL,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				doc, &elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);
	xmlDocSetRootElement(doc, elem);

	xmlChar * ret_val;
	xmlNodePtr temp = doc->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(temp->name, BAD_CAST REFERENCE));

	temp = temp->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(temp->name, BAD_CAST DIGEST_METHOD));
	ret_val = xmlGetProp(temp, BAD_CAST ALGORITHM);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST "some digest method"));
	xmlFree(ret_val);

	temp = temp->next;
	assert_equals(0, xmlStrcmp(temp->name, BAD_CAST DIGEST_VALUE));
	ret_val = xmlNodeGetContent(temp);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST "YXNkZg=="));
	xmlFree(ret_val);
}

void test_jal_create_reference_elem_fails_does_not_overwrite_existing_pointer()
{
	//successful call to jal_create_reference_elem
	xmlNodePtr elem = NULL;
	enum jal_status ret = jal_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				doc, &elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);

	//allocated elem
	xmlNodePtr old_elem = elem;
	ret = jal_create_reference_elem(EXAMPLE_URI,
                                EXAMPLE_DIGEST_METHOD,
                                (uint8_t *) base64_input_str,
                                strlen(base64_input_str),
                                doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, old_elem == elem);

	xmlDocSetRootElement(doc, elem);
}

void test_jal_create_reference_elem_fails_bad_url()
{
	xmlNodePtr elem = NULL;
	enum jal_status ret = jal_create_reference_elem(EXAMPLE_BAD_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				doc, &elem);
	assert_equals(JAL_E_INVAL_URI, ret);
	assert_equals((void*)NULL, elem);
}

void test_jal_digest_xml_data_returns_inval_for_null()
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

void test_jal_digest_xml_data_returns_inval_for_bad_digest_ctx()
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
	dgst_ctx = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);
	dgst_ctx->init = NULL;
	ret = jal_digest_xml_data(dgst_ctx, doc, &dgst, &dgst_len);
	assert_not_equals(ret, JAL_OK);
	assert_equals(dgst, NULL);
	assert_equals(0, dgst_len);

}

void test_jal_digest_xml_data_returns_inval_for_allocated_dgst_buffer()
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

void test_jal_digest_xml_data_canonicalizes_and_digests()
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

void test_jal_create_audit_transforms_elem_null_inputs()
{
	xmlNodePtr elem = NULL;
	xmlDocPtr null_doc = NULL;

	//null doc
        enum jal_status ret = jal_create_audit_transforms_elem( NULL, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, elem);

	//unallocated doc
        ret = jal_create_audit_transforms_elem( null_doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, elem);

	//successfully create element
        ret = jal_create_audit_transforms_elem( doc, &elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);

	xmlDocSetRootElement(doc, elem);

	//allocated elem
	xmlNodePtr old_elem = elem;
	ret = jal_create_audit_transforms_elem( doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, old_elem == elem);

	//null elem
        ret = jal_create_audit_transforms_elem( doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);

}

void test_jal_create_audit_transforms_elem_does_not_overwrite_elem()
{
	//successfully create element
	xmlNodePtr elem = NULL;
        enum jal_status ret = jal_create_audit_transforms_elem( doc, &elem);
        assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);

	xmlDocSetRootElement(doc, elem);

	//run again with newly created element
	xmlNodePtr old_elem = elem;
	ret = jal_create_audit_transforms_elem( doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, old_elem == elem);
}

void test_jal_create_audit_transforms_elem_outputs_correctly()
{
	xmlNodePtr elem = NULL;
        enum jal_status ret = jal_create_audit_transforms_elem( doc, &elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);

	xmlDocSetRootElement(doc, elem);
	xmlNodePtr cur_node = doc->xmlChildrenNode;
        assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST TRANSFORMS));

	xmlChar * ret_val = NULL;
	cur_node = cur_node->xmlChildrenNode;
	assert_equals(0, xmlStrcmp(cur_node->name, BAD_CAST TRANSFORM));
	ret_val = xmlGetProp(cur_node, BAD_CAST ALGORITHM);
	assert_equals(0, xmlStrcmp(ret_val, BAD_CAST CANON_ALG));
	xmlFree(ret_val);
}

void test_jal_xml_output_bad_inputs()
{
	xmlChar * buf = NULL;
	size_t bsize = 0;

	enum jal_status ret = jal_xml_output(NULL, NULL, NULL);
	assert_equals(ret, JAL_E_INVAL);

	ret = jal_xml_output(NULL, &buf, &bsize);
	assert_equals(ret, JAL_E_INVAL);

	ret = jal_xml_output(doc, NULL, &bsize);
	assert_equals(ret, JAL_E_INVAL);

	ret = jal_xml_output(doc, &buf, NULL);
	assert_equals(ret, JAL_E_INVAL);

	xmlDocPtr null_doc = NULL;
	jal_xml_output(null_doc, &buf, &bsize);
	assert_equals(ret, JAL_E_INVAL);

	buf = xmlStrdup(BAD_CAST "foo");
	jal_xml_output(doc, &buf, &bsize);
	assert_equals(ret, JAL_E_INVAL);
	assert_equals(0, xmlStrcmp(buf, BAD_CAST "foo"));

	xmlFree(buf);
}

void test_jal_xml_output_good_inputs()
{
	xmlChar * buf = NULL;
	size_t bsize = 0;
	enum jal_status ret = jal_xml_output(doc, &buf, &bsize);
        assert_equals(ret, JAL_OK);
	assert_not_equals(0, bsize);
	assert_not_equals(NULL, buf);
	xmlFree(buf);
}

void test_add_signature_block()
{
	enum jal_status ret = JAL_OK;
	load_key_and_cert();
	build_dom_for_signing();

	assert_not_equals((void *) NULL, cert);
	assert_not_equals((void *) NULL, key);

	// sign document
	ret = jal_add_signature_block(key, cert, doc, NULL, id_val);
	assert_equals(JAL_OK, ret);

	//make sure the signature got added in the right place
	xmlNodePtr sig_node = doc->children->last;
	assert_not_equals((void*) NULL, sig_node);
	assert_tag_equals("Signature", sig_node);

	xmlNodePtr signed_info = jal_get_first_element_child(sig_node);
	assert_not_equals((void*) NULL, signed_info);
	assert_tag_equals("SignedInfo", signed_info);

	xmlNodePtr canon_method = jal_get_first_element_child(signed_info);
	assert_not_equals((void*) NULL, canon_method);
	assert_tag_equals("CanonicalizationMethod", canon_method);

	xmlNodePtr sig_method = get_next_element(canon_method);
	assert_not_equals((void*) NULL, sig_method);
	assert_tag_equals("SignatureMethod", sig_method);

	// check the reference element...
	xmlNodePtr ref_elem = get_next_element(sig_method);
	assert_not_equals((void*) NULL, ref_elem);
	assert_tag_equals("Reference", ref_elem);
	assert_attr_equals("URI", XPOINTER_ID_STR, ref_elem);

	xmlNodePtr xforms = jal_get_first_element_child(ref_elem);
	assert_not_equals((void*) NULL, xforms);
	assert_tag_equals("Transforms", xforms);

	xmlNodePtr dgst_method = get_next_element(xforms);
	assert_not_equals((void*) NULL, dgst_method);
	assert_tag_equals("DigestMethod", dgst_method);
	assert_attr_equals("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256", dgst_method);

	xmlNodePtr dgst_value = get_next_element(dgst_method);
	assert_not_equals((void*) NULL, dgst_value);
	assert_tag_equals("DigestValue", dgst_value);
	assert_content_equals(EXPECTED_SIGNING_DGST_VALUE, dgst_value);

	xmlNodePtr xform = jal_get_first_element_child(xforms);
	assert_not_equals((void*) NULL, xform);
	assert_tag_equals("Transform", xform);
	assert_attr_equals("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", xform);

	xmlNodePtr sig_value = get_next_element(signed_info);
	assert_not_equals((void*) NULL, sig_value);
	assert_tag_equals("SignatureValue", sig_value);

	xmlNodePtr key_info = get_next_element(sig_value);
	assert_not_equals((void*) NULL, key_info);
	assert_tag_equals("KeyInfo", key_info);

	xmlNodePtr key_val = jal_get_first_element_child(key_info);
	assert_not_equals((void*) NULL, key_val);
	assert_tag_equals("KeyValue", key_val);

	xmlNodePtr x509_data = get_next_element(key_val);
	assert_not_equals((void*) NULL, x509_data);
	assert_tag_equals("X509Data", x509_data);
	
	xmlNodePtr rsa_key_val = jal_get_first_element_child(key_val);
	assert_not_equals((void*) NULL, rsa_key_val);
	assert_tag_equals("RSAKeyValue", rsa_key_val);

	xmlNodePtr modulus = jal_get_first_element_child(rsa_key_val);
	assert_not_equals((void*) NULL, modulus);
	assert_tag_equals("Modulus", modulus);
	assert_content_equals(EXPECTED_MODULUS, modulus);
	
	xmlNodePtr exponent = get_next_element(modulus);
	assert_not_equals((void*) NULL, exponent);
	assert_tag_equals("Exponent", exponent);
	assert_content_equals(EXPECTED_EXPONENT, exponent);

	// depending on the library version, the X509Certificate element may be first or last
	xmlNodePtr x509_certificate = jal_get_first_element_child(x509_data);
	assert_not_equals((void*) NULL, x509_certificate);
	int leading_cert_elt = !strcmp((char*)x509_certificate->name, "X509Certificate");
	xmlNodePtr x509_subject = NULL;
	if (leading_cert_elt) {
		assert_tag_equals("X509Certificate", x509_certificate);
		x509_subject = get_next_element(x509_certificate);
	} else {
		x509_subject = x509_certificate;
	}

	assert_not_equals((void*) NULL, x509_subject);
	assert_tag_equals("X509SubjectName", x509_subject);
	assert_content_equals("CN=www.tresys.com,L=Columbia,ST=MD,C=US", x509_subject);

	xmlNodePtr x509_serial = get_next_element(x509_subject);
	assert_not_equals((void*) NULL, x509_serial);
	assert_tag_equals("X509IssuerSerial", x509_serial);

	xmlNodePtr x509_issuer = jal_get_first_element_child(x509_serial);
	assert_not_equals((void*) NULL, x509_issuer);
	assert_tag_equals("X509IssuerName", x509_issuer);
	assert_content_equals("CN=www.tresys.com,L=Columbia,ST=MD,C=US", x509_issuer);

	xmlNodePtr x509_number = get_next_element(x509_issuer);
	assert_not_equals((void*) NULL, x509_number);
	assert_tag_equals("X509SerialNumber", x509_number);
	assert_content_equals("17415892367561384562", x509_number);

	if (!leading_cert_elt) {
		x509_certificate = get_next_element(x509_serial);
		assert_not_equals((void*) NULL, x509_certificate);
		assert_tag_equals("X509Certificate", x509_certificate);
	}
}

void test_add_signature_block_works_with_prev()
{
	enum jal_status ret;
	load_key_and_cert();
	build_dom_for_signing();

	assert_not_equals((void *) NULL, cert);
	assert_not_equals((void *) NULL, key);

	// sign document
	ret = jal_add_signature_block(key, cert, doc, doc->children->last, id_val);
	assert_equals(JAL_OK, ret);

	//make sure the signature got added in the right place, it should be
	//right before the 'belemnt' child.
	xmlNodePtr elm2 = doc->children->last;
	assert_not_equals((void*) NULL, elm2);
	assert_tag_equals("bchild", elm2);

	xmlNodePtr sig_node = elm2->prev;
	assert_not_equals((void*) NULL, sig_node);
	assert_tag_equals("Signature", sig_node);

	xmlNodePtr signed_info = jal_get_first_element_child(sig_node);
	assert_not_equals((void*) NULL, signed_info);
	assert_tag_equals("SignedInfo", signed_info);

	xmlNodePtr canon_method = jal_get_first_element_child(signed_info);
	assert_not_equals((void*) NULL, canon_method);
	assert_tag_equals("CanonicalizationMethod", canon_method);

	xmlNodePtr sig_method = get_next_element(canon_method);
	assert_not_equals((void*) NULL, sig_method);
	assert_tag_equals("SignatureMethod", sig_method);

	// check the reference element...
	xmlNodePtr ref_elem = get_next_element(sig_method);
	assert_not_equals((void*) NULL, ref_elem);
	assert_tag_equals("Reference", ref_elem);
	assert_attr_equals("URI", XPOINTER_ID_STR, ref_elem);

	xmlNodePtr xforms = jal_get_first_element_child(ref_elem);
	assert_not_equals((void*) NULL, xforms);
	assert_tag_equals("Transforms", xforms);

	xmlNodePtr dgst_method = get_next_element(xforms);
	assert_not_equals((void*) NULL, dgst_method);
	assert_tag_equals("DigestMethod", dgst_method);
	assert_attr_equals("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256", dgst_method);

	xmlNodePtr dgst_value = get_next_element(dgst_method);
	assert_not_equals((void*) NULL, dgst_value);
	assert_tag_equals("DigestValue", dgst_value);
	assert_content_equals(EXPECTED_SIGNING_DGST_VALUE, dgst_value);

	xmlNodePtr xform = jal_get_first_element_child(xforms);
	assert_not_equals((void*) NULL, xform);
	assert_tag_equals("Transform", xform);
	assert_attr_equals("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", xform);

	xmlNodePtr sig_value = get_next_element(signed_info);
	assert_not_equals((void*) NULL, sig_value);
	assert_tag_equals("SignatureValue", sig_value);

	xmlNodePtr key_info = get_next_element(sig_value);
	assert_not_equals((void*) NULL, key_info);
	assert_tag_equals("KeyInfo", key_info);

	xmlNodePtr key_val = jal_get_first_element_child(key_info);
	assert_not_equals((void*) NULL, key_val);
	assert_tag_equals("KeyValue", key_val);

	xmlNodePtr x509_data = get_next_element(key_val);
	assert_not_equals((void*) NULL, x509_data);
	assert_tag_equals("X509Data", x509_data);
	
	xmlNodePtr rsa_key_val = jal_get_first_element_child(key_val);
	assert_not_equals((void*) NULL, rsa_key_val);
	assert_tag_equals("RSAKeyValue", rsa_key_val);

	xmlNodePtr modulus = jal_get_first_element_child(rsa_key_val);
	assert_not_equals((void*) NULL, modulus);
	assert_tag_equals("Modulus", modulus);
	assert_content_equals(EXPECTED_MODULUS, modulus);
	
	xmlNodePtr exponent = get_next_element(modulus);
	assert_not_equals((void*) NULL, exponent);
	assert_tag_equals("Exponent", exponent);
	assert_content_equals(EXPECTED_EXPONENT, exponent);

	// depending on the library version, the X509Certificate element may be first or last
	xmlNodePtr x509_certificate = jal_get_first_element_child(x509_data);
	assert_not_equals((void*) NULL, x509_certificate);
	int leading_cert_elt = !strcmp((char*)x509_certificate->name, "X509Certificate");
	xmlNodePtr x509_subject = NULL;
	if (leading_cert_elt) {
		assert_tag_equals("X509Certificate", x509_certificate);
		x509_subject = get_next_element(x509_certificate);
	} else {
		x509_subject = x509_certificate;
	}

	assert_not_equals((void*) NULL, x509_subject);
	assert_tag_equals("X509SubjectName", x509_subject);
	assert_content_equals("CN=www.tresys.com,L=Columbia,ST=MD,C=US", x509_subject);

	xmlNodePtr x509_serial = get_next_element(x509_subject);
	assert_not_equals((void*) NULL, x509_serial);
	assert_tag_equals("X509IssuerSerial", x509_serial);

	xmlNodePtr x509_issuer = jal_get_first_element_child(x509_serial);
	assert_not_equals((void*) NULL, x509_issuer);
	assert_tag_equals("X509IssuerName", x509_issuer);
	assert_content_equals("CN=www.tresys.com,L=Columbia,ST=MD,C=US", x509_issuer);

	xmlNodePtr x509_number = get_next_element(x509_issuer);
	assert_not_equals((void*) NULL, x509_number);
	assert_tag_equals("X509SerialNumber", x509_number);
	assert_content_equals("17415892367561384562", x509_number);

	if (!leading_cert_elt) {
		x509_certificate = get_next_element(x509_serial);
		assert_not_equals((void*) NULL, x509_certificate);
		assert_tag_equals("X509Certificate", x509_certificate);
	}
}

void test_add_signature_fails_with_bad_input()
{
	enum jal_status ret;
	load_key_and_cert();
	build_dom_for_signing();
	assert_not_equals((void *) NULL, cert);
	assert_not_equals((void *) NULL, key);

	assert_not_equals((void *) NULL, key);
	ret = jal_add_signature_block(NULL, NULL, doc, NULL, id_val);
	assert_equals(JAL_E_INVAL, ret);
	ret = jal_add_signature_block(key, NULL, NULL, NULL, id_val);
	assert_equals(JAL_E_INVAL, ret);
	ret = jal_add_signature_block(key, NULL, doc, NULL, NULL);
	assert_equals(JAL_E_INVAL, ret);
}

void test_add_signature_works_without_cert()
{
	enum jal_status ret;
	load_key_and_cert();
	build_dom_for_signing();

	assert_not_equals((void *) NULL, key);

	// sign document
	ret = jal_add_signature_block(key, NULL, doc, NULL, id_val);
	assert_equals(JAL_OK, ret);

	//make sure the signature got added in the right place
	xmlNodePtr sig_node = doc->children->last;
	assert_not_equals((void*) NULL, sig_node);
	assert_tag_equals("Signature", sig_node);

	xmlNodePtr signed_info = jal_get_first_element_child(sig_node);
	assert_not_equals((void*) NULL, signed_info);
	assert_tag_equals("SignedInfo", signed_info);

	xmlNodePtr canon_method = jal_get_first_element_child(signed_info);
	assert_not_equals((void*) NULL, canon_method);
	assert_tag_equals("CanonicalizationMethod", canon_method);

	xmlNodePtr sig_method = get_next_element(canon_method);
	assert_not_equals((void*) NULL, sig_method);
	assert_tag_equals("SignatureMethod", sig_method);

	// check the reference element...
	xmlNodePtr ref_elem = get_next_element(sig_method);
	assert_not_equals((void*) NULL, ref_elem);
	assert_tag_equals("Reference", ref_elem);
	assert_attr_equals("URI", XPOINTER_ID_STR, ref_elem);

	xmlNodePtr xforms = jal_get_first_element_child(ref_elem);
	assert_not_equals((void*) NULL, xforms);
	assert_tag_equals("Transforms", xforms);

	xmlNodePtr dgst_method = get_next_element(xforms);
	assert_not_equals((void*) NULL, dgst_method);
	assert_tag_equals("DigestMethod", dgst_method);
	assert_attr_equals("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256", dgst_method);

	xmlNodePtr dgst_value = get_next_element(dgst_method);
	assert_not_equals((void*) NULL, dgst_value);
	assert_tag_equals("DigestValue", dgst_value);
	assert_content_equals(EXPECTED_SIGNING_DGST_VALUE, dgst_value);

	xmlNodePtr xform = jal_get_first_element_child(xforms);
	assert_not_equals((void*) NULL, xform);
	assert_tag_equals("Transform", xform);
	assert_attr_equals("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature", xform);

	xmlNodePtr sig_value = get_next_element(signed_info);
	assert_not_equals((void*) NULL, sig_value);
	assert_tag_equals("SignatureValue", sig_value);

	xmlNodePtr key_info = get_next_element(sig_value);
	assert_not_equals((void*) NULL, key_info);
	assert_tag_equals("KeyInfo", key_info);

	xmlNodePtr key_val = jal_get_first_element_child(key_info);
	assert_not_equals((void*) NULL, key_val);
	assert_tag_equals("KeyValue", key_val);

	// make sure there is no cert data...
	xmlNodePtr x509_data = get_next_element(key_val);
	assert_equals((void*) NULL, x509_data);
}

void test_get_first_element_child_returns_NULL_on_NULL_input()
{
	assert_equals((void*) NULL, jal_get_first_element_child(NULL));
}

void test_get_first_element_child_returns_correct_node()
{
	xmlNodePtr parent = xmlNewNode(NULL, (xmlChar *)"Parent");
	xmlNodePtr text_child = xmlNewText((xmlChar *)"text");
	xmlNodePtr real_child = xmlNewNode(NULL, (xmlChar *)"Child");
	
	xmlAddChild(parent, text_child);
	xmlAddChild(parent, real_child);

	xmlNodePtr child = jal_get_first_element_child(parent);
	assert_not_equals((void*) NULL, child);
	assert_tag_equals("Child", child);

	xmlFreeNodeList(parent);
}

void test_get_first_element_child_returns_NULL_when_child_is_NULL()
{
	xmlNodePtr parent = xmlNewNode(NULL, (xmlChar *)"Parent");
	xmlNodePtr text_child = xmlNewText((xmlChar *)"text");
	
	xmlAddChild(parent, text_child);

	xmlNodePtr child = jal_get_first_element_child(parent);
	assert_equals((void*) NULL, child);

	xmlFreeNodeList(parent);
}
