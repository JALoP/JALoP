/**
 * @file test_jalx_xml_utils.c This file contains unit tests for a
 * variety of utilities dealing with generating XML data.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <jalop/jalp_context.h>
#include <jalop/jal_status.h>


#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "jalx_xml_utils.h"
#include "jal_alloc.h"

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

xmlDocPtr doc = NULL;
const char *base64_input_str = "asdf";

void setup()
{
	doc =  xmlNewDoc((xmlChar *)"1.0");

}

void teardown()
{
	xmlFreeDoc(doc);
}

void test_jalx_create_base64_element_returns_null_with_null_inputs()
{
	assert_equals(1, 1);
}

void test_jalx_create_base64_element_fails_does_not_overwrite_existing_elm_pointer()
{
	assert_equals(1, 1);
}

void test_jalx_create_base64_element_works_with_normal_value()
{
	assert_equals(1, 1);
}

void test_jalx_create_reference_elem_returns_null_with_null_inputs()
{
	xmlNodePtr elem = NULL;

	char * null_input_string = NULL;

	//null input string
	enum jal_status ret = jalx_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) null_input_string,
				strlen(base64_input_str),
				doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, elem);

	//null doc
	ret = jalx_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				NULL, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, elem);

	//unallocated doc
	xmlDocPtr bad_doc = NULL;
	ret = jalx_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				bad_doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, elem);

	//0 string length
	ret = jalx_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				0,
				doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, elem);

	//null elem
	ret = jalx_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);

}

void test_jalx_create_reference_elem_succeeds_with_good_input()
{
	xmlNodePtr elem = NULL;
	enum jal_status ret = jalx_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				doc, &elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);
	xmlDocSetRootElement(doc, elem);
	//xmlDocDump(stdout, doc);

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

void test_jalx_create_reference_elem_succeeds_with_no_uri()
{
	xmlNodePtr elem = NULL;
	enum jal_status ret = jalx_create_reference_elem(NULL,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				doc, &elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);
	xmlDocSetRootElement(doc, elem);
	//xmlDocDump(stdout, doc);

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

void test_jalx_create_reference_elem_fails_does_not_overwrite_existing_pointer()
{
	//successful call to jalx_create_reference_elem
	xmlNodePtr elem = NULL;
	enum jal_status ret = jalx_create_reference_elem(EXAMPLE_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				doc, &elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);

	//allocated elem
	xmlNodePtr old_elem = elem;
	ret = jalx_create_reference_elem(EXAMPLE_URI,
                                EXAMPLE_DIGEST_METHOD,
                                (uint8_t *) base64_input_str,
                                strlen(base64_input_str),
                                doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, old_elem == elem);

	xmlDocSetRootElement(doc, elem);
}

void test_jalx_create_reference_elem_fails_bad_url()
{
	xmlNodePtr elem = NULL;
	enum jal_status ret = jalx_create_reference_elem(EXAMPLE_BAD_URI,
				EXAMPLE_DIGEST_METHOD,
				(uint8_t *) base64_input_str,
				strlen(base64_input_str),
				doc, &elem);
	assert_equals(JAL_E_INVAL_URI, ret);
	assert_equals(NULL, elem);
}

void test_jalx_digest_xml_data_returns_inval_for_null()
{
	assert_equals(1, 1);
}

void test_jalx_digest_xml_data_returns_inval_for_bad_digest_ctx()
{
	assert_equals(1, 1);
}

void test_jalx_digest_xml_data_returns_inval_for_allocated_dgst_buffer()
{
	assert_equals(1, 1);
}

void test_jalx_digest_xml_data_canonicalizes_and_digests()
{
	assert_equals(1, 1);
}

void test_jalx_create_audit_transforms_elem_null_inputs()
{
	xmlNodePtr elem = NULL;
	xmlDocPtr null_doc = NULL;

	//null doc
        enum jal_status ret = jalx_create_audit_transforms_elem( NULL, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, elem);

	//unallocated doc
        ret = jalx_create_audit_transforms_elem( null_doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, elem);

	//successfully create element
        ret = jalx_create_audit_transforms_elem( doc, &elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);

	xmlDocSetRootElement(doc, elem);

	//allocated elem
	xmlNodePtr old_elem = elem;
	ret = jalx_create_audit_transforms_elem( doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, old_elem == elem);

	//null elem
        ret = jalx_create_audit_transforms_elem( doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);

}

void test_jalx_create_audit_transforms_elem_does_not_overwrite_elem()
{
	//successfully create element
	xmlNodePtr elem = NULL;
        enum jal_status ret = jalx_create_audit_transforms_elem( doc, &elem);
        assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, elem);

	xmlDocSetRootElement(doc, elem);

	//run again with newly created element
	xmlNodePtr old_elem = elem;
	ret = jalx_create_audit_transforms_elem( doc, &elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(1, old_elem == elem);
}

void test_jalx_create_audit_transforms_elem_outputs_correctly()
{
	xmlNodePtr elem = NULL;
        enum jal_status ret = jalx_create_audit_transforms_elem( doc, &elem);
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

void test_jalx_xml_output_bad_inputs()
{
	xmlChar * buf = NULL;

	enum jal_status ret = jalx_xml_output(NULL, NULL);
	assert_equals(ret, JAL_E_INVAL);

	ret = jalx_xml_output(NULL, &buf);
	assert_equals(ret, JAL_E_INVAL);

	ret = jalx_xml_output(doc, NULL);
	assert_equals(ret, JAL_E_INVAL);

	xmlDocPtr null_doc = NULL;
	jalx_xml_output(null_doc, &buf);
	assert_equals(ret, JAL_E_INVAL);

	buf = xmlStrdup(BAD_CAST "foo");
	jalx_xml_output(doc, &buf);
	assert_equals(ret, JAL_E_INVAL);
	assert_equals(0, xmlStrcmp(buf, BAD_CAST "foo"));

	xmlFree(buf);

}

void test_jalx_xml_output_good_inputs()
{
	xmlChar * buf = NULL;
	enum jal_status ret = jalx_xml_output(doc, &buf);
        assert_equals(ret, JAL_OK);
	assert_not_equals(NULL, buf);

}

void test_add_signature_block()
{
	assert_equals(1, 1);
}

void test_add_signature_block_works_with_prev()
{
	assert_equals(1, 1);
}

void test_add_signature_fails_with_bad_input()
{
	assert_equals(1, 1);
}
void test_add_signature_works_without_cert()
{
	assert_equals(1, 1);
}
