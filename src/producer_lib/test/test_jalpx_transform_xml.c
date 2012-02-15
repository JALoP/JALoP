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

#include "jalpx_transform_xml.h"
#include "jal_alloc.h"
#include <jalop/jalp_context.h>

//#include <arpa/inet.h>

static xmlDocPtr doc = NULL;
static struct jalp_transform *transform1 = NULL;
static struct jalp_transform *transform2 = NULL;

static xmlChar *namespace_uri = NULL;
static xmlNodePtr transform_elm = NULL;

static const char *jalp_xml_transform_ch = "Transform";
static xmlChar *xml_transform = NULL;

// keys for xor
//static uint32_t xor_key = 1234;
//static uint32_t net_order_xor_key;
//static const char *b64_net_order_xor_key = "AAAE0g==";

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
//static const char *aes_128_key = "aaaaaaaabbbbbbbb";
//static const char *b64_aes_128_key = "YWFhYWFhYWFiYmJiYmJiYg==";

//static const char *aes_192_key = "aaaaaaaabbbbbbbbaaaaaaaa";
//static const char *b64_aes_192_key = "YWFhYWFhYWFiYmJiYmJiYmFhYWFhYWFh";

//static const char *aes_256_key = "aaaaaaaabbbbbbbbaaaaaaaabbbbbbbb";
//static const char *b64_aes_256_key = "YWFhYWFhYWFiYmJiYmJiYmFhYWFhYWFhYmJiYmJiYmI=";

// iv for aes
//static const char *aes_128_iv = "ccccccccdddddddd";
//static const char *b64_aes_128_iv = "Y2NjY2NjY2NkZGRkZGRkZA==";


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
	//transform_elm = doc->createElementNS(namespace_uri, xml_transform);
	transform_elm = xmlNewDocNode(doc, NULL, xml_transform, NULL);
	xmlNewNs(transform_elm, namespace_uri, NULL);
	

	//net_order_xor_key = htonl(xor_key);

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
 * Tests for jalp_transform_other.
 */
void test_transform_to_elem_handle_custom_succeeds_with_xml()
{
	enum jal_status ret;
	//xmlNodePtr child_element = NULL;

	printf("XML ->\n%s\n\n", transform1->other_info->xml);

	ret = jalpx_transform_to_elem_handle_custom(&transform_elm, transform1->other_info);
	assert_equals(JAL_OK, ret);

	printf("\nNEW_TRANSFORM\n");
	xmlDocSetRootElement(doc, transform_elm);

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

