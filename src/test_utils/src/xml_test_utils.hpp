/**
 * @file This file contains utilities to help with _to_xml tests.
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

#ifndef __XML_TESTS_UTILS_HPP_
#define __XML_TESTS_UTILS_HPP_

#include <list>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/dom/DOMLSOutput.hpp>
#include <xercesc/framework/XMLFormatter.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>

#define TEST_XML_DSIG_SCHEMA  SCHEMAS_ROOT "xmldsig-core-schema.xsd"
#define TEST_XML_APP_META_SCHEMA  SCHEMAS_ROOT "applicationMetadata.xsd"
#define TEST_XML_APP_META_TYPES_SCHEMA  SCHEMAS_ROOT "applicationMetadataTypes.xsd"
#define TEST_XML_SYS_META_SCHEMA  SCHEMAS_ROOT "systemMetadata.xsd"
#define TEST_XML_SCHEMA_DTD SCHEMAS_ROOT "XMLSchema.dtd"

XERCES_CPP_NAMESPACE_USE

extern const XMLCh TEST_XML_CORE[];

/**
 * Validate the given document against a set of schemas
 *
 * @param doc The DOMDOcument to validate.
 * @param document_name A string used to identify the DOMDocument when printing
 * errors.
 * @param schemas A list of schemas to load before validating the DOMDocument
 * @param debug When debug is true, the function will output more debug
 * information.
 * @return true if the DOMDocument could be validated against the schemas,
 * false if any errors occurred..
 */
bool validate(DOMDocument *, const char *, std::list<const char*>, bool debug=false);
/**
 * Serialize a DOMDocument to a memory buffer.
 * This function will serialize a given document to a memory buffer. The
 * contents of the memory buffer will be an UTF-8 encoded XML document.
 *
 * @param doc The DOMDocument to serialize
 */
MemBufFormatTarget *xml_output(DOMDocument *doc);

/**
 * Macro to aid checking attribute values of DOM nodes
 *
 * If the expected value is NULL and actual value is not NULL, this triggers a
 * failure.
 * If the expected value is non-NULL and the actual value is not textually
 * equivalent to the expected value, this triggers a failure.
 *
 * @param attr_name A char* that is the name of the attribute to check.
 * @param  expected A char* that is the expected attribute value.
 * @param the_elem A DOMElement that contains the attribute to verify.
 *
 */
#define assert_attr_equals(attr_name, expected, the_elem) \
	do { \
		char *expected_value = (char*) expected; \
		DOMElement *elem = the_elem; \
		XMLCh *xml_attr_name = XMLString::transcode(attr_name); \
		DOMNode *actual_attr_node = elem->getAttributes()->getNamedItem(xml_attr_name); \
		XMLString::release(&xml_attr_name); \
		if (expected_value == NULL) { \
			assert_equals(NULL, actual_attr_node); \
		} else { \
			assert_not_equals(NULL, actual_attr_node); \
			const XMLCh *actual_value = actual_attr_node->getNodeValue(); \
			XMLCh * expected_xml_val = XMLString::transcode(expected_value); \
			if (XMLString::compareString(expected_xml_val, actual_value) != 0) { \
				test_dept_test_failures += 1; \
				char *actual_c_str = XMLString::transcode(actual_value); \
				fprintf(stderr, "%s:%d: Failure: expected that attribute ('%s') == '%s', found '%s'\n", \
					__FILE__, __LINE__, attr_name, expected_value, actual_c_str); \
				delete actual_c_str; \
				XMLString::release(&expected_xml_val); \
				return; \
			} \
			XMLString::release(&expected_xml_val); \
		} \
	} while(0)

#define assert_content_equals(expected, the_elem) \
	do { \
		char *expected_value = (char*) expected; \
		DOMElement *elem = the_elem; \
		const XMLCh *actual_text_content = elem->getTextContent(); \
		if (expected_value == NULL) { \
			assert_equals(NULL, actual_text_content); \
		} else { \
			assert_not_equals(NULL, actual_text_content); \
			XMLCh * expected_text_content = XMLString::transcode(expected_value); \
			if (XMLString::compareString(expected_text_content, actual_text_content) != 0) { \
				test_dept_test_failures += 1; \
				char *actual_c_str = XMLString::transcode(actual_text_content); \
				fprintf(stderr, "%s:%d: Failure: expected content == '%s', found '%s'\n", \
					__FILE__, __LINE__, expected_value, actual_c_str); \
				delete actual_c_str; \
				XMLString::release(&expected_text_content); \
				return; \
			} \
			XMLString::release(&expected_text_content); \
		} \
	} while(0)

#define assert_tag_equals(expected, the_elem) \
	do { \
		char *expected_value = (char*) expected; \
		DOMElement *elem = the_elem; \
		const XMLCh *actual_tag = elem->getTagName(); \
		XMLCh * expected_tag = XMLString::transcode(expected_value); \
		if (XMLString::compareString(expected_tag, actual_tag) != 0) { \
			test_dept_test_failures += 1; \
			char *actual_c_str = XMLString::transcode(actual_tag); \
			fprintf(stderr, "%s:%d: Failure: expected tag == '%s', found '%s'\n", \
				__FILE__, __LINE__, expected_value, actual_c_str); \
			delete actual_c_str; \
			XMLString::release(&expected_tag); \
			return; \
		} \
		XMLString::release(&expected_tag); \
	} while(0)

#define assert_namespace_equals(expected, the_elem) \
	do { \
		char *expected_value = (char*) expected; \
		DOMElement *elem = the_elem; \
		const XMLCh *actual_ns = elem->getNamespaceURI(); \
		XMLCh * expected_ns = XMLString::transcode(expected_value); \
		if (XMLString::compareString(expected_ns, actual_ns) != 0) { \
			test_dept_test_failures += 1; \
			char *actual_c_str = XMLString::transcode(actual_ns); \
			fprintf(stderr, "%s:%d: Failure: expected namespace == '%s', found '%s'\n", \
				__FILE__, __LINE__, expected_value, actual_c_str); \
			delete actual_c_str; \
			XMLString::release(&expected_ns); \
			return; \
		} \
		XMLString::release(&expected_ns); \
	} while(0)

#endif
