/**
 * @file xml_test_utils2.h This file contains utilities to help with _to_xml tests.
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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __XML_TEST_UTILS_H_
#define __XML_TEST_UTILS_H_

#include <libxml/tree.h>

#define TEST_XML_DSIG_SCHEMA  SCHEMAS_ROOT "xmldsig-core-schema.xsd"
#define TEST_XML_APP_META_SCHEMA  SCHEMAS_ROOT "applicationMetadata.xsd"
#define TEST_XML_APP_META_TYPES_SCHEMA  SCHEMAS_ROOT "applicationMetadataTypes.xsd"
#define TEST_XML_SYS_META_SCHEMA  SCHEMAS_ROOT "systemMetadata.xsd"
#define TEST_XML_SCHEMA_DTD SCHEMAS_ROOT "XMLSchema.dtd"
#define TEST_XML_CORE "Core"

/**
 * Validate the given document against a schema
 *
 * @param doc The xmlDocPtr to validate.
 * @param document_name A string used to identify the xmlDocPtr when printing
 * errors.
 * @param schema_str The schema to load before validating the xmlDocPtr
 * @param debug When debug is true, the function will output more debug
 * information.
 * @return 
 * 	0 if the xmlDocPtr could be validated against the schema,
 * 	-1 if any errors occurred..
 */
int validate(xmlDocPtr doc, const char *doc_name, const char *schema_str, int debug);

/**
 * Serialize an xmlDocPtr to a memory buffer.
 * This function will serialize a given document to a memory buffer. The
 * contents of the memory buffer will be a UTF-8 encoded XML document.
 *
 * @param doc The xmlDocPtr to serialize
 */
xmlChar *xml_output(xmlDocPtr doc);

/**
 * Macro to aid checking attribute values of DOM nodes
 *
 * If the expected value is NULL and actual value is not NULL, this triggers a
 * failure.
 * If the expected value is non-NULL and the actual value is not textually
 * equivalent to the expected value, this triggers a failure.
 *
 * @param attr_name A char* that is the name of the attribute to check.
 * @param expected A char* that is the expected attribute value.
 * @param the_elem An xmlNodePtr that contains the attribute to verify.
 *
 */
#define assert_attr_equals(attr_name, expected, the_elem) \
	do { \
		xmlChar *expected_value = (xmlChar *) expected; \
		xmlNodePtr elem = the_elem; \
		xmlChar *attr_val = xmlGetProp(elem, (xmlChar *)attr_name); \
		if (NULL == expected_value) { \
			assert_equals((void*)NULL, attr_val); \
		} else { \
			assert_not_equals(NULL, attr_val); \
			if (0 != xmlStrcmp(expected_value, attr_val)) { \
				test_dept_test_failures += 1; \
				fprintf(stderr, "%s:%d: Failure: expected that attribute ('%s') == '%s', found '%s'\n", \
					__FILE__, __LINE__, attr_name, expected_value, attr_val); \
				xmlFree(attr_val); \
				return; \
			} \
		} \
		xmlFree(attr_val); \
	} while(0)

#define assert_content_equals(expected, the_elem) \
	do { \
		char *expected_value = (char *) expected; \
		xmlNodePtr elem = the_elem; \
		char *actual_text_content = NULL; \
		if (NULL == expected_value) { \
			assert_equals((void*)NULL, elem->children); \
		} else { \
			assert_not_equals(NULL, elem->children); \
			actual_text_content = (char *)elem->children->content; \
			assert_not_equals(NULL, actual_text_content); \
			if (0 != strcmp(expected_value, actual_text_content)) { \
				test_dept_test_failures += 1; \
				fprintf(stderr, "%s:%d: Failure: expected content == '%s', found '%s'\n", \
					__FILE__, __LINE__, expected_value, actual_text_content); \
				return; \
			} \
		} \
	} while(0)

#define assert_tag_equals(expected, the_elem) \
	do { \
		char *expected_value = (char *) expected; \
		xmlNodePtr elem = the_elem; \
		char *actual_tag = (char *) elem->name; \
		if (0 != strcmp(expected_value, actual_tag)) { \
			test_dept_test_failures += 1; \
			fprintf(stderr, "%s:%d: Failure: expected tag == '%s', found '%s'\n", \
				__FILE__, __LINE__, expected_value, actual_tag); \
			return; \
		} \
	} while(0)

#define assert_namespace_equals(expected, the_elem) \
	do { \
		char *expected_value = (char *) expected; \
		xmlNodePtr elem = the_elem; \
		const xmlChar *actual_ns = elem->ns->href; \
		if (0 != strcmp(expected_value, (char *)actual_ns)) { \
			test_dept_test_failures += 1; \
			fprintf(stderr, "%s:%d: Failure: expected namespace == '%s', found '%s'\n", \
				__FILE__, __LINE__, expected_value, actual_ns); \
			return; \
		} \
	} while(0)

#endif // __XML_TEST_UTILS_H_
