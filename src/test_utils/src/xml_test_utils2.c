/**
 * @file xml_test_utils2.c This file defines functions to assist with _to_xml testing.
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

#include <libxml/tree.h>
#include <libxml/xmlschemas.h>

#include "xml_test_utils2.h"

#define LS		"LS"
#define TEST_XML_CORE	"Core"

int validate(xmlDocPtr doc, const char *document_name, const char *schema_str, int debug)
{
	int ret = -1;	
	xmlDocPtr schema_doc = NULL;
	xmlSchemaParserCtxtPtr parser_ctx = NULL;
	xmlSchemaPtr schema = NULL;
	xmlSchemaValidCtxtPtr valid_ctx = NULL;

	xmlChar *xmldata = xml_output(doc);
	if (xmldata == NULL) {
		goto out;
	} else if (debug) {
		printf("%s\n%s\n", document_name, xmldata);
	}
	xmlFree(xmldata);

	schema_doc = xmlReadFile(schema_str, NULL, XML_PARSE_NONET | XML_PARSE_NSCLEAN);
	if (!schema_doc) {
		return ret;
	}

	parser_ctx = xmlSchemaNewDocParserCtxt(schema_doc);
	if (!parser_ctx) {
		if (debug) {
			fprintf(stderr, "failed to create parser context: %s\n", schema_str);
		}
		goto out;
	}

	schema = xmlSchemaParse(parser_ctx);
	if (!schema) {
		if (debug) {
			fprintf(stderr, "failed to create schema parser: %s\n", schema_str);
		}
		goto out;
	}

	valid_ctx = xmlSchemaNewValidCtxt(schema);
	if (!valid_ctx) {
		if (debug) {
			fprintf(stderr, "failed to create schema valid context: %s\n", schema_str);
		}
		goto out;
	}

	if (debug) {
		fprintf(stdout, "loaded schema: %s\n", schema_str);
	}

	if (xmlSchemaValidateDoc(valid_ctx, doc)) {
		goto out;
	}

	ret = 0;
out:
	xmlSchemaFreeValidCtxt(valid_ctx);
	xmlSchemaFree(schema);
	xmlSchemaFreeParserCtxt(parser_ctx);
	xmlFreeDoc(schema_doc);
	return ret;
}

xmlChar *xml_output(xmlDocPtr doc)
{
	xmlChar *xml_buf = NULL;
	int buf_size = 0;

	xmlDocDumpFormatMemory(doc, &xml_buf, &buf_size, 1);

	return xml_buf;
}
