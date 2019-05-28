/**
 * @file jalp_digest_audit_xml.c Provides the implementation to parse,
 * validate, and digest an audit XML file.
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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>

#include <libxml/tree.h>
#include <libxml/xmlschemas.h>

#include "jalp_digest_audit_xml.h"
#include "jal_asprintf_internal.h"
#include "jal_xml_utils.h"

#define XML_JAF_SCHEMA "event.xsd" //TODO: what is the canonical name?
#define JALP_XML_CORE "Core"

enum jal_status jalp_digest_audit_record(const struct jal_digest_ctx *ctx,
		const char *schema_root,
		const uint8_t *buffer,
		const size_t buf_len,
		uint8_t**digest_value,
		int *digest_len)
{
	if (!ctx || !schema_root || !buffer || (buf_len == 0) || !digest_value
			|| *digest_value || !digest_len) {
		return JAL_E_INVAL;
	}

	enum jal_status ret = JAL_E_XML_PARSE;
	xmlDocPtr parsed_doc = NULL;
	xmlDocPtr schema_doc = NULL;
	xmlSchemaParserCtxtPtr parser_ctx = NULL;
	xmlSchemaPtr schema = NULL;
	xmlSchemaValidCtxtPtr valid_ctx = NULL;
	char *jafSchema = NULL;
	
	jal_asprintf(&jafSchema, "%s/" XML_JAF_SCHEMA, schema_root);

	parsed_doc = xmlParseMemory((const char *)buffer, buf_len);

	schema_doc = xmlReadFile(jafSchema, NULL, XML_PARSE_NONET);
	if (!schema_doc) {
		ret = JAL_E_XML_SCHEMA;
		goto out;
	}

	parser_ctx = xmlSchemaNewDocParserCtxt(schema_doc);
	if (!parser_ctx) {
		ret = JAL_E_XML_SCHEMA;
		goto out;
	}

	schema = xmlSchemaParse(parser_ctx);
	if (!schema) {
		ret = JAL_E_XML_SCHEMA;
		goto out;
	}

	valid_ctx = xmlSchemaNewValidCtxt(schema);
	if (!valid_ctx) {
		ret = JAL_E_XML_SCHEMA;
		goto out;
	}

	if (xmlSchemaValidateDoc(valid_ctx, parsed_doc)) {
		goto out;
	}
	
	ret = jal_digest_xml_data(ctx, parsed_doc, digest_value, digest_len);
out:
	xmlSchemaFreeValidCtxt(valid_ctx);
	xmlSchemaFree(schema);
	xmlSchemaFreeParserCtxt(parser_ctx);
	xmlFreeDoc(schema_doc);
	xmlFreeDoc(parsed_doc);
	free(jafSchema);
	return ret;
}

