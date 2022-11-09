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
#include <unistd.h>

#include <libxml/tree.h>
#include <libxml/xmlschemas.h>

#include "jalp_digest_audit_xml.h"
#include "jal_asprintf_internal.h"
#include "jal_xml_utils.h"
#include "jalp_context_internal.h"

#define XML_JAF_SCHEMA_OLD "event.xsd"
#define XML_JAF_SCHEMA_NEW "eventList.xsd"
#define JALP_XML_CORE "Core"

enum jal_status jalp_digest_audit_record(jalp_context *jalp_ctx,
		const uint8_t *buffer,
		const size_t buf_len,
		uint8_t **digest_value,
		int *digest_len)
{
	if (!jalp_ctx || !jalp_ctx->schema_root || !buffer || (buf_len == 0) || !digest_value
			|| *digest_value || !digest_len) {
		return JAL_E_INVAL;
	}

    const struct jal_digest_ctx *ctx = jalp_ctx->digest_ctx;
	enum jal_status ret = JAL_E_XML_PARSE;
	xmlSchemaParserCtxtPtr parser_ctx = NULL;
	xmlSchemaValidCtxtPtr valid_ctx = NULL;
	char *jafSchema = NULL;
	xmlDocPtr parsed_doc = NULL;
	xmlDocPtr schema_doc = NULL;

	parsed_doc = xmlParseMemory((const char *)buffer, buf_len);

	if(!jalp_ctx->jaf_schema) // cache schema
	{
		// Newer versions of the JAF schemas use eventList.xsd, try this first
		jal_asprintf(&jafSchema, "%s/" XML_JAF_SCHEMA_NEW, jalp_ctx->schema_root);
		if(0 == access(jafSchema, F_OK)) {
			schema_doc = xmlReadFile(jafSchema, NULL, XML_PARSE_NONET);
			// If the file existed, but failed to load, abort immediately
			if(!schema_doc) {
				ret = JAL_E_XML_SCHEMA;
				goto out;
			}
		}
	
		// Older versions use event.xsd, fall back to this only if we did not
		// already attempt to load the eventList.xsd
		if (!schema_doc) {
			free(jafSchema);
			jafSchema = NULL;
			jal_asprintf(&jafSchema, "%s/" XML_JAF_SCHEMA_OLD, jalp_ctx->schema_root);
	
			if(0 == access(jafSchema, F_OK)) {
				schema_doc = xmlReadFile(jafSchema, NULL, XML_PARSE_NONET);
				// If the file existed, but failed to load, abort immediately
				if(!schema_doc) {
					ret = JAL_E_XML_SCHEMA;
					goto out;
				}
			}
		}
	
		// If both of these schemas do not exist, abort
		if (!schema_doc) {
			ret = JAL_E_XML_SCHEMA;
			goto out;
		}
	
		parser_ctx = xmlSchemaNewDocParserCtxt(schema_doc);
		if (!parser_ctx) {
			ret = JAL_E_XML_SCHEMA;
			goto out;
		}
	
		jalp_ctx->jaf_schema = xmlSchemaParse(parser_ctx);
		if (!jalp_ctx->jaf_schema) {
			ret = JAL_E_XML_SCHEMA;
			goto out;
		}
	}
	
	valid_ctx = xmlSchemaNewValidCtxt(jalp_ctx->jaf_schema);
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
	xmlSchemaFreeParserCtxt(parser_ctx);
	xmlFreeDoc(parsed_doc);
	if(schema_doc) {
		xmlFreeDoc(schema_doc);
	}
	free(jafSchema);
	return ret;
}


