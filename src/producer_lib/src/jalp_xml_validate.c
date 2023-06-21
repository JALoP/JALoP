/**
 * @file jalp_xml_validate.c This file defines functions to validate
 * xml files against a schema
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (C) 2022 The National Security Agency (NSA)
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
/// \cond DO_NOT_DOCUMENT

#define LIBXML_SCHEMAS_ENABLED

/// \endcond

#include <string.h>
#include <libxml/xmlschemastypes.h>

#include "jalp_xml_validate.h"

/**
 * Function to validate xml doc against xsd
 * 
 * @param jalp_context Current jalop producer context
 * @param doc XML doc to be validated
 * @param xsdFileName Name of XSD file for the schema that the XML file needs to be validated against
 * 
 * @return 0 if the XML file validates, integer greater than 0 if it doesn't validate, integer less than 0 if error occurs
 */
enum jal_status jalp_validate_xml(jalp_context *jalp_ctx, xmlDocPtr doc, const char *xsdFileName)
{
	xmlSchemaParserCtxtPtr parseCtxt = NULL;
	xmlSchemaPtr jaf_schema = NULL;

	if(jalp_ctx->jaf_validCtxt == NULL) 
	{
		if((xsdFileName == NULL) || (strcmp(xsdFileName, "")) == 0) {
			return JAL_E_INVAL;
		}

		if(access(xsdFileName, F_OK) != 0) {
			return JAL_E_INVAL;
		}

		//Setup parser context
		parseCtxt = xmlSchemaNewParserCtxt(xsdFileName);
	
		if(parseCtxt == NULL) {
			return JAL_E_XML_PARSE;
		}

		//Parse schema
		if( (jaf_schema = xmlSchemaParse(parseCtxt)) == NULL) {
			xmlSchemaFreeParserCtxt(parseCtxt);
			return JAL_E_XML_SCHEMA;
		}
		xmlSchemaFreeParserCtxt(parseCtxt);

		jalp_ctx->jaf_validCtxt = xmlSchemaNewValidCtxt(jaf_schema);

		if(jalp_ctx->jaf_validCtxt == NULL)
		{
			xmlSchemaFree(jaf_schema);
			return JAL_E_XML_SCHEMA;
		}
	}
	// validate the xml document..returns 0 on success
	int ret = xmlSchemaValidateDoc(jalp_ctx->jaf_validCtxt, doc);
	if(ret != 0) {
		return JAL_E_XML_PARSE;
	}

	return JAL_OK;
}

