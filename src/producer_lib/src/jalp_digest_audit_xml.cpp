/**
 * @file jalp_digest_audit_xml.cpp Provides the implementation to parse,
 * validate, and digest an audit XML file.
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
#include "jalp_digest_audit_xml.h"
#include "jal_asprintf_internal.h"
#include "jalp_xml_utils.hpp"
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/dom/DOMImplementationRegistry.hpp>
#include <xercesc/dom/DOMImplementationLS.hpp>
#include <xercesc/dom/DOMLSParser.hpp>
#include <xercesc/dom/DOMConfiguration.hpp>
#include <xercesc/dom/DOMErrorHandler.hpp>
#include <xercesc/dom/DOMLocator.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>

#include <stdio.h>
#define XML_CEE_SCHEMA "cee-cls-xml-event.xsd"
XERCES_CPP_NAMESPACE_USE

static const XMLCh JALP_XML_CORE[] = {	chLatin_C,
					chLatin_o,
					chLatin_r,
					chLatin_e,
					chNull
			};

class AuditErrorHandler: public DOMErrorHandler
{
public:
	AuditErrorHandler(): failed(false)
	{
		// do nothing
	}
	virtual bool handleError(const DOMError& e)
	{
		bool failure = !(e.getSeverity() == DOMError::DOM_SEVERITY_WARNING);
		if (failure) {
			failed = true;
		}
		return !failed;
	}
	bool failed;
};
enum jal_status jalp_digest_audit_record(const struct jal_digest_ctx *ctx,
		char *schema_root,
		uint8_t *buffer,
		size_t buf_len,
		uint8_t**digest_value,
		int *digest_len)
{
	if (!ctx || !schema_root || !buffer || (buf_len == 0) || !digest_value
			|| *digest_value || !digest_len) {
		return JAL_E_INVAL;
	}

	char *ceeSchema = NULL;
	DOMDocument *parsed_doc = NULL;
	Wrapper4InputSource *lsInput = NULL;
	DOMLSParser *parser = NULL;
	DOMImplementation *impl = NULL;
	DOMConfiguration *conf = NULL;
	MemBufInputSource *byte_stream = NULL;
	enum jal_status ret = JAL_OK;

	jal_asprintf(&ceeSchema, "%s/" XML_CEE_SCHEMA, schema_root);

	impl = DOMImplementationRegistry::getDOMImplementation(JALP_XML_CORE);
	parser = impl->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	conf = parser->getDomConfig();
	// perform normalization of elements, i.e. ignore any processing instructions
	// or comments for the purposes of validation.
	conf->setParameter(XMLUni::fgDOMDatatypeNormalization, true);
	// do not keep entity references in the doc
	//conf->setParameter(XMLUni::fgDOMEntities, false);
	// process namespaces
	conf->setParameter(XMLUni::fgDOMNamespaces, true);
	// Validate the document against
	conf->setParameter(XMLUni::fgDOMValidate, true);
	// Enable schema validation
	conf->setParameter(XMLUni::fgXercesSchema, true);
	// Enable schema validation
	conf->setParameter(XMLUni::fgXercesSchemaFullChecking, true);
	// Enable full checking
	conf->setParameter(XMLUni::fgXercesUseCachedGrammarInParse, true);
	// don't try and load unknown schemas
	conf->setParameter(XMLUni::fgXercesLoadSchema, false);
	// handle schemas that import types from more than one other schema
	conf->setParameter(XMLUni::fgXercesHandleMultipleImports, true);
	// Let the parser keep ownership of the document
	conf->setParameter(XMLUni::fgXercesUserAdoptsDOMDocument, false);
	// Set the error handler, otherwise xerces will quietly fail
	// validation, but still create a document.
	AuditErrorHandler eh;
	conf->setParameter(XMLUni::fgDOMErrorHandler, &eh);

	if (!parser->loadGrammar(ceeSchema, Grammar::SchemaGrammarType, true)) {
		ret = JAL_E_XML_SCHEMA;
		goto out;
	}
	byte_stream = new MemBufInputSource(buffer, buf_len, "audit_record.xml");
	lsInput = new Wrapper4InputSource(byte_stream);
	parsed_doc = parser->parse(lsInput);
	if (eh.failed || parsed_doc == NULL) {
		ret = JAL_E_XML_PARSE;
		goto out;
	}
	ret = jal_digest_xml_data(ctx, parsed_doc, digest_value, digest_len);
out:
	delete parser;
	delete lsInput;
	free(ceeSchema);
	return ret;
}

