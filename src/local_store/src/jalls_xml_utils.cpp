/**
 * @file jalls_xml_utils.cpp This file contains functions to parse and
 * validate xml for the jalop local store.
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

#include <stdio.h>
#include <openssl/pem.h>

#include <xercesc/dom/DOM.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>

#include "jal_alloc.h"
#include "jalls_xml_utils.hpp"
#include "jalls_handler.h"

XERCES_CPP_NAMESPACE_USE

static const XMLCh JALLS_XML_CORE[] = {
	chLatin_C, chLatin_o, chLatin_r, chLatin_e, chNull };

#define APP_META_ID "app_meta.xml"
#define AUDIT_ID "audit.xml"

class MyErrorHandler: public DOMErrorHandler
{
public:
	MyErrorHandler(bool debug_in): debug(debug_in), failed(false) {
		// do nothing
	}
	virtual bool handleError(const DOMError& e)
	{
		bool failure = !(e.getSeverity() == DOMError::DOM_SEVERITY_WARNING);
		if (failure) {
			failed = true;
		}
		if (debug && failure) {
			DOMLocator *loc = e.getLocation();
			const char *severity = failure ? "error: " : "warning: ";
			char *message = XMLString::transcode(e.getMessage());
			char *uri = XMLString::transcode(loc->getURI());
			printf("%s: line %lld, col %lld\n\t %s%s\n", uri,
				(long long) loc->getLineNumber(),
				(long long) loc->getColumnNumber(),
				severity, message);
			XMLString::release(&message);
			XMLString::release(&uri);
		}
		// Return true to continue processing as if the error didn't
		// occur.
		return true;
	}
	bool debug;
	bool failed;
};

void jalls_get_schema_path(char **dest, const char *schemas_root, const char *schema)
{
	size_t len = strlen(schemas_root) + strlen(schema) + 2;
	char *path = (char *)jal_malloc(sizeof(char) * len);

	strncpy(path, schemas_root, len);
	strcat(path, "/");
	strcat(path, schema);

	*dest = path;
}

int jalls_parse_app_metadata(void *buf, size_t size, char *schemas_root, DOMDocument **doc, int debug)
{
	MyErrorHandler eh(debug);
	int ret = -1;
	char *schema_path = NULL;
	DOMDocument *parsed_doc = NULL;

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(JALLS_XML_CORE);
	DOMLSParser *parser = impl->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	DOMConfiguration *conf = parser->getDomConfig();

	// perform normalization of elements, i.e. ignore any processing instructions or comments for the purposes of validation.
	conf->setParameter(XMLUni::fgDOMDatatypeNormalization, true);
	// process namespaces
	conf->setParameter(XMLUni::fgDOMNamespaces, true);
	// Validate the document against
	conf->setParameter(XMLUni::fgDOMValidate, true);
	// Enable schemas
	conf->setParameter(XMLUni::fgXercesSchema, true);
	// Enable schema validation
	conf->setParameter(XMLUni::fgXercesSchemaFullChecking, true);
	// Enable full checking
	conf->setParameter(XMLUni::fgXercesUseCachedGrammarInParse, true);
	// don't try and load unknown schemas
	conf->setParameter(XMLUni::fgXercesLoadSchema, false);
	// handle schemas that import types from more than one other schema
	conf->setParameter(XMLUni::fgXercesHandleMultipleImports, true);
	// Let the user own the document
	conf->setParameter(XMLUni::fgXercesUserAdoptsDOMDocument, true);
	// Set the error handler so we can print info about errors.
	conf->setParameter(XMLUni::fgDOMErrorHandler, &eh);

	// although not strictly needed, bufId is set to something non-null since printf() crashes on some platforms if passed NULL
	// for a '%s' argument. adoptBuffer is false because the caller owns the buffer.
	MemBufInputSource *xmldata = new MemBufInputSource((XMLByte *)buf, (XMLSize_t)size, APP_META_ID, false);

	// again, adoptBuffer is false because the caller owns the buffer, and memorymanager is null because it is not needed.
	Wrapper4InputSource *lsInput = new Wrapper4InputSource(xmldata, false, NULL);

	jalls_get_schema_path(&schema_path, schemas_root, JALLS_XML_SCHEMA_DTD);
	parser->loadGrammar(schema_path, Grammar::DTDGrammarType, true);
	if (eh.failed) {
		if (debug) {
			fprintf(stderr, "failed to load schema: %s\n", schema_path);
		}
		goto out;
        }
	free(schema_path);
	schema_path = NULL;

	jalls_get_schema_path(&schema_path, schemas_root, JALLS_XML_DSIG_SCHEMA);
	parser->loadGrammar(schema_path, Grammar::SchemaGrammarType, true);
	if (eh.failed) {
		if (debug) {
			fprintf(stderr, "failed to load schema: %s\n", schema_path);
		}
		goto out;
	}
	free(schema_path);
	schema_path = NULL;

	jalls_get_schema_path(&schema_path, schemas_root, JALLS_XML_APP_META_TYPES_SCHEMA);
	parser->loadGrammar(schema_path, Grammar::SchemaGrammarType, true);
	if (eh.failed) {
		if (debug) {
			fprintf(stderr, "failed to load schema: %s\n", schema_path);
		}
		goto out;
	}
	free(schema_path);
	schema_path = NULL;

	jalls_get_schema_path(&schema_path, schemas_root, JALLS_XML_APP_META_SCHEMA);
	parser->loadGrammar(schema_path, Grammar::SchemaGrammarType, true);
	if (eh.failed) {
		if (debug) {
			fprintf(stderr, "failed to load schema: %s\n", schema_path);
		}
		goto out;
	}
	free(schema_path);
	schema_path = NULL;

	parsed_doc = parser->parse(lsInput);
	if (parsed_doc == NULL || eh.failed) {
		if (parsed_doc) {
			delete (parsed_doc);
		}
		if (debug) {
			fprintf(stderr, "app_metadata parse failed.\n");
		}
		goto out;
	}

	*doc = parsed_doc;
	ret = 0;

out:
	free(schema_path);
	delete xmldata;
	delete parser;
	delete lsInput;
	return ret;

}

int jalls_parse_audit(void *buf, size_t size, char *schemas_root, DOMDocument **doc, int debug)
{

	MyErrorHandler eh(debug);
	int ret = -1;
	char *schema_path = NULL;
	DOMDocument *parsed_doc = NULL;

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(JALLS_XML_CORE);
	DOMLSParser *parser = impl->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	DOMConfiguration *conf = parser->getDomConfig();

	// perform normalization of elements, i.e. ignore any processing instructions or comments for the purposes of validation.
	conf->setParameter(XMLUni::fgDOMDatatypeNormalization, true);
	// process namespaces
	conf->setParameter(XMLUni::fgDOMNamespaces, true);
	// Validate the document against
	conf->setParameter(XMLUni::fgDOMValidate, true);
	// Enable schemas
	conf->setParameter(XMLUni::fgXercesSchema, true);
	// Enable schema validation
	conf->setParameter(XMLUni::fgXercesSchemaFullChecking, true);
	// Enable full checking
	conf->setParameter(XMLUni::fgXercesUseCachedGrammarInParse, true);
	// don't try and load unknown schemas
	conf->setParameter(XMLUni::fgXercesLoadSchema, false);
	// handle schemas that import types from more than one other schema
	conf->setParameter(XMLUni::fgXercesHandleMultipleImports, true);
	// Let the user own the document
	conf->setParameter(XMLUni::fgXercesUserAdoptsDOMDocument, true);
	// Set the error handler so we can print info about errors.
	conf->setParameter(XMLUni::fgDOMErrorHandler, &eh);


	// although not strictly needed, bufId is set to something non-null since printf() crashes on some platforms if passed NULL
	// for a '%s' argument. adoptBuffer is false because the caller owns the buffer.
	MemBufInputSource *xmldata = new MemBufInputSource((XMLByte *)buf, (XMLSize_t)size, AUDIT_ID, false);

	// again, adoptBuffer is false because the caller owns the buffer, and memorymanager is null because it is not needed.
	Wrapper4InputSource *lsInput = new Wrapper4InputSource(xmldata, false, NULL);

	jalls_get_schema_path(&schema_path, schemas_root, JALLS_XML_AUDIT_SCHEMA);
	parser->loadGrammar(schema_path, Grammar::SchemaGrammarType, true);
	if (eh.failed) {
		if (debug) {
			fprintf(stderr, "failed to load schema: %s\n", schema_path);
		}
		goto out;
	}

	parsed_doc = parser->parse(lsInput);
	if (parsed_doc == NULL || eh.failed) {
		if (parsed_doc) {
			delete parsed_doc;
		}
		if (debug) {
			fprintf(stderr, "audit parse failed.\n");
		}
		goto out;
	}

	*doc = parsed_doc;
	ret = 0;

out:
	free(schema_path);
	delete xmldata;
	delete parser;
	delete lsInput;
	return ret;
}
