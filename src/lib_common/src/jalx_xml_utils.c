/**
 * @file jalx_xml_utils.c This file contains utility funtions for dealing
 * with XML.
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
#include <libxml/parser.h>

#include <jalop/jal_namespaces.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

// XML-Security-C (XSEC)
//#include <xsec/canon/XSECC14n20010315.hpp>
//#include <xsec/framework/XSECProvider.hpp>
//#include <xsec/dsig/DSIGReference.hpp>
//#include <xsec/dsig/DSIGKeyInfoX509.hpp>
//#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>
//#include <xsec/enc/XSCrypt/XSCryptCryptoBase64.hpp>
//#include <xsec/framework/XSECException.hpp>


// Xalan
//#ifndef XSEC_NO_XALAN
//#include <xalanc/XalanTransformer/XalanTransformer.hpp>
//XALAN_USING_XALAN(XalanTransformer)
//#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <string.h>
#include <time.h>

#include "jalx_xml_utils.h"
#include "jal_error_callback_internal.h"
#include "jal_alloc.h"
//#include "jal_bn2b64.hpp"
#include "jal_base64_internal.h"

#define JAL_XML_CORE "Core"

enum jal_status jalx_parse_xml_snippet(
		xmlNodePtr *ctx_node,
		const char *snippet)
{
	//Wrapper4InputSource *lsInput = NULL;
	//MemBufInputSource * inputSource = NULL;
	//DOMLSParser *parser = NULL;
	//DOMImplementation *impl = NULL;
	//DOMConfiguration *conf = NULL;

	if (!ctx_node) {
		return JAL_E_INVAL;
	}
	//impl = DOMImplementationRegistry::getDOMImplementation(JAL_XML_CORE);
	//parser = impl->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	//conf = parser->getDomConfig();
	//conf->setParameter(XMLUni::fgDOMEntities, false);
	//conf->setParameter(XMLUni::fgDOMNamespaces, true);
	// don't validate (can't since building a snippet
	//conf->setParameter(XMLUni::fgDOMValidate, false);
	// Enable schema validation
	//conf->setParameter(XMLUni::fgXercesSchema, false);
	// Enable schema validation
	//conf->setParameter(XMLUni::fgXercesSchemaFullChecking, false);
	// Enable full checking
	//conf->setParameter(XMLUni::fgXercesUseCachedGrammarInParse, false);
	// don't try and load unknown schemas
	//conf->setParameter(XMLUni::fgXercesLoadSchema, false);
	// take ownership of the doc
	//conf->setParameter(XMLUni::fgXercesUserAdoptsDOMDocument, true);

	//inputSource = new MemBufInputSource(reinterpret_cast<const XMLByte*>(snippet),
	//				strlen(snippet),
	//				(char*)NULL,
	//				false);
	//lsInput = new Wrapper4InputSource(inputSource);
	//DOMNode *child_node = NULL;
	//try {
	//	child_node = parser->parseWithContext(lsInput, ctx_node, DOMLSParser::ACTION_REPLACE_CHILDREN);
	//} catch(...) {
	//	// do nothing
	//}
	//delete (parser);
	//delete lsInput;
	//return (child_node != NULL)? JAL_OK : JAL_E_XML_PARSE;
	xmlDocPtr doc;
	//doc = xmlReadMemory(snippet, strlen(snippet), "noname.xml", NULL, 0);
	//doc = xmlParseDoc((xmlChar *) snippet);
	doc = xmlParseMemory(snippet, strlen(snippet));
	if (!doc) {
		return JAL_E_XML_PARSE;
	}
	*ctx_node = xmlDocGetRootElement(doc);
	return JAL_OK;
}

enum jal_status jalx_create_base64_element(
		xmlDocPtr doc,
		const uint8_t *buffer,
		const size_t buf_len,
		const xmlChar *namespace_uri,
		const xmlChar *elm_name,
		xmlNodePtr *new_elem)
{
	if (!doc || !buffer || (buf_len == 0) || !namespace_uri ||
		!elm_name || *new_elem) {
		return JAL_E_INVAL;
	}
	char *base64_val = NULL;
	xmlChar *xml_base64_val = NULL;

	base64_val = jal_base64_enc(buffer, buf_len);
	if (!base64_val) {
		// this should never actually happen since the input is
		// non-zero in length.
		return JAL_E_INVAL;
	}

	xml_base64_val = (xmlChar *)base64_val;

	//DOMElement *elm = doc->createElementNS(namespace_uri, elm_name);
	//elm->setTextContent(xml_base64_val);
	xmlNodePtr elm = xmlNewDocNode(doc, NULL, elm_name, NULL);
	xmlNsPtr ns = xmlNewNs(elm, namespace_uri, NULL);
	xmlSetNs(elm, ns);
	xmlNodeAddContent(elm, xml_base64_val);

	free(base64_val);
	*new_elem = elm;
	return JAL_OK;
}

