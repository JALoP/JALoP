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
#include <libxml/uri.h>

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

#define REFERENCE "Reference"
#define DIGESTMETHOD "DigestMethod"
#define ALGORITHM "Algorithm"
#define DIGESTVALUE "DigestValue"
#define URI "URI"
#define JAL_XML_CORE "Core"
#define JAL_XML_TRANSFORMS "Transforms"
#define JAL_XML_TRANSFORM "Transform"
#define JAL_XML_ALGORITHM "Algorithm"
#define JAL_XML_WITH_COMMENTS "http://www.w3.org/2006/12/xml-c14n11#WithComments"
#define JAL_XML_DS "ds"
#define JAL_XML_XPOINTER_ID_BEG "#xpointer(id('"
#define JAL_XML_XPOINTER_ID_END "'))"

enum jal_status jalx_parse_xml_snippet(
		xmlNodePtr *ctx_node,
		const char *snippet)
{
	xmlDocPtr doc = xmlParseDoc((xmlChar *) snippet);
	if (!doc) {
		return JAL_E_XML_PARSE;
	}
	if (*ctx_node) {
		xmlAddChild(*ctx_node, xmlDocGetRootElement(doc));
	}
	else {
		*ctx_node = xmlDocGetRootElement(doc);
	}
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

	xmlNodePtr elm = xmlNewDocNode(doc, NULL, elm_name, NULL);
	xmlNsPtr ns = xmlNewNs(elm, namespace_uri, NULL);
	xmlSetNs(elm, ns);
	xmlNodeAddContent(elm, xml_base64_val);

	free(base64_val);
	*new_elem = elm;
	return JAL_OK;
}

// Returns a timestamp of the format YYYY-MM-DDTHH:MM:SS[+-]HH:MM
char *jalx_get_timestamp()
{
	char *ftime = (char*)jal_malloc(26);
	char *tz_offset = (char*)jal_malloc(7);
	time_t rawtime;
	struct tm *tm;
	time(&rawtime);
	tm = localtime(&rawtime);
	strftime(ftime, 26, "%Y-%m-%dT%H:%M:%S", tm);
	/* Timezone
	 * Inserts ':' into [+-]HHMM for [+-]HH:MM */
	strftime(tz_offset, 7, "%z", tm);
	tz_offset[6] = '\0';
	tz_offset[5] = tz_offset[4];
	tz_offset[4] = tz_offset[3];
	tz_offset[3] = ':';
	strcat(ftime, tz_offset);
	free(tz_offset);
	return ftime;

}

enum jal_status jalx_create_reference_elem(
		const char *reference_uri,
		const char *digest_method,
		uint8_t *digest_buf,
		uint64_t len,
		xmlDocPtr doc,
		xmlNodePtr *elem)
{
	if(!doc || !elem || *elem || len <= 0 || !digest_method || !digest_buf) {
		return JAL_E_XML_CONVERSION;
	}

	xmlChar *namespace_uri = (xmlChar *)JAL_XMLDSIG_URI;
	xmlChar *xml_reference_uri = (xmlChar *)reference_uri;
	xmlChar *xml_digest_method = (xmlChar *)digest_method;

	xmlNodePtr reference_elem = xmlNewDocNode(doc, NULL, (xmlChar *) REFERENCE, NULL);
	xmlNodePtr digestmethod_elem = NULL;
	xmlNodePtr digestvalue_elem = NULL;

	enum jal_status ret = JAL_OK;

	if(reference_uri) {
		xmlURIPtr uri = xmlParseURI(reference_uri);
		if (!uri) {
			xmlFreeNodeList(reference_elem);
			ret = JAL_E_INVAL_URI;
			goto err_out;
		}
		xmlFreeURI(uri);
		xmlSetProp(reference_elem, (xmlChar *) URI, xml_reference_uri);
	}

	ret = jalx_create_base64_element(doc, digest_buf, len, namespace_uri,
					(xmlChar *)DIGESTVALUE, &digestvalue_elem);
	if (ret != JAL_OK) {
		goto err_out;
	}

	digestmethod_elem = xmlNewChild(reference_elem, NULL, (xmlChar *) DIGESTMETHOD, NULL);
	xmlSetProp(digestmethod_elem, (xmlChar *)ALGORITHM, xml_digest_method);

	xmlAddChild(reference_elem, digestvalue_elem);

	*elem = reference_elem;

	return JAL_OK;

err_out:

	return ret;
}

enum jal_status jalx_create_audit_transforms_elem(
		xmlDocPtr doc,
		xmlNodePtr *new_elem)
{
	if (!new_elem || *new_elem || !doc) {
		return JAL_E_XML_CONVERSION;
	}

	xmlChar *namespace_uri = (xmlChar *)JAL_XMLDSIG_URI;

	xmlNodePtr out_elem = xmlNewDocNode(doc, NULL, (xmlChar *) JAL_XML_TRANSFORMS, NULL);
	xmlNsPtr ns = xmlNewNs(out_elem, namespace_uri, NULL);
	xmlSetNs(out_elem, ns);

	xmlNodePtr transform_elem = xmlNewChild(
						out_elem, NULL,
						(xmlChar *) JAL_XML_TRANSFORM,
						NULL);

	xmlSetProp(transform_elem,
			(xmlChar *) JAL_XML_ALGORITHM, (xmlChar *) JAL_XML_WITH_COMMENTS);

	*new_elem = out_elem;

	return JAL_OK;
}

enum jal_status jalx_xml_output(
		xmlDocPtr doc,
		xmlChar **buffer)
{
	if (!doc || !buffer || *buffer) {
		return JAL_E_INVAL;
	}

	xmlChar *xmlbuff = NULL;
	int buffersize;

	xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);

	*buffer = xmlbuff;

	return JAL_OK;
}
