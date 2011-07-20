/**
 * @file jalp_send_helper.cpp This file contains functions for sending an xml buffer.
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

#include <jalop/jal_namespaces.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/dom/DOMDocument.hpp>

#include "jalp_xml_utils.hpp"
#include "jalp_app_metadata_xml.hpp"
#include "jalp_digest_internal.h"
#include "jalp_send_helper_internal.h"

XERCES_CPP_NAMESPACE_USE

static const XMLCh JALP_XML_MANIFEST[] = {	chLatin_M,
				chLatin_a,
				chLatin_n,
				chLatin_i,
				chLatin_f,
				chLatin_e,
				chLatin_s,
				chLatin_t,
				chNull };
const XMLCh JALP_XML_CORE[] = {
	chLatin_C, chLatin_o, chLatin_r, chLatin_e, chNull };

enum jal_status jalp_send_buffer_xml(jalp_context *ctx,
		struct jalp_app_metadata *app_meta, const uint8_t *buffer,
		const size_t buffer_size, enum jalp_connection_msg_type message_type)
{
	enum jal_status status;
	uint8_t *digest = NULL;
	DOMImplementation *impl = NULL;
	DOMElement *app_meta_elem = NULL;
	DOMDocument *doc = NULL;
	MemBufFormatTarget *xml_mem_buffer = NULL;
	size_t bsize = buffer_size;

	// if buffer can't be NULL, or buffer_size can't be 0, it 
	// should be checked in the function calling this one
	if (!ctx) {
		return JAL_E_INVAL;
	}

	// this function can only be used to send journal or log messages
	if (message_type != JALP_LOG_MSG && message_type != JALP_JOURNAL_MSG) {
		return JAL_E_INVAL;
	}

	if (app_meta) {
		impl = DOMImplementationRegistry::getDOMImplementation(JALP_XML_CORE);
		doc = impl->createDocument();
		status = jalp_app_metadata_to_elem(app_meta, ctx, NULL, doc, &app_meta_elem);
		if (status != JAL_OK) {
			goto out;
		}
		if (ctx->digest_ctx) {
			status = jalp_digest_buffer(ctx->digest_ctx,
					buffer, bsize,
					&digest);
			if (status != JAL_OK) {
				goto out;
			}
			DOMElement *reference_elem = NULL;
			status = jal_create_reference_elem(JAL_PAYLOAD_URI, ctx->digest_ctx->algorithm_uri,
					digest, ctx->digest_ctx->len, doc, &reference_elem);
			if (status != JAL_OK) {
				goto out;
			}

			XMLCh *namespace_uri = XMLString::transcode(JALP_XMLDSIG_URI);
			DOMElement *manifest = doc->createElementNS(namespace_uri, JALP_XML_MANIFEST);
			XMLString::release(&namespace_uri);
			manifest->appendChild(reference_elem);
			app_meta_elem->appendChild(manifest);
		}
		if (ctx->signing_key) {
			// TODO: sign the doc
		}
		status = jal_xml_output(doc, &xml_mem_buffer);
		if (status != JAL_OK) {
			goto out;
		}
		status = jalp_send_buffer(ctx, message_type,
			(void*) buffer, buffer_size,
			(void*) xml_mem_buffer->getRawBuffer(), xml_mem_buffer->getLen(), -1);
	} else {
		status = jalp_send_buffer(ctx, message_type,
			(void*) buffer, buffer_size,
			NULL, 0, -1);
	}

out:
	if (xml_mem_buffer) {
		delete xml_mem_buffer;
	}
	free(digest);
	if (doc) {
		doc->release();
	}
	return status;
}
