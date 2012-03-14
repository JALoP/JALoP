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

#include "jalx_xml_utils.h"
#include "jalpx_app_metadata_xml.h"
#include "jalp_digest_internal.h"
#include "jalp_send_helper_internal.h"

#define JALP_XML_MANIFEST "Manifest"
#define JALP_XML_CORE "Core"
#define JALP_XML_JID "JID"

enum jal_status jalpx_send_buffer_xml(jalp_context *ctx,
		struct jalp_app_metadata *app_meta, const uint8_t *buffer,
		const size_t buffer_size, enum jalp_connection_msg_type message_type)
{
	enum jal_status status;
	uint8_t *digest = NULL;
	xmlNodePtr app_meta_elem = NULL;
	xmlNodePtr last_elem = NULL;
	xmlDocPtr doc = NULL;
	xmlChar *xml_mem_buffer = NULL;
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
		doc = xmlNewDoc((xmlChar *)"1.0");
		status = jalpx_app_metadata_to_elem(app_meta, ctx, doc, &app_meta_elem);
		if (status != JAL_OK) {
			goto out;
		}
		xmlDocSetRootElement(doc, app_meta_elem);

		if (ctx->digest_ctx) {
			status = jalp_digest_buffer(ctx->digest_ctx,
					buffer, bsize,
					&digest);
			if (status != JAL_OK) {
				goto out;
			}
			xmlNodePtr reference_elem = NULL;
			status = jalx_create_reference_elem(JAL_PAYLOAD_URI, ctx->digest_ctx->algorithm_uri,
					digest, ctx->digest_ctx->len, doc, &reference_elem);
			if (status != JAL_OK) {
				goto out;
			}

			xmlChar *namespace_uri = (xmlChar *)JAL_XMLDSIG_URI;
			xmlNodePtr manifest = xmlNewDocNode(doc, NULL,
							(xmlChar *)JALP_XML_MANIFEST,
							NULL);
			xmlNsPtr ns = xmlNewNs(manifest, namespace_uri, NULL);
			xmlSetNs(manifest, ns);
			xmlAddChild(manifest, reference_elem);
			xmlAddChild(app_meta_elem, manifest);
			last_elem = manifest;
		}
		if (ctx->signing_key) {
			const xmlChar *id = xmlGetProp(app_meta_elem, (xmlChar *)JALP_XML_JID);
			status = jalx_add_signature_block(ctx->signing_key, ctx->signing_cert, doc, last_elem, (char *)id);
			xmlFree((void*)id);
			if (status != JAL_OK) {
				goto out;
			}
		}
		status = jalx_xml_output(doc, &xml_mem_buffer);
		if (status != JAL_OK) {
			goto out;
		}
		status = jalp_send_buffer(ctx, message_type,
			(void*) buffer, buffer_size,
			(void*) xml_mem_buffer, xmlStrlen(xml_mem_buffer), -1);
	} else {
		status = jalp_send_buffer(ctx, message_type,
			(void*) buffer, buffer_size,
			NULL, 0, -1);
	}

out:
	if (xml_mem_buffer) {
		free(xml_mem_buffer);
	}
	free(digest);
	if (doc) {
		xmlFreeDoc(doc);
	}
	return status;
}
