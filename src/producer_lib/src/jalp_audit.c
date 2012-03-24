/**
 * @file jalp_audit.cpp Function to send audit records to the local store.
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

#include <jalop/jalp_audit.h>
#include <jalop/jal_status.h>
#include <jalop/jalp_app_metadata.h>
#include <jalop/jal_namespaces.h>
#include "jalp_context_internal.h"
#include "jalp_connection_internal.h"
#include "jalp_app_metadata_xml.h"
#include "jal_xml_utils.h"
#include "jalp_digest_audit_xml.h"

#define JALP_XML_CORE		"Core"
#define JALP_XML_MANIFEST	"Manifest"
#define JALP_XML_JID		"JID"

enum jal_status jalp_audit(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		const uint8_t *audit_buffer,
		const size_t audit_buffer_size)
{

	enum jal_status status;
	uint8_t *digest = NULL;
	xmlNodePtr app_meta_elem = NULL;
	xmlNodePtr last_elem = NULL;
	xmlDocPtr doc = NULL;
	xmlChar *buffer = NULL;
	int digest_len = 0;

	if (!ctx || !audit_buffer || (audit_buffer_size == 0)) {
		status = JAL_E_INVAL;
		goto out;
	}
	
	if (app_meta) {
		doc = xmlNewDoc((xmlChar *)"1.0");

		status = jalp_app_metadata_to_elem(app_meta, ctx, doc, &app_meta_elem);
		if (status != JAL_OK) {
			goto out;
		}
		xmlDocSetRootElement(doc, app_meta_elem);

		if (ctx->digest_ctx) {
			status = jalp_digest_audit_record(ctx->digest_ctx, ctx->schema_root,
					audit_buffer, audit_buffer_size, &digest, &digest_len);
			if (status != JAL_OK) {
				goto out;
			}
			xmlNodePtr reference_elem = NULL;
			status = jal_create_reference_elem(JAL_PAYLOAD_URI, ctx->digest_ctx->algorithm_uri,
					digest, digest_len, doc, &reference_elem);
			if (status != JAL_OK) {
				goto out;
			}
			xmlNodePtr transforms_elem = NULL;
			status = jal_create_audit_transforms_elem(doc, &transforms_elem);
			if (status != JAL_OK) {
				goto out;
			}
			xmlNodePtr first_elem = NULL;
			first_elem = jal_get_first_element_child(reference_elem);
			if (!first_elem) {
				xmlAddChild(reference_elem, transforms_elem);
			} else {
				xmlAddPrevSibling(first_elem, transforms_elem);
			}
			xmlChar *jal_ns = (xmlChar *)JAL_XMLDSIG_URI;
			xmlNodePtr manifest = xmlNewDocNode(doc, NULL,
							(xmlChar *)JALP_XML_MANIFEST,
							NULL);
			xmlNsPtr ns = xmlNewNs(manifest, jal_ns, NULL);
			xmlSetNs(manifest, ns);
			xmlAddChild(manifest, reference_elem);
			xmlAddChild(app_meta_elem, manifest);
			last_elem = manifest;
		}
		if (ctx->signing_key) {
			const xmlChar *id = xmlGetProp(app_meta_elem, (xmlChar *)JALP_XML_JID);
			status = jal_add_signature_block(ctx->signing_key, ctx->signing_cert, doc, last_elem, (char *)id);
			xmlFree((void*)id);
			if (status != JAL_OK) {
				goto out;
			}
		}
		status = jal_xml_output(doc, &buffer);
		if (status != JAL_OK) {
			goto out;
		}
		status = jalp_send_buffer(ctx, JALP_AUDIT_MSG,
			(void *) audit_buffer, audit_buffer_size,
			(void *) buffer, xmlStrlen(buffer), -1);
	} else {
		status = jalp_send_buffer(ctx, JALP_AUDIT_MSG,
			(void *) audit_buffer, audit_buffer_size,
			NULL, 0, 0);
	}
out:
	if (buffer) {
		free(buffer);
	}
	free(digest);
	if (doc) {
		xmlFreeDoc(doc);
	}
	return status;
}
