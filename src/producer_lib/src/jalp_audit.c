/**
 * @file jalp_audit.c Function to send audit records to the local store.
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

#include <jalop/jalp_audit.h>
#include <jalop/jal_status.h>
#include <jalop/jalp_app_metadata.h>
#include <jalop/jal_namespaces.h>
#include "jalp_context_internal.h"
#include "jalp_connection_internal.h"
#include "jalp_app_metadata_xml.h"
#include "jal_xml_utils.h"
#include "jal_asprintf_internal.h"
#include "jalp_xml_validate.h"

#define JALP_XML_CORE		"Core"
#define JALP_XML_MANIFEST	"Manifest"
#define JALP_XML_JID		"JID"
#define XML_JAF_SCHEMA_NEW	"eventList.xsd"
#define XML_JAF_SCHEMA_OLD	"event.xsd"

enum jal_status jalp_audit(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		const uint8_t *audit_buffer,
		const size_t audit_buffer_size)
{

	enum jal_status status = JAL_OK;
	uint8_t *digest = NULL;
	xmlNodePtr app_meta_elem = NULL;
	xmlNodePtr last_elem = NULL;
	xmlDocPtr doc = NULL;
	xmlDocPtr validated_doc = NULL;
	xmlChar *buffer = NULL;
	int digest_len = 0;
	char *eventList_schema = NULL;
	char *event_schema = NULL;

	if (!ctx || ctx->schema_root == NULL || !audit_buffer || (audit_buffer_size == 0)) {
		status = JAL_E_INVAL;
		goto out;
	}

	int flags = jalp_context_get_flags(ctx);
	// Only if schema validation and/or digest calculation are requested, expect that the
	// input data is xml and attempt to parse into a document
	if((JAF_VALIDATE_XML & flags) || ctx->digest_ctx) {
		validated_doc = xmlReadMemory((const char *)audit_buffer, strlen((const char *)audit_buffer), "", NULL, 0);
		if(NULL == validated_doc) {
			// If we expected XML and don't get XML, report a parse failure
			status = JAL_E_XML_PARSE;
			goto out;
		}
	}

	// If schema validation has been requested, do it here
	if(flags & JAF_VALIDATE_XML)
	{
		// If the schema context is not already cached
		if(!ctx->jaf_validCtxt)
		{
			jal_asprintf(&eventList_schema, "%s/" XML_JAF_SCHEMA_NEW, ctx->schema_root);

			status = jalp_validate_xml(ctx, validated_doc, eventList_schema);

			if (status == JAL_E_INVAL) {
				// a JAL_E_INVAL return means the XML_JAF_SCHEMA_NEW file doesn't exist.
				// any other return value is an error.
				// Older versions use event.xsd, fall back to this only if we did not
				// already load the eventList.xsd
				jal_asprintf(&event_schema, "%s/" XML_JAF_SCHEMA_OLD, ctx->schema_root);

				status = jalp_validate_xml(ctx, validated_doc, event_schema);

				if (status != JAL_OK) {
					goto out;
				}
			}
			if (status != JAL_OK) {
				goto out;
			}
			free(eventList_schema);
			eventList_schema = NULL;
			if(event_schema != NULL){
				free(event_schema);
				event_schema = NULL;
			}
		}
		else // always validate xml if the JAF_VALIDATE_XML is set...schema context is cached
		{
			// validate the xml document..0 == ok else error
			int ret = xmlSchemaValidateDoc(ctx->jaf_validCtxt, validated_doc);
			if (ret != 0) {
				status = JAL_E_XML_PARSE;
				goto out;
			}
		}
	}

	if (app_meta) {
		doc = xmlNewDoc((xmlChar *)"1.0");

		status = jalp_app_metadata_to_elem(app_meta, ctx, doc, &app_meta_elem);
		if (status != JAL_OK) {
			goto out;
		}
		xmlDocSetRootElement(doc, app_meta_elem);

		// We guarantee above that we have an xml document if digest calculation is requested
		if (ctx->digest_ctx) {
			// generate digest of (validated) xml document
			status = jal_digest_xml_data(ctx->digest_ctx, validated_doc, &digest, &digest_len);
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
		size_t tmp = 0;
		status = jal_xml_output(doc, &buffer, &tmp);
		if (status != JAL_OK) {
			goto out;
		}
		status = jalp_send_buffer(ctx, JALP_AUDIT_MSG,
			(void *) audit_buffer, audit_buffer_size,
			(void *) buffer, xmlStrlen(buffer), -1);
	} else {
		status = jalp_send_buffer(ctx, JALP_AUDIT_MSG,
			(void *) audit_buffer, audit_buffer_size,
			NULL, 0, -1);
	}
out:
	if (buffer) {
		xmlFree(buffer);
	}
	free(digest);
	if (doc) {
		xmlFreeDoc(doc);
	}
	if (validated_doc) {
		xmlFreeDoc(validated_doc);
	}
	if(eventList_schema != NULL){
		free(eventList_schema);
	}
	if(event_schema != NULL){
		free(event_schema);
	}
	return status;
}
