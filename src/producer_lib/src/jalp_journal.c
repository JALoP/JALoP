/**
 * @file jalp_journal.cpp Contains jalp journal functions
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

#include <jalop/jal_status.h>
#include <jalop/jalp_journal.h>
#include <jalop/jalp_app_metadata.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_journal.h>
#include "jalp_context_internal.h"
#include "jalp_connection_internal.h"
#include "jalp_app_metadata_xml.h"
#include "jal_xml_utils.h"
#include "jalp_digest_internal.h"
#include "jalp_send_helper_internal.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define JALP_XML_CORE "Core"
#define JALP_XML_MANIFEST "Manifest"
#define JALP_XML_JID "JID"

enum jal_status jalp_journal_fd(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		int fd)
{
	enum jal_status status;
	uint8_t *digest = NULL;
	xmlNodePtr app_meta_elem = NULL;
	xmlNodePtr last_elem = NULL;
	xmlDocPtr doc = NULL;
	xmlChar *buffer = NULL;

	if (!ctx || fd < 0) {
		return JAL_E_INVAL;
	}
	off_t file_sz = lseek(fd, 0, SEEK_END);

	if ((off_t)-1 == file_sz) {
		return JAL_E_BAD_FD;
	}

	if (app_meta) {
		doc = xmlNewDoc((xmlChar *)"1.0");
		status = jalp_app_metadata_to_elem(app_meta, ctx, doc, &app_meta_elem);
		if (status != JAL_OK) {
			goto out;
		}
		xmlDocSetRootElement(doc, app_meta_elem);
		if (ctx->digest_ctx) {
			status = jalp_digest_fd(ctx->digest_ctx, fd, &digest);
			if (status != JAL_OK) {
				goto out;
			}
			xmlNodePtr reference_elem = NULL;
			status = jal_create_reference_elem(JAL_PAYLOAD_URI, ctx->digest_ctx->algorithm_uri,
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
		status = jalp_send_buffer(ctx, JALP_JOURNAL_FD_MSG,
			NULL, file_sz,
			(void*) buffer, xmlStrlen(buffer), fd);
	} else {
		status = jalp_send_buffer(ctx, JALP_JOURNAL_FD_MSG,
			NULL, file_sz,
			NULL, 0, fd);
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
enum jal_status jalp_journal(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		const uint8_t *journal_buffer,
		const size_t journal_buffer_size)
{
	if (!ctx || !journal_buffer || (journal_buffer_size == 0)) {
		return JAL_E_INVAL;
	}

	return jalp_send_buffer_xml(ctx, app_meta, journal_buffer,
			journal_buffer_size, JALP_JOURNAL_MSG);
}

enum jal_status jalp_journal_path(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		const char *path)
{
	if (!ctx || !path) {
		return JAL_E_INVAL;
	}
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = jalp_journal_fd(ctx, app_meta, fd);
	close(fd);
	return ret;
}

