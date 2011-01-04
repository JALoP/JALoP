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

#include <jalop/jal_status.h>
#include <jalop/jalp_journal.h>
#include <jalop/jalp_app_metadata.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_journal.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/XMLUni.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/dom/DOMElement.hpp>
#include <xercesc/dom/DOMImplementationRegistry.hpp>
#include "jalp_context_internal.h"
#include "jalp_connection_internal.h"
#include "jalp_app_metadata_xml.hpp"
#include "jal_xml_utils.hpp"
#include "jalp_digest_internal.h"
#include "jalp_send_helper_internal.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
XERCES_CPP_NAMESPACE_USE

static const XMLCh JALP_XML_CORE[] = {	chLatin_C,
				chLatin_o,
				chLatin_r,
				chLatin_e,
				chNull };

static const XMLCh JALP_XML_MANIFEST[] = {	chLatin_M,
				chLatin_a,
				chLatin_n,
				chLatin_i,
				chLatin_f,
				chLatin_e,
				chLatin_s,
				chLatin_t,
				chNull };

const XMLCh JALP_XML_JID[] = {
	chLatin_J, chLatin_I, chLatin_D, chNull };

enum jal_status jalp_journal_fd(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		int fd)
{
	enum jal_status status;
	uint8_t *digest = NULL;
	DOMImplementation *impl = NULL;
	DOMElement *app_meta_elem = NULL;
	DOMDocument *doc = NULL;
	MemBufFormatTarget *buffer = NULL;

	if (!ctx || fd < 0) {
		return JAL_E_INVAL;
	}
	off_t file_sz = lseek(fd, 0, SEEK_END);

	if ((off_t)-1 == file_sz) {
		return JAL_E_BAD_FD;
	}

	if (app_meta) {
		impl = DOMImplementationRegistry::getDOMImplementation(JALP_XML_CORE);
		doc = impl->createDocument();
		status = jalp_app_metadata_to_elem(app_meta, ctx, doc, &app_meta_elem);
		if (status != JAL_OK) {
			goto out;
		}
		doc->appendChild(app_meta_elem);
		DOMElement *last_element = NULL;
		if (ctx->digest_ctx) {
			status = jalp_digest_fd(ctx->digest_ctx, fd, &digest);
			if (status != JAL_OK) {
				goto out;
			}
			DOMElement *reference_elem = NULL;
			status = jal_create_reference_elem(JAL_PAYLOAD_URI, ctx->digest_ctx->algorithm_uri,
					digest, ctx->digest_ctx->len, doc, &reference_elem);
			if (status != JAL_OK) {
				goto out;
			}

			XMLCh *namespace_uri = XMLString::transcode(JAL_XMLDSIG_URI);
			DOMElement *manifest = doc->createElementNS(namespace_uri, JALP_XML_MANIFEST);
			XMLString::release(&namespace_uri);
			manifest->appendChild(reference_elem);
			app_meta_elem->appendChild(manifest);
			last_element = manifest;
		}
		if (ctx->signing_key) {
			const XMLCh *id = app_meta_elem->getAttribute(JALP_XML_JID);
			status = jal_add_signature_block(ctx->signing_key, ctx->signing_cert, doc,
					app_meta_elem, last_element, id);
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
			(void*) buffer->getRawBuffer(), buffer->getLen(), fd);
	} else {
		status = jalp_send_buffer(ctx, JALP_JOURNAL_FD_MSG,
			NULL, file_sz,
			NULL, 0, fd);
	}

out:
	if (buffer) {
		delete buffer;
	}
	free(digest);
	if (doc) {
		doc->release();
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

