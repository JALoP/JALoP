/**
 * @file jalls_handle_audit.cpp This file contains functions to handle an audit
 * to the jal local store.
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

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <xercesc/dom/DOM.hpp>

#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

#include "jal_xml_utils.hpp"
#include "jalls_msg.h"
#include "jalls_context.h"
#include "jalls_handler.h"
#include "jalls_xml_utils.hpp"
#include "jaldb_context.hpp"
#include "jalls_system_metadata_xml.hpp"
#include "jalls_handle_audit.hpp"

XERCES_CPP_NAMESPACE_USE

static const XMLCh JALLS_XML_MANIFEST[] = {
	chLatin_M, chLatin_a, chLatin_n, chLatin_i, chLatin_f, chLatin_e, chLatin_s, chLatin_t, chNull };

static const XMLCh JALLS_XML_JID[] = {
	chLatin_J, chLatin_I, chLatin_D, chNull };

extern "C" int jalls_handle_audit(struct jalls_thread_context *thread_ctx, uint64_t data_len, uint64_t meta_len)
{
	if (!thread_ctx || !(thread_ctx->ctx) || (!thread_ctx->signing_key)) {
		return -1; //should never happen.
	}

	XMLCh *namespace_uri = XMLString::transcode(JAL_SYS_META_NAMESPACE_URI);
	XMLCh *manifest_namespace_uri = XMLString::transcode(JAL_XMLDSIG_URI);

	int ret = -1;

	int debug = thread_ctx->ctx->debug;

	uint8_t *data_buf = (uint8_t *)malloc(data_len);
	uint8_t *app_meta_buf = NULL;

	std::string sid = "";
	std::string source = "";
	enum jaldb_status db_err = JALDB_OK;
	//get the payload audit

	struct iovec iov[1];
	iov[0].iov_base = data_buf;
	iov[0].iov_len = data_len;

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_iov = iov;
	msgh.msg_iovlen = 1;

	ssize_t bytes_received;

	int err;

	DOMDocument *sys_meta_doc = NULL;
	DOMDocument *app_meta_doc = NULL;
	DOMDocument *audit_doc = NULL;

	struct jal_digest_ctx *digest_ctx = NULL;
	uint8_t *digest = NULL;

	bytes_received = jalls_recvmsg_helper(thread_ctx->fd, &msgh, debug);
	if (bytes_received < 0) {
		if (debug) {
			fprintf(stderr, "could not receive audit data\n");
		}
		goto err_out;
	}

	//validate/parse the audit
	err = jalls_parse_audit(data_buf, data_len, thread_ctx->ctx->schemas_root, &audit_doc, debug);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not parse the audit\n");
		}
		goto err_out;
	}

	//get first break string
	err = jalls_handle_break(thread_ctx->fd);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not receive first BREAK\n");
		}
		goto err_out;
	}

	//get the app_metadata
	if (meta_len) {
		err = jalls_handle_app_meta(&app_meta_buf, meta_len, thread_ctx->fd, debug);
		if (err < 0) {
			if (debug) {
				fprintf(stderr, "could not receive application metadata\n");
			}
			goto err_out;
		}

		//parse/validate the app metadata
		err = jalls_parse_app_metadata(app_meta_buf, meta_len, thread_ctx->ctx->schemas_root, &app_meta_doc, debug);
		if (err < 0) {
			if (debug) {
				fprintf(stderr, "could not parse the application metadata\n");
			}
			goto err_out;
		}
	}

	//get second break string
	err = jalls_handle_break(thread_ctx->fd);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not receive second BREAK\n");
		}
		goto err_out;
	}

	err = jalls_create_system_metadata(JALLS_AUDIT, thread_ctx->ctx->hostname, thread_ctx->ctx->system_uuid,
	        thread_ctx->fd, thread_ctx->peer_pid, thread_ctx->peer_uid, &sys_meta_doc);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not create system metadata\n");
		}
		goto err_out;
	}

        //digest the audit
	enum jal_status jal_err;
	digest_ctx = jal_sha256_ctx_create();
	int digest_len;
	jal_err = jal_digest_xml_data(digest_ctx, audit_doc, &digest, &digest_len);

	//add the manifest to the system metadata
	DOMElement *manifest;
	manifest = sys_meta_doc->createElementNS(manifest_namespace_uri, JALLS_XML_MANIFEST);
	DOMElement *sys_meta_root;
	sys_meta_root = sys_meta_doc->getDocumentElement();
	sys_meta_root->appendChild(manifest);
	DOMElement *reference_elem;
	reference_elem = NULL;
	DOMElement *first_elem;
	first_elem = NULL;
	jal_err = jal_create_reference_elem(JAL_PAYLOAD_URI, digest_ctx->algorithm_uri,
		digest, digest_len, sys_meta_doc, &reference_elem);
	if (jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not create system metadata manifest\n");
		}
		goto err_out;
	}
	DOMElement *transforms_elem;
	transforms_elem = NULL;
	jal_err = jal_create_audit_transforms_elem(sys_meta_doc, &transforms_elem);
	if (jal_err != JAL_OK) {
		if(debug) {
			fprintf(stderr, "could not create system metadata manifest\n");
		}
		goto err_out;
	}
	first_elem = reference_elem->getFirstElementChild();
	if (!first_elem) {
		reference_elem->appendChild(transforms_elem);
	}
	else {
		reference_elem->insertBefore(transforms_elem, first_elem);
	}
	manifest->appendChild(reference_elem);

	//add signature to the system metadata
	jal_err = jal_add_signature_block(thread_ctx->signing_key, thread_ctx->signing_cert,
		sys_meta_doc, sys_meta_root, manifest, sys_meta_root->getAttribute(JALLS_XML_JID));
	if (jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not create system metadata signature\n");
		}
		goto err_out;
	}

	db_err = jaldb_insert_audit_record(
			thread_ctx->db_ctx,
			source,
			sys_meta_doc,
			app_meta_doc,
			audit_doc,
			sid);
	if (db_err != JALDB_OK) {
		if (debug) {
			fprintf(stderr, "could not insert audit record into database\n");
		}
		goto err_out;
	}

	ret = 0;

err_out:
	XMLString::release(&namespace_uri);
	XMLString::release(&manifest_namespace_uri);
	jal_digest_ctx_destroy(&digest_ctx);
	free(digest);
	free(data_buf);
	free(app_meta_buf);
	if (sys_meta_doc) {
		delete sys_meta_doc;
	}
	if (app_meta_doc) {
		delete app_meta_doc;
	}
	if (audit_doc) {
		delete audit_doc;
	}
	return ret;
}
