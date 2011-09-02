/**
 * @file jalls_handle_log.cpp This file contains functions to handle a log
 * to the jal local store.
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

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <xercesc/dom/DOM.hpp>

#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

#include "jal_xml_utils.hpp"
#include "jal_alloc.h"
#include "jalls_msg.h"
#include "jalls_context.h"
#include "jalls_handler.h"
#include "jalls_xml_utils.hpp"
#include "jalls_system_metadata_xml.hpp"
#include "jalls_handle_log.hpp"

XERCES_CPP_NAMESPACE_USE

static const XMLCh JALLS_XML_MANIFEST[] = {
	chLatin_M, chLatin_a, chLatin_n, chLatin_i, chLatin_f, chLatin_e, chLatin_s, chLatin_t, chNull };

static const XMLCh JALLS_XML_JID[] = {
	chLatin_J, chLatin_I, chLatin_D, chNull };

extern "C" int jalls_handle_log(struct jalls_thread_context *thread_ctx, uint64_t data_len, uint64_t meta_len)
{
	if (!thread_ctx || !(thread_ctx->ctx) || (!thread_ctx->signing_key)) {
		return -1; //should never happen.
	}
	struct jal_digest_ctx *digest_ctx = NULL;

	XMLCh *namespace_uri = XMLString::transcode(JAL_SYS_META_NAMESPACE_URI);
	XMLCh *manifest_namespace_uri = XMLString::transcode(JAL_XMLDSIG_URI);

	int debug = thread_ctx->ctx->debug;
	int err;
	int ret = -1;

	uint8_t *data_buf = (uint8_t *)malloc(data_len);
	uint8_t *app_meta_buf = NULL;

	DOMDocument *app_meta_doc = NULL;
	DOMDocument *sys_meta_doc = NULL;

	void *instance = NULL;
	//get the log

	struct iovec iov[1];
	iov[0].iov_base = data_buf;
	iov[0].iov_len = data_len;

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_iov = iov;
	msgh.msg_iovlen = 1;

	ssize_t bytes_recieved;

	if (data_len > 0) {
		bytes_recieved = jalls_recvmsg_helper(thread_ctx->fd, &msgh, debug);
		if (bytes_recieved < 0) {
			if (debug) {
				fprintf(stderr, "could not recieve log data\n");
			}
			goto err_out;
		}
	}

	//get first break string. If the log was empty, this is omitted
	err = jalls_handle_break(thread_ctx->fd);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "%s: could not recieve first BREAK\n", __FILE__);
		}
		goto err_out;
	}

	//get the app_metadata
	err = jalls_handle_app_meta(&app_meta_buf, meta_len, thread_ctx->fd, debug);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not recieve the application metadata\n");
		}
		goto err_out;
	}

	//get second break string
	err = jalls_handle_break(thread_ctx->fd);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not recieve second BREAK\n");
		}
		goto err_out;
	}

	//Parse and Validate the app metadata
	err = jalls_parse_app_metadata(app_meta_buf, (size_t)meta_len, thread_ctx->ctx->schemas_root, &app_meta_doc, debug);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not parse the application metadata\n");
		}
		goto err_out;
	}

	//digest the log data
	enum jal_status jal_err;
	digest_ctx = jal_sha256_ctx_create();
	uint8_t *digest;

	instance = digest_ctx->create();
	digest = (uint8_t *)jal_malloc(digest_ctx->len);

	jal_err = digest_ctx->init(instance);
	if(jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not init sha256 digest\n");
		}
		goto err_out;
	}

	jal_err = digest_ctx->update(instance, data_buf, data_len);
	if(jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not digest the log\n");
		}
		goto err_out;
	}
	size_t digest_length;
	digest_length = digest_ctx->len;
	jal_err = digest_ctx->final(instance, digest, &digest_length);
	if(jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not digest the log\n");
		}
		goto err_out;
	}

	//create system metadata
	err = jalls_create_system_metadata(JALLS_JOURNAL, thread_ctx->ctx->hostname, thread_ctx->ctx->system_uuid,
		thread_ctx->fd, thread_ctx->peer_pid, thread_ctx->peer_uid, &sys_meta_doc);
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "could not create system metadata\n");
		}
		goto err_out;
	}

	//append a manifest element to the system metadata
	DOMElement *manifest;
	manifest = sys_meta_doc->createElementNS(manifest_namespace_uri, JALLS_XML_MANIFEST);
	DOMElement *sys_meta_root;
	sys_meta_root = sys_meta_doc->getDocumentElement();
	sys_meta_root->appendChild(manifest);
	DOMElement *reference_elem;
	reference_elem = NULL;
	jal_err = jal_create_reference_elem(JAL_PAYLOAD_URI, digest_ctx->algorithm_uri,
		digest, digest_length, sys_meta_doc, &reference_elem);
	if (jal_err != JAL_OK) {
		if (debug) {
			fprintf(stderr, "could not create system metadata manifest\n");
		}
		goto err_out;
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




	/*
	 * TODO: insert into the database
	jal_err = jaldb_insert_log_record(thread_ctx->db_ctx, NULL, sys_meta_doc,
		app_meta_doc, NULL);
	if (jal_err != JAL_OK) {
		goto err_out;
	}
	*/

	ret = 0;

err_out:
	XMLString::release(&namespace_uri);
	XMLString::release(&manifest_namespace_uri);
	jal_digest_ctx_destroy(&digest_ctx);
	free(data_buf);
	free(app_meta_buf);
	return -1;
}
