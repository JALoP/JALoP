/**
 * @file jaln_handle_init_replies.c This file contains function
 * definitions for internal library functions related to processing responses
 * to 'initialize' messages (init-ack/init-nack).
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

#include "jaln_context.h"
#include "jaln_digest.h"
#include "jaln_encoding.h"
#include "jaln_handle_init_replies.h"
#include "jaln_strings.h"

int jaln_handle_initialize_nack(jaln_session *sess,
		VortexFrame *frame)
{
	int err_cnt = 0;
	if (sess == NULL || frame == NULL || !sess->jaln_ctx ||
			!sess->jaln_ctx->conn_callbacks) {
		return axl_false;
	}
	char *err_strs[4];
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_UNAUTHORIZED_MODE)) {
		err_strs[err_cnt++] = JALN_HDRS_UNAUTHORIZED_MODE;
	}
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_UNSUPPORTED_MODE)) {
		err_strs[err_cnt++] = JALN_HDRS_UNSUPPORTED_MODE;
	}
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_UNSUPPORTED_ENCODING)) {
		err_strs[err_cnt++] = JALN_HDRS_UNSUPPORTED_ENCODING;
	}
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_UNSUPPORTED_DIGEST)) {
		err_strs[err_cnt++] = JALN_HDRS_UNSUPPORTED_DIGEST;
	}
	struct jaln_connect_nack nack;
	memset(&nack, 0, sizeof(nack));
	nack.ch_info = sess->ch_info;
	nack.error_list = err_strs;
	nack.error_cnt = err_cnt;
	sess->jaln_ctx->conn_callbacks->connect_nack(&nack, sess->jaln_ctx->user_data);
	return axl_true;
}

axl_bool jaln_handle_initialize_ack(jaln_session *session,
		enum jaln_role role,
		VortexFrame *frame)
{
	int ret = axl_true;
	char *encoding = NULL;
	char *digest = NULL;
	char *agent = NULL;

	if (!session || !session->rec_chan) {
		return axl_false;
	}
	VortexConnection *v_conn = vortex_channel_get_connection(session->rec_chan);

	if (!frame || !session->ch_info || !session->jaln_ctx ||
			!session->jaln_ctx->conn_callbacks) {
		goto err_out;
	}
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_ENCODING))
	{
		const char *tmp = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_ENCODING);
		encoding = strdup(tmp);
	}
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_DIGEST))
	{
		const char *tmp = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_DIGEST);
		digest = strdup(tmp);
	}
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_AGENT))
	{
		const char *tmp = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_AGENT);
		agent = strdup(tmp);
	}

	jaln_context *ctx = session->jaln_ctx;

	if (!encoding || !digest) {
		goto err_out;
	}
	if (axl_list_is_empty(ctx->xml_encodings)) {
		if (0 != strcasecmp(encoding, JALN_ENC_XML)) {
			goto err_out;
		}
	} else {
		axlPointer ptr = axl_list_lookup(ctx->xml_encodings,
				jaln_string_list_case_insensitive_lookup_func,
				encoding);
		if (!ptr) {
			// the response contained an unknown encoding
			goto err_out;
		}
	}

	if (axl_list_is_empty(ctx->dgst_algs)) {
		if (0 != strcasecmp(digest, JALN_DGST_SHA256)) {
			goto err_out;
		}
		session->dgst = ctx->sha256_digest;
	} else {
		axlPointer ptr = axl_list_lookup(ctx->dgst_algs, jaln_digest_lookup_func, digest);
		if (!ptr) {
			// the response contained an unknown digest
			goto err_out;
		}
		session->dgst = (struct jal_digest_ctx*) ptr;
	}

	session->ch_info->digest_method = digest;
	session->ch_info->encoding = encoding;
	// set to NULL so they don't get freed in the cleanup code.
	digest = NULL;
	encoding = NULL;

	struct jaln_connect_ack ack;
	memset(&ack, 0, sizeof(ack));
	ack.hostname = session->ch_info->hostname;
	ack.addr = session->ch_info->addr;
	ack.jaln_version = JALN_JALOP_VERSION_ONE;
	ack.jaln_agent = agent;
	ack.mode = role;
	session->jaln_ctx->conn_callbacks->connect_ack(&ack, ctx->user_data);
	goto out;

err_out:
	ret = axl_false;
	vortex_connection_shutdown(v_conn);
out:
	free(agent);
	free(digest);
	free(encoding);
	return ret;
}

