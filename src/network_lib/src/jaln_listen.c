/**
 * @file jaln_listen.c This file contains function definitions
 * related to listening for a remote peer to connect over the JALoP
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
#include "jaln_listen.h"

#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>

#include "jal_alloc.h"
#include "jaln_connection_callbacks_internal.h"
#include "jaln_connection_request.h"
#include "jaln_context.h"
#include "jaln_digest.h"
#include "jaln_encoding.h"
#include "jaln_init_msg_handler.h"
#include "jaln_message_helpers.h"
#include "jaln_publisher.h"
#include "jaln_publisher_callbacks_internal.h"
#include "jaln_session.h"
#include "jaln_subscriber.h"
#include "jaln_subscriber_callbacks_internal.h"
#include "jaln_tls.h"

axl_bool jaln_listener_handle_new_digest_channel_no_lock(jaln_context *ctx,
		VortexConnection *conn,
		const char *server_name,
		int new_chan_num,
		int paired_chan_num)
{
	if (!ctx || !conn || !server_name || 0 >= new_chan_num || 0 >= paired_chan_num) {
		return axl_false;
	}
	VortexChannel *chan = vortex_connection_get_channel(conn, new_chan_num);
	// setting '2' disables MIME generation completely.
	vortex_channel_set_automatic_mime(chan, 2);
	vortex_channel_set_serialize(chan, axl_true);
	char * server_name_cpy = jal_strdup(server_name);
	struct jaln_session *sess = jaln_ctx_find_session_by_rec_channel_no_lock(ctx, server_name_cpy, paired_chan_num);
	free(server_name_cpy);
	if (!sess) {
		return axl_false;
	}
	vortex_mutex_lock(&sess->lock);
	axl_bool ret = jaln_session_associate_digest_channel_no_lock(sess, chan, new_chan_num);
	vortex_mutex_unlock(&sess->lock);
	return ret;
}

axl_bool jaln_listener_handle_new_record_channel_no_lock(jaln_context *ctx,
		VortexConnection *conn,
		const char *server_name,
		int chan_num)
{
	// expect to have the ctx lock held
	if (!ctx || !conn || !server_name || (0 > chan_num)) {
		return axl_false;
	}
	struct jaln_session *session = jaln_session_create();
	session->rec_chan_num = chan_num;
	session->rec_chan = vortex_connection_get_channel(conn, chan_num);

	// The lock on ctx should already be held, so just increment the
	// count.
	ctx->ref_cnt++;
	session->jaln_ctx = ctx;
	session->ch_info->hostname = jal_strdup(server_name);
	if (JAL_OK != jaln_ctx_add_session_no_lock(ctx, session)) {
		jaln_session_unref(session);
		return axl_false;
	}

	// setting '2' disables MIME generation completely.
	vortex_channel_set_automatic_mime(session->rec_chan, 2);
	vortex_channel_set_serialize(session->rec_chan, axl_true);
	vortex_channel_set_received_handler(session->rec_chan, jaln_listener_init_msg_handler, session);
	vortex_channel_set_closed_handler(session->rec_chan, jaln_session_notify_unclean_channel_close, session);
	vortex_channel_set_close_handler(session->rec_chan, jaln_session_on_close_channel, session);
	return axl_true;
}

axl_bool jaln_listener_start_channel_no_lock(jaln_context *ctx,
		int chan_num,
		VortexConnection *conn,
		const char *server_name,
		const char *profile_content)
{
	int paired_channel = -1;

	if (profile_content &&
			(0 != strlen(profile_content))) {
		// have profile content, so this must be a 'digest' channel
		int matched = sscanf(profile_content, JALN_DGST_CHAN_FORMAT_STR, &paired_channel);
		if (!matched) {
			return axl_false;
		} else {
			axl_bool ret = jaln_listener_handle_new_digest_channel_no_lock(ctx, conn, server_name, chan_num, paired_channel);
			return ret;
		}
	} else {
		// no profile content, must be a 'record' channel
		axl_bool ret = jaln_listener_handle_new_record_channel_no_lock(ctx, conn, server_name, chan_num);
		return ret;
	}
	return axl_false;
}

axl_bool jaln_listener_start_channel_extended(
		__attribute__((unused)) const char *profile,
		int chan_num,
		VortexConnection *conn,
		__attribute__((unused)) const char *server_name,
		const char *profile_content,
		__attribute__((unused)) char **profile_content_reply,
		__attribute__((unused)) VortexEncoding encoding,
		axlPointer user_data)
{
	jaln_context *ctx = (jaln_context *) user_data;
	if (!ctx) {
		return axl_false;
	}
	const char *remote_host = vortex_connection_get_host(conn);
	vortex_mutex_lock(&ctx->lock);
	axl_bool ret = jaln_listener_start_channel_no_lock(ctx, chan_num, conn, remote_host, profile_content);
	vortex_mutex_unlock(&ctx->lock);
	return ret;
}

void jaln_listener_init_msg_handler(VortexChannel *chan, VortexConnection *conn,
		VortexFrame *frame, axlPointer user_data)
{
	char *msg = NULL;
	struct jaln_init_info *info = NULL;
	struct jaln_session *sess = (struct jaln_session *)user_data;
	struct jaln_connect_request *conn_req = NULL;
	if (!chan || !conn || !frame || !sess || !sess->jaln_ctx || !sess->jaln_ctx->conn_callbacks) {
		goto err_out;
	}
	const char *recv_msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (!recv_msg) {
		goto err_out;
	}
	if (JAL_OK != jaln_process_init(frame, &info)) {
		goto err_out;
	}

	conn_req = jaln_connect_request_create();
	conn_req->hostname = jal_strdup(vortex_connection_get_host(conn));
	conn_req->addr = jal_strdup(vortex_connection_get_host_ip(conn));
	conn_req->type = info->type;
	conn_req->jaln_version = JALN_JALOP_VERSION_ONE;

	// Implementation are required to support 'xml' encoding (i.e. no
	// encoding) and sha256 digests.
	if (!axl_list_lookup(info->encodings, jaln_string_list_case_insensitive_lookup_func, JALN_ENC_XML)) {
		axl_list_append(info->encodings, jal_strdup(JALN_ENC_XML));
	}
	if (!axl_list_lookup(info->digest_algs, jaln_string_list_case_insensitive_lookup_func, JALN_DGST_SHA256)) {
		axl_list_append(info->digest_algs, jal_strdup(JALN_DGST_SHA256));
	}

	jaln_axl_string_list_to_array(info->encodings, &conn_req->encodings, &conn_req->enc_cnt);
	jaln_axl_string_list_to_array(info->digest_algs, &conn_req->digests, &conn_req->dgst_cnt);
	conn_req->role = info->role;
	conn_req->jaln_agent = jal_strdup(info->peer_agent);

	int sel_enc= -1;
	int sel_dgst = -1;
	int enc_cnt = conn_req->enc_cnt;
	int dgst_cnt = conn_req->dgst_cnt;

	int cnt = 0;
	for (cnt = 0; cnt < enc_cnt; cnt++) {
		axlPointer found = axl_list_lookup(sess->jaln_ctx->xml_encodings,
				jaln_string_list_case_insensitive_lookup_func,
				conn_req->encodings[cnt]);
		if (found) {
			break;
		}
	}
	if (cnt < conn_req->enc_cnt) {
		sel_enc = cnt;
	}

	for (cnt = 0; cnt < dgst_cnt; cnt++) {
		axlPointer found = axl_list_lookup(sess->jaln_ctx->dgst_algs,
				jaln_digest_lookup_func,
				conn_req->digests[cnt]);
		if (found) {
			break;
		}
	}

	if (cnt < conn_req->dgst_cnt) {
		sel_dgst = cnt;
	}
	enum jaln_connect_error err =
		sess->jaln_ctx->conn_callbacks->connect_request_handler(conn_req, &sel_enc, &sel_dgst, sess->jaln_ctx->user_data);
	struct jal_digest_ctx *dgst_ctx = NULL;
	if (JALN_CE_ACCEPT == err) {
		if (0 > sel_enc || sel_enc >= enc_cnt) {
			err |= JALN_CE_UNSUPPORTED_ENCODING;
		}
		if (0 > sel_dgst || sel_dgst >= dgst_cnt) {
			err |= JALN_CE_UNSUPPORTED_DIGEST;
		} else {
			dgst_ctx = (struct jal_digest_ctx*)axl_list_lookup(sess->jaln_ctx->dgst_algs,
					jaln_digest_lookup_func,
					conn_req->digests[sel_dgst]);
			if (!dgst_ctx) {
				// special case for sha256
				if (0 == strcasecmp(conn_req->digests[sel_dgst], JALN_DGST_SHA256)) {
					dgst_ctx = sess->jaln_ctx->sha256_digest;
				} else {
					err |= JALN_CE_UNSUPPORTED_DIGEST;
				}
			}
		}
	}
	size_t msg_len;
	int msg_no = vortex_frame_get_msgno(frame);
	if (JALN_CE_ACCEPT != err) {
		jaln_create_init_nack_msg(err, &msg, &msg_len);
		vortex_channel_send_err(chan, msg, msg_len, msg_no);
		goto err_out;
	}
	vortex_mutex_lock(&sess->lock);

	sess->dgst = dgst_ctx;
	sess->ch_info->type = info->type;

	// The init message indicates the role the remote side wants to play,
	// i.e. if the remote indicates it wishes to be a publisher, then the
	// we need to be a subscriber here.
	if (JALN_ROLE_SUBSCRIBER == info->role) {
		sess->role = JALN_ROLE_PUBLISHER;
	} else {
		sess->role = JALN_ROLE_SUBSCRIBER;
	}
	switch (sess->role) {
	case(JALN_ROLE_SUBSCRIBER):
		jaln_configure_sub_session_no_lock(chan, sess);
		break;
	case(JALN_ROLE_PUBLISHER):
		jaln_configure_pub_session_no_lock(chan, sess);
		break;
	default:
		goto err_out;
	}
	vortex_mutex_unlock(&sess->lock);
	jaln_create_init_ack_msg(conn_req->encodings[sel_enc], conn_req->digests[sel_dgst], &msg, &msg_len);
	vortex_channel_send_rpy(chan, msg, msg_len, msg_no);
	if (JALN_ROLE_SUBSCRIBER == sess->role) {
		jaln_subscriber_send_subscribe_request(sess);
	}

	goto out;
err_out:
	vortex_channel_close(chan, NULL);
out:
	jaln_init_info_destroy(&info);
	jaln_connect_request_destroy(&conn_req);
	free(msg);
	return;
}

enum jal_status jaln_listen(
		jaln_context *ctx,
		const char *host,
		const char *port,
		void *user_data)
{
	if (!ctx || !host || !port) {
		return JAL_E_INVAL;
	}
	vortex_mutex_lock(&ctx->lock);

	if (!ctx->vortex_ctx ||
		ctx->is_connected) {
		goto err_out;
	}
	ctx->is_connected = axl_true;

	if (!jaln_subscriber_callbacks_is_valid(ctx->sub_callbacks) &&
		!jaln_publisher_callbacks_is_valid(ctx->pub_callbacks)) {
		goto err_out;
	}
	if (!jaln_connection_callbacks_is_valid(ctx->conn_callbacks)) {
		goto err_out;
	}

	ctx->user_data = user_data;

	VortexCtx *v_ctx = ctx->vortex_ctx;

	vortex_mutex_unlock(&ctx->lock);

	vortex_profiles_register_extended_start(v_ctx, JALN_JALOP_1_0_PROFILE,
			jaln_listener_start_channel_extended,
			ctx);

	vortex_profiles_register(v_ctx, JALN_JALOP_1_0_PROFILE,
			NULL, NULL,
			NULL, NULL,
			NULL, NULL);

	VortexConnection * v_conn = vortex_listener_new(v_ctx, host, port, NULL, NULL);

	if (!v_conn) {
		return JAL_E_INVAL;
	}

	vortex_mutex_lock(&ctx->lock);

	if (ctx->private_key && ctx->public_cert && ctx->peer_certs) {
		// Filters out any non-TLS connections
		vortex_listener_set_on_connection_accepted(ctx->vortex_ctx,
						jaln_tls_on_connection_accepted,
						NULL);
	}

	ctx->listener_conn = v_conn;
	vortex_mutex_unlock(&ctx->lock);

	return JAL_OK;

err_out:
	vortex_mutex_unlock(&ctx->lock);
	return JAL_E_INVAL;
}

enum jal_status jaln_listener_wait(
		jaln_context *ctx)
{
	if (!ctx) {
		return JAL_E_INVAL;
	}
	vortex_mutex_lock(&ctx->lock);
	if (!ctx->vortex_ctx ||
		!ctx->is_connected ||
		!ctx->listener_conn) {
		goto err_out;
	}

	VortexCtx *v_ctx = ctx->vortex_ctx;
	vortex_mutex_unlock(&ctx->lock);

	vortex_listener_wait(v_ctx);
	return JAL_OK;

err_out:
	vortex_mutex_unlock(&ctx->lock);
	return JAL_E_INVAL;
}

enum jal_status jaln_listener_shutdown(jaln_context *ctx)
{
	if (!ctx) {
		return JAL_E_INVAL;
	}
	vortex_mutex_lock(&ctx->lock);
	if (!ctx->vortex_ctx ||
		!ctx->is_connected ||
		!ctx->listener_conn) {
		goto err_out;
	}

	VortexConnection *v_conn = ctx->listener_conn;
	vortex_mutex_unlock(&ctx->lock);

	vortex_listener_shutdown(v_conn, axl_true);
	return JAL_OK;

err_out:
	vortex_mutex_unlock(&ctx->lock);
	return JAL_E_INVAL;
}

