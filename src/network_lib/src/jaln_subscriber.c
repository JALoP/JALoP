/**
 * @file jaln_subscriber.c This file contains function
 * declarations for internal library functions related to a
 * subscribere session
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

#include <vortex.h>
#include <vortex_tls.h>
#include <jalop/jaln_network.h>

#include "jal_alloc.h"

#include "jaln_connection.h"
#include "jaln_connection_callbacks_internal.h"
#include "jaln_context.h"
#include "jaln_message_helpers.h"
#include "jaln_handle_init_replies.h"
#include "jaln_session.h"
#include "jaln_subscriber.h"
#include "jaln_subscriber_callbacks_internal.h"
#include "jaln_subscriber_state_machine.h"

void jaln_subscriber_on_frame_received(VortexChannel *chan, VortexConnection *conn,
		VortexFrame *frame, axlPointer user_data)
{
	jaln_session *session = (jaln_session*) user_data;
	if (!session || !session->sub_data || !session->sub_data->curr_frame_handler) {
		// something's not right
		vortex_connection_close(conn);
		return;
	}
	session->sub_data->curr_frame_handler(session, chan, conn, frame);
}

jaln_session *jaln_subscriber_create_session(jaln_context *ctx, const char *host, enum jaln_record_type type)
{
	if (!ctx || !host) {
		return NULL;
	}

	switch (type) {
	case JALN_RTYPE_JOURNAL:
	case JALN_RTYPE_AUDIT:
	case JALN_RTYPE_LOG:
		break;
	default:
		return NULL;
	}
	jaln_session *session = NULL;

	session = jaln_session_create();
	struct jaln_channel_info *ch_info = session->ch_info;

	jaln_ctx_ref(ctx);
	session->jaln_ctx = ctx;
	session->role = JALN_ROLE_SUBSCRIBER;
	session->sub_data = jaln_sub_data_create();
	session->sub_data->curr_frame_handler = jaln_subscriber_unexpected_frame_handler;
	ch_info->hostname = jal_strdup(host);
	ch_info->type = type;

	return session;
}

void jaln_subscriber_on_connection_close(__attribute__((unused)) VortexConnection *conn,
					axlPointer data)
{
	struct jaln_connection *jal_conn = (struct jaln_connection *) data;

	if (!jal_conn || !jal_conn->jaln_ctx || !jal_conn->jaln_ctx->conn_callbacks) {
		return;
	}

	jaln_context *ctx = jal_conn->jaln_ctx;

	vortex_mutex_lock(&ctx->lock);
	ctx->conn_callbacks->on_connection_close(jal_conn, ctx->user_data);
	vortex_mutex_unlock(&ctx->lock);
}

struct jaln_connection *jaln_subscribe(
		jaln_context *ctx,
		const char *host,
		const char *port,
		const int data_classes,
		enum jaln_publish_mode mode,
		void *user_data)
{
	if (!ctx || !host || !port ||
		!ctx->vortex_ctx ||
		!jaln_subscriber_callbacks_is_valid(ctx->sub_callbacks) ||
		!jaln_connection_callbacks_is_valid(ctx->conn_callbacks)) {
		return NULL;
	}


	vortex_mutex_lock(&ctx->lock);
	if (ctx->is_connected) {
		vortex_mutex_unlock(&ctx->lock);
		return NULL;
	}

	ctx->is_connected = axl_true;
	ctx->user_data = user_data;

	if (ctx->private_key && ctx->public_cert && ctx->peer_certs) {
		// Enable TLS for every connection and do not allow failures.
		vortex_tls_set_auto_tls(ctx->vortex_ctx, axl_true, axl_false, NULL);
	}

	vortex_mutex_unlock(&ctx->lock);

	if (!(data_classes & JALN_RTYPE_ALL)) {
		return NULL;
	}
	VortexConnection *v_conn = NULL;
	VortexCtx *v_ctx = ctx->vortex_ctx;
	v_conn = vortex_connection_new(v_ctx, host, port, NULL, NULL);
	if (!vortex_connection_is_ok(v_conn, axl_true)) {
		return NULL;
	}
	struct jaln_connection *jconn = jaln_connection_create();
	jconn->jaln_ctx = ctx;
	jconn->v_conn = v_conn;

	vortex_connection_set_on_close_full(v_conn, jaln_subscriber_on_connection_close, jconn);

	if (data_classes & JALN_RTYPE_JOURNAL) {
		jaln_session* session = jaln_subscriber_create_session(ctx, host, JALN_RTYPE_JOURNAL);
		session->mode = mode;
		vortex_channel_new(v_conn, 0, JALN_JALOP_1_0_PROFILE,
				jaln_session_on_close_channel, session,
				jaln_subscriber_on_frame_received, session,
				jaln_subscriber_on_channel_create, session);
	}
	if (data_classes & JALN_RTYPE_AUDIT) {
		jaln_session* session = jaln_subscriber_create_session(ctx, host, JALN_RTYPE_AUDIT);
		session->mode = mode;
		vortex_channel_new(v_conn, 0, JALN_JALOP_1_0_PROFILE,
				jaln_session_on_close_channel, session,
				jaln_subscriber_on_frame_received, session,
				jaln_subscriber_on_channel_create, session);
	}
	if (data_classes & JALN_RTYPE_LOG) {
		jaln_session* session = jaln_subscriber_create_session(ctx, host, JALN_RTYPE_LOG);
		session->mode = mode;
		vortex_channel_new(v_conn, 0, JALN_JALOP_1_0_PROFILE,
				jaln_session_on_close_channel, session,
				jaln_subscriber_on_frame_received, session,
				jaln_subscriber_on_channel_create, session);
	}
	return jconn;
}

void jaln_subscriber_init_reply_frame_handler(jaln_session *session,
		VortexChannel *chan,
		VortexConnection *conn,
		VortexFrame *frame)
{
	if (!session || !chan || !conn || !frame) {
		goto out;
	}

	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		vortex_connection_shutdown(conn);
		goto out;
	}
	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (!msg) {
		vortex_connection_shutdown(conn);
		goto out;
	}
	if (0 == strcasecmp(msg, JALN_MSG_INIT_ACK)) {
		if (!jaln_handle_initialize_ack(session, JALN_ROLE_SUBSCRIBER, frame)) {
			goto out;
		}
		jaln_configure_sub_session(chan, session);

		jaln_subscriber_send_subscribe_request(session);
		// create the 'digest' channel

		int chan_num = vortex_channel_get_number(chan);
		if (chan_num == -1) {
			vortex_connection_shutdown(conn);
			goto out;
		}
		vortex_channel_new_fullv(conn, 0, NULL, JALN_JALOP_1_0_PROFILE,
				EncodingNone,
				NULL, NULL, // close handler, user data,
				NULL, NULL, // frame handler, user data,
				jaln_session_on_dgst_channel_create, session,
				"digest:%d", chan_num);
	} else if (0 == strcasecmp(msg, JALN_MSG_INIT_NACK)) {
		jaln_handle_initialize_nack(session, frame);
	} else {
		vortex_connection_shutdown(conn);
	}
out:
	return;
}

void jaln_subscriber_unexpected_frame_handler(
		__attribute__((unused)) jaln_session *session,
		__attribute__((unused)) VortexChannel *chan,
		VortexConnection *conn,
		__attribute__((unused)) VortexFrame *frame)
{
	vortex_connection_shutdown(conn);
}

void jaln_subscriber_record_frame_handler(jaln_session *session,
		VortexChannel *chan,
		__attribute__((unused)) VortexConnection *conn,
		VortexFrame *frame)
{
	if (!session || !session->sub_data || !session->sub_data->sm ||
			!session->sub_data->sm->curr_state ||
			!session->sub_data->sm->curr_state->frame_handler) {
		goto err_out;
	}

	VortexFrameType frame_type = vortex_frame_get_type(frame);
	if (frame_type != VORTEX_FRAME_TYPE_ANS) {
		goto err_out;
	}
	int flag_more = vortex_frame_get_more_flag(frame);
	int ret = session->sub_data->sm->curr_state->frame_handler(session, frame, 0, flag_more);
	if (!ret) {
		goto err_out;
	}
	return;

err_out:
	vortex_channel_close_full(chan, jaln_session_notify_close, session);
	return;
}

enum jal_status jaln_configure_sub_session(VortexChannel *chan, jaln_session *session)
{
	vortex_mutex_lock(&session->lock);
	enum jal_status ret = jaln_configure_sub_session_no_lock(chan, session);
	vortex_mutex_unlock(&session->lock);
	return ret;
}

enum jal_status jaln_configure_sub_session_no_lock(VortexChannel *chan, jaln_session *session)
{
	if (!chan || !session) {
		return JAL_E_INVAL;
	}
	session->rec_chan = chan;
	session->rec_chan_num = vortex_channel_get_number(chan);
	session->role = JALN_ROLE_SUBSCRIBER;
	if (!session->sub_data) {
		session->sub_data = jaln_sub_data_create();
	}
	switch (session->ch_info->type) {
	case (JALN_RTYPE_JOURNAL):
		session->sub_data->sm = jaln_sub_state_create_journal_machine();
		break;
	case (JALN_RTYPE_AUDIT):
		session->sub_data->sm = jaln_sub_state_create_audit_machine();
		break;
	case (JALN_RTYPE_LOG):
		session->sub_data->sm = jaln_sub_state_create_log_machine();
		break;
	}
	jaln_sub_state_reset(session);
	session->sub_data->curr_frame_handler = jaln_subscriber_record_frame_handler;
	vortex_channel_set_received_handler(chan, jaln_subscriber_on_frame_received, session);
	return JAL_OK;
}

void jaln_subscriber_send_subscribe_request(jaln_session *session)
{
	char *msg = NULL;

	if (!session || !session->jaln_ctx || !session->jaln_ctx->sub_callbacks ||
			!session->ch_info || !session->rec_chan) {
		goto err_out;
	}
	char *serial_id = NULL;
	uint64_t offset = 0;
	enum jal_status ret = session->jaln_ctx->sub_callbacks->get_subscribe_request(
			session,
			session->ch_info,
			session->ch_info->type,
			&serial_id,
			&offset);
	if ((JAL_OK != ret) ||
		(!serial_id)) {
		goto err_out;
	}
	axl_stream_trim(serial_id);
	if (0 == strlen(serial_id)) {
		goto err_out;
	}

	uint64_t msg_len = 0;
	if ((JALN_RTYPE_JOURNAL == session->ch_info->type) && (0 < offset)) {
		if (JAL_OK != jaln_create_journal_resume_msg(serial_id, offset, &msg, &msg_len)) {
			goto err_out;
		}
	} else {
		if (JAL_OK != jaln_create_subscribe_msg(&msg, &msg_len)) {
			goto err_out;
		}
	}
	int msg_no;
	vortex_channel_set_complete_flag(session->rec_chan, axl_false);

	if (!(vortex_channel_send_msg(session->rec_chan, msg, strlen(msg), &msg_no))) {
		goto err_out;
	}
	goto out;
err_out:
	if (session && session->rec_chan) {
		vortex_channel_close_full(session->rec_chan, jaln_session_notify_close, session);
	}
out:
	free(msg);
	return;
}

void jaln_subscriber_on_channel_create(int channel_num,
		VortexChannel *chan, VortexConnection *conn,
		axlPointer user_data)
{
	jaln_session *sess = (jaln_session*)user_data;
	if (-1 == channel_num || !chan) {
		// channel wasn't created, so need to free up the session
		// object.
		jaln_session_unref(sess);
		return;
	}

	if (!sess || !sess->ch_info || !sess->jaln_ctx || !sess->sub_data) {
		goto err_out;
	}

	sess->rec_chan = chan;
	sess->rec_chan_num = channel_num;

	vortex_channel_set_serialize(chan, axl_true);

	vortex_channel_set_closed_handler(chan, jaln_session_notify_unclean_channel_close, sess);
	sess->ch_info->addr = strdup(vortex_connection_get_host(conn));
	char *init_msg = NULL;
	uint64_t init_msg_len = 0;

	// setting '2' disables MIME generation completely.
	vortex_channel_set_automatic_mime(chan, 2);

	enum jal_status ret = jaln_create_init_msg(JALN_ROLE_SUBSCRIBER, sess->mode, sess->ch_info->type,
			sess->jaln_ctx->dgst_algs, sess->jaln_ctx->xml_encodings, &init_msg,
			&init_msg_len);
	if (ret != JAL_OK) {
		// something went terribly wrong...
		goto err_out;
	}
	sess->sub_data->curr_frame_handler = jaln_subscriber_init_reply_frame_handler;
	if (!vortex_channel_send_msg(chan, init_msg, init_msg_len, NULL)) {
		goto err_out;
	}
	goto out;
err_out:
	vortex_channel_close_full(chan, jaln_session_notify_close, sess);
out:
	free(init_msg);
}

