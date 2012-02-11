/**
 * @file jaln_publisher.c  This file contains function
 * definitions related to the jal publisher.
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
#include <jalop/jaln_publisher_callbacks.h>

#include "jal_alloc.h"

#include "jaln_context.h"
#include "jaln_connection.h"
#include "jaln_connection_callbacks_internal.h"
#include "jaln_digest_info.h"
#include "jaln_digest_msg_handler.h"
#include "jaln_digest_resp_info.h"
#include "jaln_handle_init_replies.h"
#include "jaln_journal_resume_msg_handler.h"
#include "jaln_message_helpers.h"
#include "jaln_publisher.h"
#include "jaln_publisher_callbacks_internal.h"
#include "jaln_pub_feeder.h"
#include "jaln_session.h"
#include "jaln_sync_msg_handler.h"
#include "jaln_subscribe_msg_handler.h"

void jaln_pub_notify_digests_and_create_digest_response(
		jaln_session *sess,
		axlList *calc_dgsts,
		axlList *peer_dgsts,
		axlList **dgst_resp_infos)
{
	if (!sess || !sess->jaln_ctx || !sess->ch_info || !sess->jaln_ctx->pub_callbacks ||
			!sess->jaln_ctx->pub_callbacks->peer_digest ||
			!calc_dgsts || !peer_dgsts || !dgst_resp_infos ||
			*dgst_resp_infos) {
		return;
	}

	axlList *resps = jaln_digest_resp_list_create();

	axlListCursor *calc_cursor = axl_list_cursor_new(calc_dgsts);
	axlListCursor *peer_cursor = axl_list_cursor_new(peer_dgsts);

	axl_list_cursor_first(peer_cursor);
	while(axl_list_cursor_has_item(peer_cursor)) {
		struct jaln_digest_info *peer_di = (struct jaln_digest_info*) axl_list_cursor_get(peer_cursor);
		struct jaln_digest_info *calc_di = NULL;

		axl_list_cursor_first(calc_cursor);
		while(axl_list_cursor_has_item(calc_cursor)) {
			struct jaln_digest_info *tmp = (struct jaln_digest_info*) axl_list_cursor_get(calc_cursor);
			if (tmp && (0 == strcmp(peer_di->serial_id, tmp->serial_id))) {
				calc_di = tmp;
				axl_list_cursor_unlink(calc_cursor);
				break;
			}
			axl_list_cursor_next(calc_cursor);
		}

		struct jaln_digest_resp_info *resp_info = NULL;
		if (!calc_di) {
			sess->jaln_ctx->pub_callbacks->peer_digest(sess,
					sess->ch_info,
					sess->ch_info->type,
					peer_di->serial_id,
					NULL, 0,
					peer_di->digest, peer_di->digest_len,
					sess->jaln_ctx->user_data);

			resp_info = jaln_digest_resp_info_create(peer_di->serial_id, JALN_DIGEST_STATUS_UNKNOWN);
		} else {
			if (jaln_digests_are_equal(peer_di, calc_di)) {
				resp_info = jaln_digest_resp_info_create(peer_di->serial_id, JALN_DIGEST_STATUS_CONFIRMED);
			} else {
				resp_info = jaln_digest_resp_info_create(peer_di->serial_id, JALN_DIGEST_STATUS_INVALID);
			}

			sess->jaln_ctx->pub_callbacks->peer_digest(sess,
					sess->ch_info,
					sess->ch_info->type,
					peer_di->serial_id,
					calc_di->digest, calc_di->digest_len,
					peer_di->digest, peer_di->digest_len,
					sess->jaln_ctx->user_data);
		}
		axl_list_append(resps, resp_info);

		jaln_digest_info_destroy(&calc_di);

		axl_list_cursor_next(peer_cursor);
	}
	axl_list_cursor_free(peer_cursor);
	axl_list_cursor_free(calc_cursor);
	*dgst_resp_infos = resps;
}

enum jal_status jaln_publisher_handle_sync(jaln_session *sess,
		VortexChannel *chan,
		VortexFrame *frame,
		int msg_no)
{
	axl_bool ans_rpy_sent = vortex_channel_finalize_ans_rpy(chan, msg_no);
	char *serial_id = NULL;
	enum jal_status ret = JAL_E_INVAL;
	if (!sess || !sess->jaln_ctx || !sess->jaln_ctx->pub_callbacks || 
			!sess->jaln_ctx->pub_callbacks->sync || !sess->ch_info) {
		goto out;
	}
	ret = jaln_process_sync(frame, &serial_id);
	if (ret != JAL_OK) {
		goto out;
	}
	sess->jaln_ctx->pub_callbacks->sync(sess, sess->ch_info, sess->ch_info->type, serial_id, NULL, sess->jaln_ctx->user_data);
	free(serial_id);
out:
	if (!ans_rpy_sent) {
		ret = JAL_E_COMM;
	}
	return ret;
}

enum jal_status jaln_publisher_handle_digest(jaln_session *sess, VortexChannel *chan, VortexFrame *frame, int msg_no)
{
	axlList *calc_dgsts = NULL;
	axlList *dgst_from_remote = NULL;
	axlList *resps = NULL;
	char *msg = NULL;
	uint64_t len = 0;

	enum jal_status ret;
	ret = jaln_process_digest(frame, &dgst_from_remote);
	if (JAL_OK != ret) {
		goto err_out;
	}

	vortex_mutex_lock(&sess->lock);
	calc_dgsts = sess->dgst_list;
	sess->dgst_list = jaln_digest_info_list_create();
	vortex_mutex_unlock(&sess->lock);

	jaln_pub_notify_digests_and_create_digest_response(sess, calc_dgsts, dgst_from_remote, &resps);

	vortex_mutex_lock(&sess->lock);
	axlListCursor *cursor = axl_list_cursor_new(sess->dgst_list);
	axl_list_cursor_first(cursor);
	while(axl_list_cursor_has_item(cursor)) {
		axlPointer from_sess = axl_list_cursor_get(cursor);
		axl_list_append(calc_dgsts, from_sess);
		axl_list_cursor_unlink(cursor);
		axl_list_cursor_next(cursor);
	}
	axl_list_cursor_free(cursor);
	axlList *tmp_list = sess->dgst_list;
	sess->dgst_list = calc_dgsts;
	vortex_mutex_unlock(&sess->lock);

	axl_list_free(tmp_list);
	tmp_list = NULL;
	calc_dgsts = NULL;

	ret = jaln_create_digest_response_msg(resps, &msg, &len);
	axl_list_free(resps);
	resps = NULL;
	vortex_channel_send_rpy(chan, msg, len, msg_no);
	goto out;
err_out:
	vortex_channel_close_full(chan, jaln_session_notify_close, sess);
out:
	return ret;
}

void jaln_publisher_digest_and_sync_frame_handler(VortexChannel *chan, VortexConnection *conn,
		VortexFrame *frame, axlPointer user_data)
{
	jaln_session *sess = (jaln_session*) user_data;
	int msg_no = -1;
	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		goto err_out;
	}
	msg_no = vortex_frame_get_msgno(frame);
	if (msg_no < 0) {
		goto err_out;
	}
	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (!msg) {
		goto err_out;
	}
	if (0 == strcmp(msg, JALN_MSG_DIGEST)) {
		if (JAL_OK != jaln_publisher_handle_digest(sess, chan, frame, msg_no)) {
			goto err_out;
		}
	} else if (0 == strcmp(msg, JALN_MSG_SYNC)) {
		if (JAL_OK != jaln_publisher_handle_sync(sess, chan, frame, msg_no)) {
			goto err_out;
		}
	} else {
		goto err_out;
	}
	return;
err_out:
	vortex_connection_shutdown(conn);
}

void jaln_pub_channel_frame_handler(
		VortexChannel *chan,
		VortexConnection *conn,
		VortexFrame *frame,
		axlPointer user_data)
{
	jaln_session *sess = (jaln_session*) user_data;
	if (!sess || !sess->ch_info) {
		goto err_out;
	}
	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		goto err_out;
	}
	int msg_no = vortex_frame_get_msgno(frame);
	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (0 == strcasecmp(msg, JALN_MSG_SUBSCRIBE)) {
		if (JAL_OK != jaln_pub_handle_subscribe(sess, chan, frame, msg_no)) {
			goto err_out;
		}
	} else if (0 == strcasecmp(msg, JALN_MSG_JOURNAL_RESUME) && (JALN_RTYPE_JOURNAL == sess->ch_info->type)) {
		if (JAL_OK != jaln_pub_handle_journal_resume(sess, chan, frame, msg_no)) {
			goto err_out;
		}
	} else {
		goto err_out;
	}
	return;
err_out:
	vortex_connection_shutdown(conn);
	return;
}

enum jal_status jaln_pub_handle_journal_resume(jaln_session *sess, VortexChannel *chan, VortexFrame *frame, int msg_no)
{
	enum jal_status ret = JAL_E_INVAL;
	if (!sess || !sess->ch_info || !sess->jaln_ctx || !sess->jaln_ctx->pub_callbacks || !chan || !frame) {
		return ret;
	}
	struct jaln_channel_info *ch_info = sess->ch_info;
	enum jaln_record_type type = ch_info->type;
	if  (JALN_RTYPE_JOURNAL != type) {
		return JAL_E_INVAL;
	}
	struct jaln_publisher_callbacks *cbs = sess->jaln_ctx->pub_callbacks;
	struct jaln_pub_data *pd = sess->pub_data;
	void *ud = sess->jaln_ctx->user_data;
	char *sid = NULL;
	uint64_t offset;
	ret = jaln_process_journal_resume(frame, &sid, &offset);
	if (JAL_OK != ret) {
		goto err_out;
	}

	sess->pub_data->payload_off = offset;
	struct jaln_record_info rec_info;
	memset(&rec_info, 0, sizeof(rec_info));
	rec_info.type = type;
	rec_info.serial_id = jal_strdup(sid);

	ret = cbs->on_journal_resume(sess, ch_info, &rec_info, offset, &pd->sys_meta, &pd->app_meta, NULL, ud);
	if (JAL_OK != ret) {
		goto err_out;
	}

	sess->pub_data->msg_no = msg_no;
	sess->pub_data->serial_id = jal_strdup(sid);

	ret = jaln_pub_begin_next_record_ans(sess, offset, &rec_info, chan);
	free(rec_info.serial_id);
	if (JAL_OK != ret) {
		goto err_out;
	}
	goto out;

err_out:
	vortex_channel_finalize_ans_rpy(chan, msg_no);
	jaln_session_set_errored(sess);
out:
	free(sid);
	return ret;
}

enum jal_status jaln_pub_handle_subscribe(jaln_session *sess, VortexChannel *chan, VortexFrame *frame, int msg_no)
{
	enum jal_status ret = JAL_E_INVAL;
	if (!sess || !chan || !frame || !sess->jaln_ctx || !sess->jaln_ctx->pub_callbacks ||
			!sess->ch_info || !sess->pub_data) {
		return ret;
	}
	struct jaln_publisher_callbacks *cbs = sess->jaln_ctx->pub_callbacks;
	struct jaln_pub_data *pd = sess->pub_data;
	struct jaln_channel_info *ch_info = sess->ch_info;
	enum jaln_record_type type = ch_info->type;
	void *user_data = sess->jaln_ctx->user_data;
	char *sid = NULL;
	ret = jaln_process_subscribe(frame, &sid);
	if (JAL_OK != ret) {
		goto err_out;
	}
	ret = cbs->on_subscribe(sess, ch_info, type, sid, NULL, user_data);

	if (JAL_OK != ret) {
		goto err_out;
	}

	sess->pub_data->msg_no = msg_no;
	sess->pub_data->serial_id = sid;
	sid = NULL;

	struct jaln_record_info rec_info;
	memset(&rec_info, 0, sizeof(rec_info));
	rec_info.type = type;

	ret = cbs->get_next_record_info_and_metadata(sess, ch_info, type,
			pd->serial_id, &rec_info, &pd->sys_meta, &pd->app_meta, user_data);
	if (JAL_OK != ret) {
		goto err_out;
	}
	ret = jaln_pub_begin_next_record_ans(sess, 0, &rec_info, chan);
	if (JAL_OK != ret) {
		goto err_out;
	}
	goto out;

err_out:
	vortex_channel_finalize_ans_rpy(chan, msg_no);
	jaln_session_set_errored(sess);
out:
	free(sid);
	return ret;
}

void jaln_publisher_on_connection_close(__attribute__((unused)) VortexConnection *conn,
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

void jaln_publisher_on_channel_create(int channel_num,
		VortexChannel *chan, VortexConnection *conn,
		axlPointer user_data)
{
	char *init_msg = NULL;
	uint64_t init_msg_len = 0;
	jaln_session *session = (jaln_session*)user_data;
	if (!chan) {
		// channel creation failed, cleanup the session and bail.
		jaln_session_unref(session);
		return;
	}
	if (!session || !session->ch_info || !session->jaln_ctx) {
		// shouldn't ever happen
		goto err_out;
	}

	vortex_channel_set_serialize(chan, axl_true);
	vortex_channel_set_closed_handler(chan, jaln_session_notify_unclean_channel_close, session);
	vortex_channel_set_close_handler(chan, jaln_session_on_close_channel, session);
	vortex_channel_set_automatic_mime(chan, 2);
	session->rec_chan = chan;
	session->rec_chan_num = channel_num;
	session->ch_info->addr = jal_strdup(vortex_connection_get_host(conn));

	vortex_channel_set_received_handler(chan, jaln_publisher_init_reply_frame_handler, session);

	enum jal_status ret = jaln_create_init_msg(JALN_ROLE_PUBLISHER, session->ch_info->type,
			session->jaln_ctx->dgst_algs, session->jaln_ctx->xml_encodings, &init_msg, &init_msg_len);

	if (JAL_OK != ret) {
		goto err_out;
	}
	if (!vortex_channel_send_msg(chan, init_msg, init_msg_len, NULL)) {
		goto err_out;
	}
	goto out;

err_out:
	vortex_channel_close_full(chan, jaln_session_notify_close, session);
out:
	free(init_msg);
	return;
}

struct jaln_connection *jaln_publish(
		jaln_context *ctx,
		const char *host,
		const char *port,
		const int data_classes,
		void *user_data)
{
	if (!ctx || !host || !port) {
		return NULL;
	}

	vortex_mutex_lock(&ctx->lock);
	if (!ctx->vortex_ctx ||
		!jaln_publisher_callbacks_is_valid(ctx->pub_callbacks) ||
		!jaln_connection_callbacks_is_valid(ctx->conn_callbacks) ||
		ctx->is_connected) {
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

	vortex_connection_set_on_close_full(v_conn, jaln_publisher_on_connection_close, jconn);

	if (data_classes & JALN_RTYPE_JOURNAL) {
		jaln_session* session = jaln_publisher_create_session(ctx, host, JALN_RTYPE_JOURNAL);
		vortex_channel_new(v_conn, 0, JALN_JALOP_1_0_PROFILE,
				NULL, NULL,
				NULL, NULL,
				jaln_publisher_on_channel_create, session);
	}
	if (data_classes & JALN_RTYPE_AUDIT) {
		jaln_session* session = jaln_publisher_create_session(ctx, host, JALN_RTYPE_AUDIT);
		vortex_channel_new(v_conn, 0, JALN_JALOP_1_0_PROFILE,
				NULL, NULL,
				NULL, NULL,
				jaln_publisher_on_channel_create, session);
	}
	if (data_classes & JALN_RTYPE_LOG) {
		jaln_session* session = jaln_publisher_create_session(ctx, host, JALN_RTYPE_LOG);
		vortex_channel_new(v_conn, 0, JALN_JALOP_1_0_PROFILE,
				NULL, NULL,
				NULL, NULL,
				jaln_publisher_on_channel_create, session);
	}
	return jconn;
}

void jaln_publisher_init_reply_frame_handler(__attribute__((unused)) VortexChannel *chan,
		__attribute__((unused)) VortexConnection *conn,
		VortexFrame *frame,
		void *user_data)
{
	jaln_session *sess = (jaln_session*) user_data;
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
		if (!jaln_handle_initialize_ack(sess, JALN_ROLE_PUBLISHER, frame)) {
			goto out;
		}
		vortex_channel_set_received_handler(chan, jaln_pub_channel_frame_handler, sess);

		int chan_num = vortex_channel_get_number(chan);
		if (chan_num == -1) {
			vortex_connection_shutdown(conn);
			goto out;
		}

		vortex_channel_new_fullv(conn, 0, NULL, JALN_JALOP_1_0_PROFILE,
				EncodingNone,
				NULL, NULL, // close handler, user data,
				NULL, NULL, // frame handler, user data,
				jaln_session_on_dgst_channel_create, sess,
				"digest:%d", chan_num);
	} else if (0 == strcasecmp(msg, JALN_MSG_INIT_NACK)) {
		jaln_handle_initialize_nack(sess, frame);
	} else {
		vortex_connection_shutdown(conn);
	}
out:
	return;
}

jaln_session *jaln_publisher_create_session(jaln_context *ctx, const char *host, enum jaln_record_type type)
{
	if (!ctx || !host) {
		return NULL;
	}
	switch(type) {
	case JALN_RTYPE_JOURNAL:
	case JALN_RTYPE_AUDIT:
	case JALN_RTYPE_LOG:
		break;
	default:
		return NULL;
	}
	jaln_session *sess = NULL;
	sess = jaln_session_create();
	jaln_ctx_ref(ctx);
	sess->jaln_ctx = ctx;
	sess->role = JALN_ROLE_PUBLISHER;

	struct jaln_channel_info *ch_info = sess->ch_info;
	sess->pub_data = jaln_pub_data_create();
	ch_info->hostname = jal_strdup(host);
	ch_info->type = type;

	return sess;
}

enum jal_status jaln_configure_pub_session_no_lock(VortexChannel *chan, jaln_session *session)
{
	if (!chan || !session || session->pub_data) {
		return JAL_E_INVAL;
	}
	session->rec_chan = chan;
	session->rec_chan_num = vortex_channel_get_number(chan);
	session->role = JALN_ROLE_PUBLISHER;
	session->pub_data = jaln_pub_data_create();
	vortex_channel_set_received_handler(chan, jaln_pub_channel_frame_handler, session);
	return JAL_OK;
}

enum jal_status jaln_configure_pub_session(VortexChannel *chan, jaln_session *session)
{
	vortex_mutex_lock(&session->lock);
	enum jal_status ret = jaln_configure_pub_session_no_lock(chan, session);
	vortex_mutex_unlock(&session->lock);
	return ret;
}

