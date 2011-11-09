/**
 * @file jaln_channel_info.c This file contains function
 * definitions for internal library functions related to a jaln_channel_info
 * structure.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
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
#include <vortex.h>
#include <jalop/jaln_publisher_callbacks.h>

#include "jal_alloc.h"

#include "jaln_context.h"
#include "jaln_digest_info.h"
#include "jaln_digest_msg_handler.h"
#include "jaln_digest_resp_info.h"
#include "jaln_message_helpers.h"
#include "jaln_publisher.h"
#include "jaln_session.h"
#include "jaln_sync_msg_handler.h"

void jaln_pub_notify_digests_and_create_digest_response(
		struct jaln_session *sess,
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
			sess->jaln_ctx->pub_callbacks->peer_digest(sess->ch_info,
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

			sess->jaln_ctx->pub_callbacks->peer_digest(sess->ch_info,
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

enum jal_status jaln_publisher_handle_sync(struct jaln_session *sess,
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
	sess->jaln_ctx->pub_callbacks->sync(sess->ch_info, sess->ch_info->type, serial_id, NULL, sess->jaln_ctx->user_data);
	free(serial_id);
out:
	if (!ans_rpy_sent) {
		ret = JAL_E_COMM;
	}
	return ret;
}

enum jal_status jaln_publisher_handle_digest(struct jaln_session *sess, VortexChannel *chan, VortexFrame *frame, int msg_no)
{
	axlList *calc_dgsts = NULL;
	axlList *dgst_from_remote = NULL;
	axlList *resps = NULL;
	char *msg = NULL;
	size_t len = 0;

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
	struct jaln_session *sess = (struct jaln_session*) user_data;
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
		goto err_out;;
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
struct jaln_session *jaln_publisher_create_session(jaln_context *ctx, const char *host, enum jaln_record_type type)
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
	struct jaln_session *sess = NULL;
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
