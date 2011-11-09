/**
 * @file jaln_session.h This file contains function
 * declarations for internal library functions related to a jaln_session
 * structure.
 *
 * @section LICENSE
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

#include "jaln_sub_dgst_channel.h"

#include "jaln_message_helpers.h"
#include "jaln_context.h"
#include "jaln_digest.h"
#include "jaln_digest_info.h"
#include "jaln_digest_resp_info.h"
#include "jaln_digest_resp_msg_handler.h"

axlPointer jaln_sub_dgst_wait_thread(axlPointer user_data) {
	struct jaln_session *sess = (struct jaln_session*) user_data;

	vortex_mutex_lock(&sess->lock);
	while (!sess->errored || !sess->closing) {
		if (!vortex_cond_timedwait(&sess->sub_data->dgst_list_cond, &sess->lock, sess->dgst_timeout)) {
			// wait failed? now what... I guess try again?
			continue;
		}
		if (sess->errored || sess->closing) {
			// try to close the channel;
			if (sess->dgst_chan) {
				vortex_channel_close_full(sess->dgst_chan, jaln_session_notify_close, sess);
				continue;
			} else {
				vortex_mutex_unlock(&sess->lock);
				break;
			}
		}
		// no point sending empty digest/sync messages
		if (axl_list_length(sess->dgst_list) > 0) {
			axlList *dgst_list = sess->dgst_list;
			sess->dgst_list =
				axl_list_new(jaln_axl_equals_func_digest_info_serial_id, jaln_axl_destroy_digest_info);
			vortex_mutex_unlock(&sess->lock);
			jaln_send_digest_and_sync_no_lock(sess, dgst_list);
			vortex_mutex_lock(&sess->lock);
		}
	}
	return NULL;
}

void jaln_send_digest_and_sync_no_lock(struct jaln_session *sess, axlList *dgst_list)
{
	if (!sess || !sess->ch_info || !sess->jaln_ctx || !sess->dgst_chan ||
			!dgst_list) {
		return;
	}

	size_t len;
	char *msg = NULL;
	WaitReplyData *wait_reply = NULL;
	VortexFrame *frame = NULL;
	axlList *dgst_resp = NULL;
	axlListCursor *cursor = NULL;

	int msg_no;
	if (JAL_OK != jaln_create_digest_msg(dgst_list, &msg, &len)) {
		goto out;
	}
	wait_reply = vortex_channel_create_wait_reply();
	if (!wait_reply) {
		goto out;
	}
	if (!vortex_channel_send_msg_and_wait(sess->dgst_chan, msg, len, &msg_no, wait_reply)) {
		goto out;
	}
	free(msg);
	msg = NULL;

	frame = vortex_channel_wait_reply(sess->dgst_chan, msg_no, wait_reply);
	if (frame == NULL) {
		goto out;
	}

	if (JAL_OK != jaln_process_digest_resp(frame, &dgst_resp)) {
		goto out;
	}
	cursor = axl_list_cursor_new(dgst_resp);
	axl_list_cursor_first(cursor);

	while (axl_list_cursor_has_item(cursor)) {
		struct jaln_digest_resp_info *resp_info = (struct jaln_digest_resp_info*) axl_list_cursor_get(cursor);
		sess->jaln_ctx->sub_callbacks->
			on_digest_response(sess->ch_info, sess->ch_info->type, resp_info->serial_id, resp_info->status, sess->jaln_ctx->user_data);
		axl_list_cursor_next(cursor);
	}

	struct jaln_digest_info *info = axl_list_get_last(dgst_list);
	jaln_create_sync_msg(info->serial_id, &msg, &len);

	if (!vortex_channel_send_msg(sess->dgst_chan, msg, len, NULL)) {
		goto out;
	}
out:
	free(msg);
	if (wait_reply) {
		vortex_channel_free_wait_reply(wait_reply);
	}
	if (cursor) {
		axl_list_cursor_free(cursor);
	}
	if (dgst_resp) {
		axl_list_free(dgst_resp);
	}
}

void jaln_create_sub_digest_channel_thread_no_lock(struct jaln_session *sess)
{
	VortexThread thread;
	if (!vortex_thread_create(&thread, jaln_sub_dgst_wait_thread, sess,
				VORTEX_THREAD_CONF_END)) {
		jaln_session_set_errored_no_lock(sess);
	}
}
