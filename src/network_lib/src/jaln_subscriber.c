/**
 * @file jaln_subscriber.c This file contains function
 * declarations for internal library functions related to a
 * subscribere session
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

#include "jaln_context.h"
#include "jaln_message_helpers.h"
#include "jaln_session.h"
#include "jaln_subscriber.h"
#include "jaln_subscriber_state_machine.h"

void jaln_subscriber_on_frame_received(VortexChannel *chan, VortexConnection *conn,
		VortexFrame *frame, axlPointer user_data)
{
	struct jaln_session *session = (struct jaln_session*) user_data;
	if (!session || !session->sub_data || !session->sub_data->curr_frame_handler) {
		// something's not right
		vortex_connection_close(conn);
		return;
	}
	session->sub_data->curr_frame_handler(session, chan, conn, frame);
}

void jaln_subscriber_record_frame_handler(struct jaln_session *session,
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

enum jal_status jaln_configure_sub_session(VortexChannel *chan, struct jaln_session *session)
{
	vortex_mutex_lock(&session->lock);
	enum jal_status ret = jaln_configure_sub_session_no_lock(chan, session);
	vortex_mutex_unlock(&session->lock);
	return ret;
}

enum jal_status jaln_configure_sub_session_no_lock(VortexChannel *chan, struct jaln_session *session)
{
	if (!chan || !session || session->sub_data || session->rec_chan) {
		return JAL_E_INVAL;
	}
	session->rec_chan = chan;
	session->rec_chan_num = vortex_channel_get_number(chan);
	session->role = JALN_ROLE_SUBSCRIBER;
	session->sub_data = jaln_sub_data_create();
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

void jaln_subscriber_send_subscribe_request(struct jaln_session *session)
{
	char *msg = NULL;

	if (!session || !session->jaln_ctx || !session->jaln_ctx->sub_callbacks ||
			!session->ch_info || !session->rec_chan) {
		goto err_out;
	}
	char *serial_id = NULL;
	uint64_t offset = 0;
	enum jal_status ret = session->jaln_ctx->sub_callbacks->get_subscribe_request(
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

	size_t msg_len = 0;
	if ((JALN_RTYPE_JOURNAL == session->ch_info->type) && (0 < offset)) {
		if (JAL_OK != jaln_create_journal_resume_msg(serial_id, offset, &msg, &msg_len)) {
			goto err_out;
		}
	} else {
		if (JAL_OK != jaln_create_subscribe_msg(serial_id, &msg, &msg_len)) {
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

