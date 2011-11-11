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

#include "jaln_session.h"
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

