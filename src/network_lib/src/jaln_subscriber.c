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

