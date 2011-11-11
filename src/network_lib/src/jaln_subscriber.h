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

#ifndef _JALN_SUBSCRIBER_H_
#define _JALN_SUBSCRIBER_H_

#include <vortex.h>
#include "jaln_session.h"

#include "jaln_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Vortex handler for a subscriber's 'record' channel
 *
 * @param[in] chan The vortex channel that received the frame
 * @param[in] conn The vortex connection for the channel.
 * @param[in] frame The frame
 * @param[in] user_data This is expected to be a jaln_session.
 */
void jaln_subscriber_on_frame_received(VortexChannel *chan, VortexConnection *conn,
		VortexFrame *frame, axlPointer user_data);

/**
 * Frame handler for use when the subscriber is expecting 'ANS' frames in
 * response to a 'subscribe'
 *
 * @param[in] session
 * @param[in] chan The channel that received the frame
 * @param[in] conn The connection that holds the channel.
 * @param[in] frame Teh frame of the message.
 */
void jaln_subscriber_record_frame_handler(struct jaln_session *session,
		VortexChannel *chan,
		__attribute__((unused)) VortexConnection *v_conn,
		VortexFrame *frame);

/**
 * Configure a session for use as a subscriber
 * This function acquires a lock on the session, at configures it for use as a
 * publisher.
 *
 * @param[in] chan The vortex channel, this should be the channel to be used as
 * a record channel.
 * @param[in] sess The jaln_session to configure
 *
 * @return JAL_OK on success, or an error.
 */
enum jal_status jaln_configure_sub_session(VortexChannel *chan, struct jaln_session *session);

/**
 * Configure a session for use as a subscriber
 * This is the same as jaln_configure_sub_session, except no lock is acquired.
 *
 * @param[in] chan The vortex channel, this should be the channel to be used as
 * a record channel.
 * @param[in] sess The jaln_session to configure
 *
 * @return JAL_OK on success, or an error.
 */
enum jal_status jaln_configure_sub_session_no_lock(VortexChannel *chan, struct jaln_session *session);

/**
 * Send the 'subscribe' message.
 *
 * @param[in] session The jaln_session to send the message on.
 */
void jaln_subscriber_send_subscribe_request(struct jaln_session *session);

#ifdef __cplusplus
}
#endif
#endif //_JALN_SUBSCRIBER_H_
