/**
 * @file jaln_subscriber.h This file contains function
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
 * Vortex handler for when subsciber's connection closes
 * This calls the user on_connection_close callback
 *
 * @param[in] conn The vortex connection
 * @param[in] data This is expected to be the jaln_connection
 */
void jaln_subscriber_on_connection_close(VortexConnection *conn,
					axlPointer data);

/**
 * Frame handler for a subscriber to deal with the response to an 'init'
 * message.
 *
 * @param[in] chan The vortex channel that received the frame
 * @param[in] conn The vortex connection for the channel.
 * @param[in] frame The frame
 * @param[in] user_data This is expected to be a jaln_session.
 */
void jaln_subscriber_init_reply_frame_handler(jaln_session *session,
		VortexChannel *chan,
		VortexConnection *conn,
		VortexFrame *frame);

/**
 * Frame handler that is used before any messages are sent by the publisher.
 *
 * @param[in] sess The jaln_session
 * @param[in] chan The vortex channel that received the frame
 * @param[in] conn The vortex connection for the channel.
 * @param[in] frame The frame
 */
void jaln_subscriber_unexpected_frame_handler(
		jaln_session *session,
		VortexChannel *chan,
		VortexConnection *conn,
		VortexFrame *frame);

/**
 * Frame handler for use when the subscriber is expecting 'ANS' frames in
 * response to a 'subscribe'
 *
 * @param[in] session
 * @param[in] chan The channel that received the frame
 * @param[in] conn The connection that holds the channel.
 * @param[in] frame Teh frame of the message.
 */
void jaln_subscriber_record_frame_handler(jaln_session *session,
		VortexChannel *chan,
		VortexConnection *v_conn,
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
enum jal_status jaln_configure_sub_session(VortexChannel *chan, jaln_session *session);

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
enum jal_status jaln_configure_sub_session_no_lock(VortexChannel *chan, jaln_session *session);

/**
 * Send the 'subscribe' message.
 *
 * @param[in] session The jaln_session to send the message on.
 */
enum jal_status jaln_subscriber_send_subscribe_request(jaln_session *session);

/**
 * Callback that needs to get registered when a subscriber initiates a
 * connection to a remote.
 *
 * The function will get called after the channel is created, and this function
 * will send finish configuring the channel and send the 'initialize' message
 * to the peer.
 *
 * @param[in] channel_num The channel number assigned to the channel
 * @param[in] channel The Vortex Channel
 * @param[in] v_conn The Vortex Connection
 * @param[in] user_data This is expected to be a pointer to a jaln_session
 * object.
 */
void jaln_subscriber_on_channel_create(int channel_num,
		VortexChannel *channel, VortexConnection *v_conn,
		axlPointer user_data);

/**
 * Helper utility to create/configure a session for use as a subscriber.
 *
 * @param[in] ctx The context to associate with.
 * @param[in] host A string for the remote host.
 * @param[in] type The type of records to transfer.
 *
 * @return a new jaln_session
 */
jaln_session *jaln_subscriber_create_session(jaln_context *ctx, const char *host, enum jaln_record_type type);

#ifdef __cplusplus
}
#endif
#endif //_JALN_SUBSCRIBER_H_
