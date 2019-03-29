/**
 * @file jaln_publisher.h This file contains function
 * declarations related to publishing records to a remote.
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

#ifndef JALN_PUBLISHER_H
#define JALN_PUBLISHER_H

#include <axl.h>
#include <vortex.h>
#include <jalop/jaln_network.h>
#include <curl/curl.h>

#include "jaln_session.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Compare 2 lists of jaln_digest_info structures to determine if the remote
 * side correctly received a set of records. The functions tries to match each
 * jaln_digest_info from \p peer_dgsts to one contained in \p calc_dgsts. For
 * each jaln_digest_info in \p peer_dgsts, it creates a corresponding
 * jaln_digest_resp_info and adds it to a list. As nonces are matched in \p
 * calc_dgsts, they are removed from the list.
 *
 * @param[in] sess The session related to the digests.
 * @param[in] calc_dgsts An axlList of jlan_digest_info structures. This is the
 * digests calculated locally by the network library.
 * @param[in] peer_dgsts An axlList of jaln_digest_info structures. These are
 * the digests calculated by the remote side and sent in a 'digest' message.
 * @param[out] dgst_resp_infos This will be a list of jaln_digest_resp_info
 * structures. It will contain an entry for each nonce indicated in \p
 * peer_dgsts.
 */
void jaln_pub_notify_digests_and_create_digest_response(
		jaln_session *sess,
		axlList *calc_dgsts,
		axlList *peer_dgsts,
		axlList **dgst_resp_infos);

/**
 * Helper function for a publisher to process (and reply to) a 'sync' message.
 * @param[in] sess The session
 * @param[in] chan The channel that received the message
 * @param[in] frame The frame for the sync message
 * @param[in] msg_no The message number for the frame.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_publisher_handle_sync(
		jaln_session *sess,
		VortexChannel *chan,
		VortexFrame *frame,
		int msg_no);

/**
 * Helper utility to parse and process a 'digest' message.
 *
 * @param[in] sess The session
 * @param[in] chan The vortex channel that received the message.
 * @param[in] frame The frame that contains the message
 * @param[in] msg_no The message number
 *
 * @return JAL_OK if the message successfully parsed and dealt with, or an
 * error code.
 */
enum jal_status jaln_publisher_handle_digest(jaln_session *sess,
		VortexChannel *chan,
		VortexFrame *frame,
		int msg_no);

/**
 * Vortex Frame handler for responding to 'digest' and 'sync' messages.
 *
 * @param[in] chan The vortex channel
 * @param[in] conn The vortex connection
 * @param[in] frame The vortex frame
 * @param[in] user_data Expected to be a jaln_session object.
 */
void jaln_publisher_digest_and_sync_frame_handler(VortexChannel *chan,
		VortexConnection *conn,
		VortexFrame *frame,
		axlPointer user_data);

/**
 * Helper function to create a jaln_session for use as a publisher.
 *
 * @param[in] ctx The jaln_context associated with the session.
 * @param[in] host The IP/hostname of the remote
 * @param[in] type The type of records that will be sent using this session.
 *
 * @return a configured jaln_session.
 */
jaln_session *jaln_publisher_create_session(jaln_context *ctx, const char *host, enum jaln_record_type type);

/**
 * Top level vortex frame handler for the 'record' channel of a session.
 *
 * @param[in] chan The vortex channel
 * @param[in] conn The vortex connection
 * @param[in] frame The vortex frame
 * @param[in] user_data Expected to be a jaln_session pointer.
 */
void jaln_pub_channel_frame_handler(VortexChannel *chan,
		VortexConnection *v_conn,
		VortexFrame *frame,
		axlPointer user_data);

/**
 * Function to process a 'subscribe' message.
 *
 * @param[in] session The session that is receiving the message
 * @param[in] chan The channel that received the message
 * @param[in] frame The frame for the subscribe message
 * @param[in] msg_no The message number of the 'subscribe' message.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_pub_handle_subscribe(jaln_session *session,
		VortexChannel *chan,
		VortexFrame *frame,
		int msg_no);

/**
 * Handle to process a 'journal-resume' message.
 *
 * @param[in] chan The channel that received the message
 * @param[in] frame The frame containing the message
 * @param[in] msg_no The message number
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_pub_handle_journal_resume(jaln_session *session,
		VortexChannel *chan,
		VortexFrame *frame,
		int msg_no);

/**
 * Vortex frame handler to process the replies from an 'init' message.
 *
 * @param[in] chan The vortex channel that received the message
 * @param[in] conn The vortex connection
 * @param[in] frame The frame containing the message
 * @param[in] user_data Expected to be a pointer to a jaln_session
 */
/*
void jaln_publisher_init_reply_frame_handler(VortexChannel *chan,
		VortexConnection *v_conn,
		VortexFrame *frame,
		void *user_data);
*/
size_t jaln_publisher_init_reply_frame_handler(char *ptr, size_t size, size_t nmemb, void *user_data);

/**
 * Vortex handler for when publisher's connection closes
 * This calls the user on_connection_close callback
 *
 * @param[in] conn The vortex connection
 * @param[in] data This is expected to be the jaln_connection
 */
void jaln_publisher_on_connection_close(VortexConnection *conn,
					axlPointer data);

/**
 * Callback registered with vortex to finish configuring a jaln_session for use
 * as a publisher. The Vortex library will call this once the new channel is
 * created, or if the remote peer rejects the creation of the channel.
 *
 * @param[in] channel_num The channel number, or -1 if there was an error.
 * @param[in] chan The Vortex Channel, or NULL if there was an error.
 * @param[in] conn The vortex connection
 * @param[in] user_data a pointer to a jaln_session.
 */
/*
void jaln_publisher_on_channel_create(int channel_num,
		VortexChannel *chan, VortexConnection *conn,
		axlPointer user_data);
*/
enum jal_status jaln_publisher_send_init(jaln_session *session, CURL *curl);

/**
 * Configure a jaln_session for use as a publisher. Before modifying the
 * jaln_session, this function will obtain the jaln_session::lock.
 *
 * @param[in] chan The vortex channel
 * @param[in] session The jaln_session
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_configure_pub_session(VortexChannel *chan, jaln_session *session);

/**
 * Configure a jaln_session for use as a publisher. This function expects the
 * jaln_session::lock to be held by the calling thread.
 *
 * @param[in] chan The vortex channel
 * @param[in] session The jaln_session
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_configure_pub_session_no_lock(VortexChannel *chan, jaln_session *session);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // JALN_PUBLISHER_H
