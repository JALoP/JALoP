/**
 * @file jaln_publisher.h This file contains function
 * declarations related to publishing records to a remote.
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

#ifndef JALN_PUBLISHER_H
#define JALN_PUBLISHER_H

#include <axl.h>
#include <vortex.h>
#include <jalop/jaln_network.h>

#include "jaln_session.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Compare 2 lists of jaln_digest_info structures to determine if the remote
 * side correctly received a set of records. The functions tries to match each
 * jaln_digest_info from \p peer_dgsts to one contained in \p calc_dgsts. For
 * each jaln_digest_info in \p peer_dgsts, it creates a corresponding
 * jaln_digest_resp_info and adds it to a list. As serial IDs are matched in \p
 * calc_dgsts, they are removed from the list.
 *
 * @param[in] sess The session related to the digests.
 * @param[in] calc_dgsts An axlList of jlan_digest_info structures. This is the
 * digests calculated locally by the network library.
 * @param[in] peer_dgsts An axlList of jaln_digest_info structures. These are
 * the digests calculated by the remote side and sent in a 'digest' message.
 * @param[out] dgst_resp_infos This will be a list of jaln_digest_resp_info
 * structures. It will contain an entry for each serial-ID indicated in \p
 * peer_dgsts.
 */
void jaln_pub_notify_digests_and_create_digest_response(
		struct jaln_session *sess,
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
		struct jaln_session *sess,
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
enum jal_status jaln_publisher_handle_digest(struct jaln_session *sess,
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
struct jaln_session *jaln_publisher_create_session(jaln_context *ctx, const char *host, enum jaln_record_type type);

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
enum jal_status jaln_pub_handle_subscribe(struct jaln_session *session,
		VortexChannel *chan,
		VortexFrame *frame,
		int msg_no);


#ifdef __cplusplus
}
#endif // __cplusplus

#endif // JALN_PUBLISHER_H