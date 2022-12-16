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
#include <jalop/jaln_network.h>
#include <curl/curl.h>

#include "jaln_session.h"
#include "jaln_digest_resp_info.h"
#include "jaln_digest_info.h"

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
 * @param[in] peer_dgst A jaln_digest_info structure. This is
 * the digest calculated by the remote side and sent in a 'digest' message.
 * @param[out] dgst_resp_info This will be a jaln_digest_resp_info
 * structure. It will contain an entry for the nonce indicated in the \p peer_dgst
 */
void jaln_pub_notify_digests_and_create_digest_response(
		jaln_session *sess,
		axlList *calc_dgsts,
		struct jaln_digest_info *peer_dgst,
		struct jaln_digest_resp_info **dgst_resp_info);

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
 * cURL callback to process the replies from an 'init' message.
 *
 * @param[in] ptr Buffer containing the received reply
 * @param[in] size The size
 * @param[in] nmemb The number of members
 * @param[in] user_data Expected to be a pointer to a jaln_session
 */
size_t jaln_publisher_init_reply_frame_handler(char *ptr, size_t size, size_t nmemb, void *user_data);

/**
 * Curl callback to process the response from a journal-missing message.
 * This response should always only be a journal-missing-response message
 *
 * @param ptr The header info
 * @param size The size of one section of ptr
 * @param nmemb The number of items of size size in ptr
 * @param user_data The data passed to curl (a jaln_session pointer)
 */
size_t jaln_publisher_journal_missing_response_handler(char *ptr, size_t size, size_t nmemb, void *user_data);

/**
 * Curl callback to process a digest-challege message
 *
 * @param ptr The header info
 * @param size The size of one section of ptr
 * @param nmemb The number of items of size size in ptr
 * @param user_data The data passed to curl (a jaln_session pointer)
 */
size_t jaln_publisher_digest_challenge_handler(char *ptr, size_t size, size_t nmemb, void *user_data);

/**
 * Curl callback to process a sync message
 *
 * @param ptr The header info
 * @param size The size of one section of ptr
 * @param nmemb The number of items of size size in ptr
 * @param user_data The data passed to curl (a jaln_session pointer)
 */
size_t jaln_publisher_sync_handler(char *ptr, size_t size, size_t nmemb, void *user_data);

/**
 * Curl callback to process an expected JAL-Record-Failure JAL-Invalid Digest message
 *
 * @param ptr The header info
 * @param size The size of one section of ptr
 * @param nmemb The number of items of size size in ptr
 * @param user_data The data passed to curl (a jaln_session pointer)
 */
size_t jaln_publisher_failed_digest_handler(char *ptr, size_t size, size_t nmemb, void *user_data);

/**
 * Send initialize message to subscriber and parse the returned
 * initialize-ack message.
 *
 * @param[in] session The session to initialize.
 */
enum jal_status jaln_publisher_send_init(jaln_session *session);

/**
 * Send journal-missing message to subscriber and parse the returned
 * journal-missing-response message.
 *
 * @param session The session the journal is missing for
 * @param nonce The nonce of the missing journal
 */
enum jal_status jaln_publisher_send_journal_missing(jaln_session *session, char *nonce);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // JALN_PUBLISHER_H
