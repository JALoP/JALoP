/**
 * @file jaln_context.h
 *
 * Public functions for creating and configuring a jaln_context.
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
#ifndef _JALN_CONTEXT_H_
#define _JALN_CONTEXT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <axl.h>
#include <vortex.h>
#include <jalop/jaln_network.h>

#include "jaln_strings.h"


/** Represents the support for digest challenge configuration.
 * Digest challenges may be configured to "on" or "off". This enum represents
 * which configuration states are allowed for this connection, and the preference.
 */
enum jaln_digest_challenge {
	JALN_DC_UNSET     = 0,      //!< No value set.
	JALN_DC_OFF_BIT   = 1 << 0, //!< Bit allowing digest challenge to be configured off.
	JALN_DC_ON_BIT    = 1 << 1, //!< Bit allowing digest challenge to be configured on.
	JALN_DC_PREF_BIT  = 1 << 2, //!< Bit marking if digest challenge is preferred.
	JALN_DC_OFF       = JALN_DC_OFF_BIT, //!< Must be configured off.
	JALN_DC_ON        = JALN_DC_PREF_BIT | JALN_DC_ON_BIT, //!< Must be configured on.
	JALN_DC_PREF_OFF  = JALN_DC_OFF_BIT | JALN_DC_ON_BIT,  //!< May be configured on or off. Off is preferred.
	JALN_DC_PREF_ON   = JALN_DC_PREF_BIT | JALN_DC_ON_BIT | JALN_DC_OFF_BIT //!< May be configured on or off. On is preferred.
};

struct jaln_context_t {
	VortexMutex lock;
	int ref_cnt;
	axl_bool is_connected;
	struct jaln_publisher_callbacks *pub_callbacks;
	struct jaln_subscriber_callbacks *sub_callbacks;
	struct jaln_connection_callbacks *conn_callbacks;
	struct jal_digest_ctx *sha256_digest;
	axlList *dgst_algs;
	axlList *xml_encodings;
	enum jaln_digest_challenge digest_challenge;
	axlHash *sessions_by_conn;
	VortexCtx *vortex_ctx;
	VortexConnection *listener_conn;
	char *peer_certs;
	char *public_cert;
	char *private_key;
	void *user_data;
};

/**
 * Increase the reference count on the context.
 *
 * @param[in] ctx The context to increase the reference count on.
 */
void jaln_ctx_ref(jaln_context *ctx);

/**
 * Decrease the reference count on the context. This function will decrement
 * the reference count on the context and, potentially, delete the context.
 * Callers should not access \p ctx after calling this function.
 *
 * @param[in] ctx The context to decrease the reference count on.
 */
void jaln_ctx_unref(jaln_context *ctx);

/**
 * Removes a given session from the context.
 *
 * @param [in] ctx The ctx to operate on.
 * @param [in] sess The session to remove.
 */
void jaln_ctx_remove_session(jaln_context *ctx, jaln_session *sess);

/**
 * Removes a session from the context. The calling thread must already hold jaln_context::lock.
 *
 * @param [in] ctx The ctx to operate on.
 * @param [in] sess The session to remove.
 *
 * @see jaln_ctx_remove_session_no_lock
 */
void jaln_ctx_remove_session_no_lock(jaln_context *ctx, jaln_session *sess);

/**
 * Add a session to the context. The jaln_context::lock must already be held by
 * the calling thread.
 *
 * @param [in] ctx The ctx to operate on.
 * @param [in] sess The session to add.
 *
 * @return JAL_OK on success, or an error.
 */
enum jal_status jaln_ctx_add_session_no_lock(jaln_context *ctx, jaln_session *sess);

/**
 * Lookup a session by by hostname and record channel number. The calling
 * thread must already hold the jaln_context::lock.
 *
 * @param[in] ctx The context to operate on.
 * @param[in] hostname The hostname of the remote.
 * @param[in] rec_channel_num The BEEP channel number for the record channel of
 * the session to find.
 *
 * @return the jaln_session for the provided hostname and rec_channel_num
 */
jaln_session *jaln_ctx_find_session_by_rec_channel_no_lock(jaln_context *ctx, char * hostname, int rec_channel_num);

/**
 * Utility function for use with axl_list_lookup() to find a session by
 * jaln_session::rec_chan_num
 *
 * @param[in] ptr A jaln_session pointer.
 * @param[in] data An int pointer.
 *
 * @return axl_true if the jaln_session pointed to by \p ptr has the \p
 * rec_chan_num equal to \p data, false otherwise.
 */
axl_bool jaln_ctx_cmp_session_rec_channel_to_channel(axlPointer ptr, axlPointer data);

/**
 * Wrapper function to for use by the sessions_by_conn hash.
 *
 * @param[in] ptr This is expected to be an axlList*, and will be freed as if
 * it were.
 */
void jaln_axl_list_destroy_wrapper(axlPointer ptr);

#ifdef __cplusplus
}
#endif

#endif //_JALN_CONTEXT_H_
