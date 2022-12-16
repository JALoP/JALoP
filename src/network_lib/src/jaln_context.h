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

#include <pthread.h>
#include <axl.h>
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
	pthread_mutex_t lock;
	int ref_cnt;
	int sess_cnt; // Count of open sessions. Need to know when to call on_connection_close
	axl_bool is_connected;
	struct jaln_connection *conn; // Connection to pass to on_connection_close
	struct jaln_publisher_callbacks *pub_callbacks;
	struct jaln_connection_callbacks *conn_callbacks;
	struct jal_digest_ctx *sha256_digest;
	axlList *dgst_algs;
	axlList *xml_compressions;
	enum jaln_digest_challenge digest_challenge;
	char *peer_certs;
	char *public_cert;
	char *private_key;
	void *user_data;
	char pub_id[37]; // holds textual UUID (32 hex chars, 4 dashes, 1 NUL)
	long long int network_timeout;
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

#ifdef __cplusplus
}
#endif

#endif //_JALN_CONTEXT_H_
