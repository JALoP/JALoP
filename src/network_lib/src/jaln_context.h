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

struct jaln_session;

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
	VortexCtx *vortex_ctx;
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

#ifdef __cplusplus
}
#endif

#endif //_JALN_CONTEXT_H_
