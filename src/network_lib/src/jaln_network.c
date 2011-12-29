/**
 * @file jaln_network.c This file contains function definitions for
 * general public network library functions.
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

#include <axl.h>
#include <vortex.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>

#include "jaln_context.h"
#include "jaln_connection.h"
#include "jaln_publisher.h"

axl_bool jaln_disconnect_helper(__attribute__((unused)) axlPointer key,
				axlPointer data,
				__attribute__((unused)) axlPointer user_data)
{
	axlList *sessions = (axlList *) data;
	int i;

	for (i = 0; i < axl_list_length(sessions); i++) {
		jaln_session *sess = NULL;
		sess = (jaln_session *) axl_list_get_nth(sessions, i);

		vortex_mutex_lock(&sess->lock);
		sess->closing = axl_true;
		vortex_mutex_unlock(&sess->lock);
	}

	return axl_false;
}

enum jal_status jaln_disconnect(struct jaln_connection *jal_conn)
{
	if (!jal_conn || !jal_conn->jaln_ctx) {
		return JAL_E_INVAL;
	}

	jaln_context *ctx = jal_conn->jaln_ctx;

	vortex_mutex_lock(&ctx->lock);
	axl_hash_foreach(ctx->sessions_by_conn, jaln_disconnect_helper, NULL);
	vortex_mutex_unlock(&ctx->lock);

	return JAL_OK;
}

enum jal_status jaln_shutdown(struct jaln_connection *jal_conn)
{
	if (!jal_conn || !jal_conn->v_conn) {
		return JAL_E_INVAL;
	}

	axl_bool ret = axl_false;

	vortex_connection_shutdown(jal_conn->v_conn);
	ret = vortex_connection_close(jal_conn->v_conn);
	if (axl_true != ret) {
		return JAL_E_INVAL;
	}

	return JAL_OK;
}
