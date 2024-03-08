/**
 * @file jaln_connection_callbacks.c This file contains jaln_connection_callback functions
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

#include <stdlib.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_connection_callbacks.h>
#include "jal_alloc.h"
#include "jaln_context.h"
#include "jaln_connection_callbacks_internal.h"

struct jaln_connection_callbacks *jaln_connection_callbacks_create()
{
	struct jaln_connection_callbacks *new_callbacks;
	new_callbacks = jal_calloc(1, sizeof(*new_callbacks));
	return new_callbacks;
}

void jaln_connection_callbacks_destroy(struct jaln_connection_callbacks **callbacks)
{
	if (!callbacks || !(*callbacks)) {
		return;
	}
	free(*callbacks);
	*callbacks = NULL;
}

int jaln_connection_callbacks_is_valid(struct jaln_connection_callbacks *callbacks)
{
	if (!callbacks ||
			!callbacks->on_channel_close ||
			!callbacks->on_connection_close ||
			!callbacks->connect_ack ||
			!callbacks->connect_nack) {
		return 0;
	}
	return 1;
}

enum jal_status jaln_register_connection_callbacks(jaln_context *jaln_ctx,
		struct jaln_connection_callbacks *conn_callbacks)
{
	if (!jaln_ctx || jaln_ctx->conn_callbacks ||
			!jaln_connection_callbacks_is_valid(conn_callbacks)) {
		return JAL_E_INVAL;
	}
	jaln_ctx->conn_callbacks = conn_callbacks;
	return JAL_OK;
}
