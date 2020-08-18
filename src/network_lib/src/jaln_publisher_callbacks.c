/**
 * @file jaln_publisher_callbacks.c This file contains jaln_publisher_callback functions
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
#include <string.h>
#include <jalop/jal_status.h>
#include <jalop/jaln_publisher_callbacks.h>
#include "jaln_publisher_callbacks_internal.h"
#include "jaln_context.h"
#include "jal_alloc.h"

struct jaln_publisher_callbacks *jaln_publisher_callbacks_create()
{
	struct jaln_publisher_callbacks *new_pub_callbacks;
	new_pub_callbacks = jal_calloc(1, sizeof(*new_pub_callbacks));
	return new_pub_callbacks;
}

void jaln_publisher_callbacks_destroy(struct jaln_publisher_callbacks **pub_callbacks)
{
	if (!pub_callbacks || !(*pub_callbacks)) {
		return;
	}
	free(*pub_callbacks);
	*pub_callbacks = NULL;
}

int jaln_publisher_callbacks_is_valid(struct jaln_publisher_callbacks *publisher_callbacks)
{
	if (!publisher_callbacks ||
			!publisher_callbacks->on_journal_resume ||
			!publisher_callbacks->on_subscribe ||
			!publisher_callbacks->on_record_complete ||
			!publisher_callbacks->sync ||
			!publisher_callbacks->notify_digest ||
			!publisher_callbacks->peer_digest) {
		return 0;
	}

	return 1;
}

#if 0
enum jal_status jaln_register_publisher_callbacks(jaln_context *jaln_ctx,
					struct jaln_publisher_callbacks *publisher_callbacks)
{
	if (!jaln_ctx || jaln_ctx->pub_callbacks) {
		return JAL_E_INVAL;
	}
	struct jaln_publisher_callbacks *new_callbacks = NULL;

	if (!jaln_publisher_callbacks_is_valid(publisher_callbacks)) {
		return JAL_E_INVAL;
	}

	new_callbacks = jaln_publisher_callbacks_create();
	memcpy(new_callbacks, publisher_callbacks, sizeof(*new_callbacks));

	jaln_ctx->pub_callbacks = new_callbacks;

	return JAL_OK;
}
#endif

enum jal_status jaln_register_publisher_callbacks(jaln_context *jaln_ctx,
		struct jaln_publisher_callbacks *publisher_callbacks)
{
	if (!jaln_ctx || jaln_ctx->pub_callbacks ||
		!jaln_publisher_callbacks_is_valid(publisher_callbacks)) {
		return JAL_E_INVAL;
	}
        jaln_ctx->pub_callbacks = publisher_callbacks;
        return JAL_OK;
}
