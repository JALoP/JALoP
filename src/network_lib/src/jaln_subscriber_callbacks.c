/**
 * @file jaln_subscriber_callbacks.c
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
#include <jalop/jaln_subscriber_callbacks.h>
#include "jaln_subscriber_callbacks_internal.h"
#include "jaln_context.h"
#include "jal_alloc.h"

struct jaln_subscriber_callbacks *jaln_subscriber_callbacks_create()
{
	struct jaln_subscriber_callbacks *new_callbacks;
	new_callbacks = jal_calloc(1, sizeof(*new_callbacks));
	return new_callbacks;
}

void jaln_subscriber_callbacks_destroy(struct jaln_subscriber_callbacks **callbacks)
{
	if (!callbacks || !(*callbacks)) {
		return;
	}
	free(*callbacks);
	*callbacks = NULL;
}

enum jal_status jaln_subscriber_callbacks_is_valid(struct jaln_subscriber_callbacks *subscriber_callbacks)
{
	if (!subscriber_callbacks->get_subscribe_request ||
	!subscriber_callbacks->on_record_info ||
	!subscriber_callbacks->on_audit ||
	!subscriber_callbacks->on_log ||
	!subscriber_callbacks->on_journal ||
	!subscriber_callbacks->notify_digest ||
	!subscriber_callbacks->on_digest_response ||
	!subscriber_callbacks->message_complete ||
	!subscriber_callbacks->acquire_journal_feeder ||
	!subscriber_callbacks->release_journal_feeder) {
		return JAL_E_INVAL;
	}

	return JAL_OK;
}

enum jal_status jaln_register_subscriber_callbacks(jaln_context *jaln_ctx,
					struct jaln_subscriber_callbacks *subscriber_callbacks)
{
	struct jaln_subscriber_callbacks *new_callbacks = NULL;
	enum jal_status ret;

	ret = jaln_subscriber_callbacks_is_valid(subscriber_callbacks);
	if (ret != JAL_OK) {
		goto out;
	}

	new_callbacks = jaln_subscriber_callbacks_create();
	memcpy(new_callbacks, &subscriber_callbacks, sizeof(*new_callbacks));

	jaln_ctx->sub_callbacks = new_callbacks;
out:
	return ret;
}
