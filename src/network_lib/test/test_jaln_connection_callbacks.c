/**
 * @file test_jaln_connection_callbacks.c This file contains tests for jaln_connection_callbacks.c functions.
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

#include "jaln_context.h"
#include <jalop/jaln_connection_callbacks.h>
#include <jalop/jaln_network.h>
#include "jaln_connection_callbacks_internal.h"
#include <test-dept.h>
#include <string.h>

/* Dummy connection callbacks. */

enum jaln_connect_error my_connect_request_handler(
	const struct jaln_connect_request *req __attribute__((unused)),
	int *selected_compression __attribute__((unused)),
	int *selected_digest __attribute__((unused)),
	void *user_data __attribute__((unused)))
{
	return JALN_CE_ACCEPT;
}

void my_on_channel_close(
	const struct jaln_channel_info *channel_info __attribute__((unused)),
	void *user_data __attribute__((unused)))
{
}

void my_on_connection_close(
	const struct jaln_connection *jal_conn __attribute__((unused)),
	void *user_data __attribute__((unused)))
{
}

void my_connect_ack(
	const struct jaln_connect_ack *ack __attribute__((unused)),
	void *user_data __attribute__((unused)))
{
}

void my_connect_nack(
	const struct jaln_connect_nack *nack __attribute__((unused)),
	void *user_data __attribute__((unused)))
{
}

void test_publish_callbacks_create()
{
	struct jaln_connection_callbacks empty_cb;
	memset(&empty_cb, 0, sizeof(empty_cb));
	struct jaln_connection_callbacks *cb = jaln_connection_callbacks_create();
	assert_not_equals((void*) NULL, cb);
	assert_equals(0, memcmp(&empty_cb, cb, sizeof(*cb)));
	jaln_connection_callbacks_destroy(&cb);
}

void test_publish_callbacks_destroy_does_not_crash()
{
	struct jaln_connection_callbacks *cb = NULL;
	jaln_connection_callbacks_destroy(NULL);
	jaln_connection_callbacks_destroy(&cb);
}

void test_register_connection_callbacks()
{
	jaln_context *ctx = jaln_context_create();

	struct jaln_connection_callbacks *cb = jaln_connection_callbacks_create();
	cb->connect_request_handler = my_connect_request_handler;
	cb->on_channel_close = my_on_channel_close;
	cb->on_connection_close = my_on_connection_close;
	cb->connect_ack = my_connect_ack;
	cb->connect_nack = my_connect_nack;

	assert_equals(JAL_OK, jaln_register_connection_callbacks(ctx, cb));

	jaln_context_destroy(&ctx);
}

void test_register_connection_callbacks_fails_with_invalid()
{
	jaln_context *ctx = jaln_context_create();

	assert_equals(JAL_E_INVAL, jaln_register_connection_callbacks(ctx, NULL));

	struct jaln_connection_callbacks *cb = jaln_connection_callbacks_create();
	cb->connect_request_handler = NULL;
	cb->on_channel_close = NULL;
	cb->on_connection_close = NULL;
	cb->connect_ack = NULL;
	cb->connect_nack = NULL;

	assert_equals(JAL_E_INVAL, jaln_register_connection_callbacks(ctx, cb));

	cb->connect_request_handler = my_connect_request_handler;
	assert_equals(JAL_E_INVAL, jaln_register_connection_callbacks(ctx, cb));

	cb->on_channel_close = my_on_channel_close;
	assert_equals(JAL_E_INVAL, jaln_register_connection_callbacks(ctx, cb));

	cb->on_connection_close = my_on_connection_close;
	assert_equals(JAL_E_INVAL, jaln_register_connection_callbacks(ctx, cb));

	cb->connect_ack = my_connect_ack;
	assert_equals(JAL_E_INVAL, jaln_register_connection_callbacks(ctx, cb));

	/* Callback will be valid after this, testing with invalid context. */
	cb->connect_nack = my_connect_nack;
	assert_equals(JAL_E_INVAL, jaln_register_connection_callbacks(NULL, cb));

	/* Unsetting to invalidate (all set but first). */
	cb->connect_request_handler = NULL;
	assert_equals(JAL_E_INVAL, jaln_register_connection_callbacks(ctx, cb));

	jaln_connection_callbacks_destroy(&cb);
	jaln_context_destroy(&ctx);
}
