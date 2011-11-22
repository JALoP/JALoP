/**
 * @file This file contains tests for jaln_listen.c functions.
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

#include <test-dept.h>
#include <test-dept.h>
#include <vortex.h>

#include "jaln_listen.h"
#include "jaln_session.h"

static jaln_context *ctx;
static struct jaln_session *sess;
static const char *server_name = "some_server";

VortexChannel *fake_connection_get_channel(__attribute__((unused)) VortexConnection *conn, int chan_num)
{
	if (-1 == chan_num) {
		return NULL;
	}
	return (VortexChannel*) 0xaabbccdd;
}

void fake_channel_set_automatic_mime(__attribute__((unused)) VortexChannel *chan,
		__attribute__((unused)) int flag)
{
	return;
}

void fake_channel_set_serialize(__attribute__((unused)) VortexChannel *chan,
		__attribute__((unused)) axl_bool flag)
{
	return;
}

struct jaln_session * fake_find_session_by_rec_channel_fails(
		__attribute__((unused)) jaln_context* ctx,
		__attribute__((unused)) char *server_name_cpy,
		__attribute__((unused)) int paired_chan_num)
{
	return NULL;
}

struct jaln_session * fake_find_session_by_rec_channel_no_lock(
		__attribute__((unused)) jaln_context* ctx,
		__attribute__((unused)) char *server_name_cpy,
		__attribute__((unused)) int paired_chan_num)
{
	return sess;
}

axl_bool fake_associate_digest_channel_no_lock(
		__attribute__((unused)) struct jaln_session* sess,
		__attribute__((unused)) VortexChannel *chan,
		__attribute__((unused)) int paired_chan_num)
{
	return axl_true;
}

axl_bool fake_associate_digest_channel_fails(
		__attribute__((unused)) struct jaln_session* sess,
		__attribute__((unused)) VortexChannel *chan,
		__attribute__((unused)) int paired_chan_num)
{
	return axl_false;
}

void setup()
{
	replace_function(vortex_connection_get_channel, fake_connection_get_channel);
	replace_function(vortex_channel_set_automatic_mime, fake_channel_set_automatic_mime);
	replace_function(vortex_channel_set_serialize, fake_channel_set_serialize);
	replace_function(jaln_ctx_find_session_by_rec_channel_no_lock, fake_find_session_by_rec_channel_no_lock);
	replace_function(jaln_session_associate_digest_channel_no_lock, fake_associate_digest_channel_no_lock);
	ctx = jaln_context_create();
	sess = jaln_session_create();
	sess->jaln_ctx = ctx;
	jaln_ctx_ref(ctx);
}

void teardown()
{
	restore_function(vortex_connection_get_channel);
	restore_function(vortex_channel_set_automatic_mime);
	restore_function(vortex_channel_set_serialize);
	restore_function(jaln_ctx_find_session_by_rec_channel_no_lock);
	restore_function(jaln_session_associate_digest_channel_no_lock);

	if (ctx->ref_cnt > 1) {
		jaln_ctx_unref(ctx);
	}
	jaln_session_unref(sess);
}

void test_add_new_digest_channel_no_lock()
{
	assert_true(jaln_listener_handle_new_digest_channel_no_lock(ctx,
		(VortexConnection *) 0xbadf00d,
		server_name, 2, 4));
}

void test_add_new_digest_channel_no_lock_fails_with_bad_input()
{
	assert_false(jaln_listener_handle_new_digest_channel_no_lock(NULL, (VortexConnection *) 0xbadf00d, server_name, 2, 4));
	assert_false(jaln_listener_handle_new_digest_channel_no_lock(ctx, NULL, server_name, 2, 4));
	assert_false(jaln_listener_handle_new_digest_channel_no_lock(ctx, (VortexConnection *) 0xbadf00d, NULL, 2, 4));
	assert_false(jaln_listener_handle_new_digest_channel_no_lock(ctx, (VortexConnection *) 0xbadf00d, server_name, -1, 4));
	assert_false(jaln_listener_handle_new_digest_channel_no_lock(ctx, (VortexConnection *) 0xbadf00d, server_name, 2, -1));
}

void test_add_new_digest_channel_no_lock_fails_if_cannot_find_session()
{
	replace_function(jaln_ctx_find_session_by_rec_channel_no_lock, fake_find_session_by_rec_channel_fails);
	assert_false(jaln_listener_handle_new_digest_channel_no_lock(ctx, (VortexConnection *) 0xbadf00d, server_name, 2, 4));
}

void test_add_new_digest_channel_no_lock_fails_if_cannot_associate_channel()
{
	replace_function(jaln_session_associate_digest_channel_no_lock, fake_associate_digest_channel_fails);
	assert_false(jaln_listener_handle_new_digest_channel_no_lock(ctx, (VortexConnection *) 0xbadf00d, server_name, 2, 4));
}
