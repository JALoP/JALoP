/**
 * @file test_jaln_sub_dgst_channel.c This file contains tests for jaln_sub_dgst_channel.c functions.
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
#include "jaln_context.h"
#include "jaln_channel_info.h"
#include "jaln_digest_info.h"
#include "jaln_digest_resp_info.h"
#include "jaln_digest_resp_msg_handler.h"
#include "jaln_message_helpers.h"
#include "jaln_sub_dgst_channel.h"

static jaln_context *ctx;
static struct jaln_channel_info *ch_info;
static jaln_session *sess;
static axlList *dgst_list;

int on_digest_response(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *nonce,
		__attribute__((unused)) const enum jaln_digest_status status,
		__attribute__((unused)) const void *user_data)
{
	return JAL_OK;
}

VortexFrame *vortex_channel_wait_reply_always_succeeds(__attribute__((unused)) VortexChannel *channel,
							__attribute__((unused)) int msg_no,
							__attribute__((unused)) WaitReplyData *wait_reply)
{
	return (VortexFrame *)0xdeadbeef;
}

axl_bool vortex_channel_send_msg_and_wait_always_succeeds(__attribute__((unused)) VortexChannel *channel,
							__attribute__((unused)) const void *message,
							__attribute__((unused)) size_t message_size,
							__attribute__((unused)) int *msg_no,
							__attribute__((unused)) WaitReplyData *wait_reply)
{
	return axl_true;
}

axl_bool vortex_channel_send_msg_always_succeeds(__attribute__((unused)) VortexChannel *channel,
						__attribute__((unused)) const void *message,
						__attribute__((unused)) size_t message_size,
						__attribute__((unused)) int *msg_no)
{
	return axl_true;
}

VortexMimeHeader *fake_vortex_frame_get_mime_header(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-message")) {
		return (VortexMimeHeader *) "digest-response";
	} else if (0 == strcasecmp(header_name, "jal-count")) {
		return (VortexMimeHeader *) "3";
	}
	return NULL;
}

enum jal_status jaln_process_digest_resp_always_succeeds(__attribute__((unused)) VortexFrame *frame,
							__attribute__((unused)) axlList **dgst_resp_list_out)
{
	return JAL_OK;
}

enum jal_status fake_jaln_process_digest_resp(__attribute__((unused)) VortexFrame *frame,
						axlList **dgst_resp_list_out)
{

	*dgst_resp_list_out = axl_list_new(jaln_axl_equals_func_digest_resp_info_nonce, jaln_axl_destroy_digest_resp_info);

	axl_list_append(*dgst_resp_list_out, jaln_digest_resp_info_create("nonce1", JALN_DIGEST_STATUS_CONFIRMED));

	axl_list_append(*dgst_resp_list_out, jaln_digest_resp_info_create("nonce2", JALN_DIGEST_STATUS_CONFIRMED));

	axl_list_append(*dgst_resp_list_out, jaln_digest_resp_info_create("nonce3", JALN_DIGEST_STATUS_CONFIRMED));

	return JAL_OK;
}

void fake_vortex_frame_unref(__attribute__((unused)) VortexFrame *frame)
{
	return;
}

void setup()
{
	int dgst_val;
	dgst_list = jaln_digest_info_list_create();
	ctx = jaln_context_create();
	ctx->sub_callbacks = jaln_subscriber_callbacks_create();
	ctx->sub_callbacks->on_digest_response = on_digest_response;
	sess = jaln_session_create();
	ch_info = sess->ch_info;
	sess->jaln_ctx = ctx;
	sess->dgst_chan = (VortexChannel *)0xdeadbeef;

	dgst_val = 0xf001;
	axl_list_append(dgst_list, jaln_digest_info_create("nonce1", (uint8_t *)&dgst_val, sizeof(dgst_val)));
	dgst_val = 0xf002;
	axl_list_append(dgst_list, jaln_digest_info_create("nonce2", (uint8_t *)&dgst_val, sizeof(dgst_val)));
	dgst_val = 0xf003;
	axl_list_append(dgst_list, jaln_digest_info_create("nonce3", (uint8_t *)&dgst_val, sizeof(dgst_val)));
}

void teardown()
{
	jaln_session_destroy(&sess);
	axl_list_free(dgst_list);
}

void test_jaln_send_digest_and_sync_no_lock_does_not_crash_with_bad_input()
{
	replace_function(vortex_channel_wait_reply, vortex_channel_wait_reply_always_succeeds);
	replace_function(vortex_channel_send_msg_and_wait, vortex_channel_send_msg_and_wait_always_succeeds);
	replace_function(vortex_channel_send_msg, vortex_channel_send_msg_always_succeeds);
	replace_function(jaln_process_digest_resp, jaln_process_digest_resp_always_succeeds);
	replace_function(vortex_frame_unref, fake_vortex_frame_unref);

	jaln_send_digest_and_sync_no_lock(NULL, dgst_list);
	jaln_send_digest_and_sync_no_lock(sess, NULL);

	sess->dgst_chan = NULL;
	jaln_send_digest_and_sync_no_lock(sess, dgst_list);
	sess->dgst_chan = (VortexChannel *)0xf00;

	sess->ch_info = NULL;
	jaln_send_digest_and_sync_no_lock(sess, dgst_list);
	sess->ch_info = ch_info;

	sess->jaln_ctx = NULL;
	jaln_send_digest_and_sync_no_lock(sess, dgst_list);
	sess->jaln_ctx = ctx;
	
	sess->jaln_ctx->sub_callbacks->on_digest_response = NULL;
	jaln_send_digest_and_sync_no_lock(sess, dgst_list);
	sess->jaln_ctx->sub_callbacks->on_digest_response = on_digest_response;

	jaln_subscriber_callbacks_destroy(&sess->jaln_ctx->sub_callbacks);
	jaln_send_digest_and_sync_no_lock(sess, dgst_list);
}

void test_jaln_send_digest_and_sync_no_lock_succeeds()
{
	replace_function(vortex_channel_wait_reply, vortex_channel_wait_reply_always_succeeds);
	replace_function(vortex_channel_send_msg_and_wait, vortex_channel_send_msg_and_wait_always_succeeds);
	replace_function(vortex_channel_send_msg, vortex_channel_send_msg_always_succeeds);
	replace_function(jaln_process_digest_resp, fake_jaln_process_digest_resp);
	replace_function(vortex_frame_unref, fake_vortex_frame_unref);

	jaln_send_digest_and_sync_no_lock(sess, dgst_list);
}
