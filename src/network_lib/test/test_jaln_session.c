/**
 * @file test_jaln_session.c This file contains tests for jaln_session.c functions.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <jalop/jaln_network.h>
#include <test-dept.h>
#include <string.h>

#include "jal_alloc.h"

#include "jaln_context.h"
#include "jaln_session.h"
#include "jaln_digest_info.h"
#include "jaln_sub_dgst_channel.h"

#define NONCE "nonce_1234"

static jaln_session *sess = NULL;
static struct jaln_pub_data *pub_data = NULL;
static struct jaln_sub_data *sub_data = NULL;
static struct jaln_payload_feeder zeroed_feeder;
static char *nonce = NULL;
static uint8_t *dgst_buf = NULL;
static uint64_t dgst_len;
static axl_bool cond_signal_called;

void fake_cond_signal(__attribute__((unused)) VortexCond *cond)
{
	cond_signal_called = axl_true;
}

void fake_create_sub_digest_channel_thread_no_lock(__attribute__((unused)) jaln_session *session)
{
	return;
}

axl_bool fake_vortex_thread_create(__attribute__((unused))  VortexThread *thread_def,
				__attribute__((unused)) VortexThreadFunc func,
				__attribute__((unused)) axlPointer user_data,
				...)
{
	return axl_true;
}

void fake_vortex_channel_set_automatic_mime(__attribute__((unused)) VortexChannel *channel,
					__attribute__((unused)) int value)
{
	return;
}

void fake_vortex_channel_set_serialize(__attribute__((unused)) VortexChannel *channel,
					__attribute__((unused)) axl_bool serialize)
{
	return;
}

void fake_vortex_channel_set_closed_handler(__attribute__((unused)) VortexChannel *channel,
					__attribute__((unused)) VortexOnClosedChannel closed,
					__attribute__((unused)) axlPointer user_data)
{
	return;
}

void fake_vortex_channel_set_close_handler(__attribute__((unused)) VortexChannel *channel,
					__attribute__((unused)) VortexOnCloseChannel close,
					__attribute__((unused)) axlPointer user_data)
{
	return;
}

void fake_vortex_channel_set_received_handler(__attribute__((unused)) VortexChannel *channel,
					__attribute__((unused)) VortexOnFrameReceived received,
					__attribute__((unused)) axlPointer user_data)
{
	return;
}

void fake_on_channel_close(__attribute__((unused)) const struct jaln_channel_info *ch_info,
			__attribute__((unused)) void *user_data)
{
	return;
}

VortexConnection *fake_channel_get_connection(__attribute__((unused)) VortexChannel *vchan)
{
	return (VortexConnection *)0xbadf00d;
}

axl_bool fake_connection_is_ok_fails(
		__attribute__((unused)) VortexConnection *vcon,
		__attribute__((unused)) axl_bool free_on_fail)
{
	return axl_false;
}

axl_bool fake_connection_is_ok_success(
		__attribute__((unused)) VortexConnection *vcon,
		__attribute__((unused)) axl_bool free_on_fail)
{
	return axl_true;
}

void setup()
{
	sess = jaln_session_create();
	pub_data = jaln_pub_data_create();
	sub_data = jaln_sub_data_create();
	memset(&zeroed_feeder, 0, sizeof(zeroed_feeder));
	nonce = jal_strdup(NONCE);
	dgst_len = 4;
	dgst_buf = (uint8_t*) jal_malloc(dgst_len);
	dgst_buf[0] = 0xa;
	dgst_buf[1] = 0x1;
	dgst_buf[2] = 0xb;
	dgst_buf[3] = 0x0;
	cond_signal_called = axl_false;

	replace_function(vortex_thread_create, fake_vortex_thread_create);
	replace_function(jaln_create_sub_digest_channel_thread_no_lock, fake_create_sub_digest_channel_thread_no_lock);
	replace_function(vortex_channel_get_connection, fake_channel_get_connection);
	replace_function(vortex_connection_is_ok, fake_connection_is_ok_success);
}

void teardown()
{
	jaln_session_destroy(&sess);
	jaln_pub_data_destroy(&pub_data);
	jaln_sub_data_destroy(&sub_data);
	free(nonce);
	free(dgst_buf);
	restore_function(vortex_thread_create);
	restore_function(vortex_channel_get_connection);
	restore_function(vortex_connection_is_ok);
}

void test_session_destroy_unrefs_jaln_ctx()
{
	jaln_context *ctx = jaln_context_create();
	jaln_ctx_ref(ctx);
	sess->jaln_ctx = ctx;
	assert_equals(2, ctx->ref_cnt);
	jaln_session_destroy(&sess);
	assert_equals(1, ctx->ref_cnt);
	jaln_ctx_unref(ctx);
}

void test_session_create()
{
	assert_not_equals((void*) NULL, sess);
	assert_equals(1, sess->ref_cnt);
	assert_equals((void*) NULL, sess->jaln_ctx);
	assert_equals((void*) NULL, sess->dgst);
	assert_equals((void*) NULL, sess->rec_chan);
	assert_equals((void*) NULL, sess->dgst_chan);
	assert_equals((void*) NULL, sess->dgst);
	assert_equals(-1, sess->rec_chan_num);
	assert_equals(-1, sess->dgst_chan_num);
	assert_not_equals((void*) NULL, sess->ch_info);
	assert_false(sess->closing);
	assert_false(sess->errored);
	assert_not_equals((void*) NULL, sess->dgst_list);
	assert_equals(JALN_ROLE_UNSET, sess->role);
	assert_equals(JALN_SESSION_DEFAULT_DGST_LIST_MAX, sess->dgst_list_max);
	assert_equals(JALN_SESSION_DEFAULT_DGST_TIMEOUT_MICROS, sess->dgst_timeout);
	assert_equals((void*) NULL, sess->sub_data);
	assert_equals((void*) NULL, sess->pub_data);
}

void test_session_destroy_does_not_crash()
{
	jaln_session *sess = NULL;
	jaln_session_destroy(NULL);
	jaln_session_destroy(&sess);
}

void test_session_destroy_sets_pointer_to_null()
{
	jaln_session_destroy(&sess);
	assert_equals((void*)NULL, sess);
}

void test_session_destroy_cleans_up_pub_data()
{
	// run under valgrind to check.
	sess->role = JALN_ROLE_SUBSCRIBER;
	sess->sub_data = sub_data;
	sub_data = NULL;
}

void test_session_destroy_cleans_up_sub_data()
{
	sess->role = JALN_ROLE_PUBLISHER;
	sess->pub_data = pub_data;
	pub_data = NULL;
}

void test_ref_and_unref_work()
{
	assert_equals(1, sess->ref_cnt);
	jaln_session_ref(sess);
	assert_equals(2, sess->ref_cnt);

	jaln_session_unref(sess);
	assert_equals(1, sess->ref_cnt);
	jaln_session_unref(sess);
	// The second unref should destroy the sess, run on valgrind to check
	// for leaks.
	sess = NULL;
}

void test_jaln_session_list_create_works()
{
	axlList *sessions = jaln_session_list_create();
	assert_not_equals((void*) NULL, sessions);
	axl_list_free(sessions);
}

void test_jaln_session_does_not_free_sessions()
{
	// run under valgrind to look for invalid frees
	axlList *sessions = jaln_session_list_create();
	axl_list_append(sessions, sess);
	axl_list_free(sessions);
}

void test_jaln_ptrs_equals()
{
	axlPointer a = (axlPointer) 0x12345;
	axlPointer  b = (axlPointer) 0x54321;
	assert_equals((a - b), jaln_ptrs_equal(a, b));
	assert_equals((b - a), jaln_ptrs_equal(b, a));
	assert_equals(0, jaln_ptrs_equal(a,a));
}

void test_pub_data_create()
{
	assert_not_equals((void*) NULL, pub_data);
	assert_equals(0, memcmp(&pub_data->journal_feeder, &zeroed_feeder, sizeof(zeroed_feeder)));
	assert_equals(0, pub_data->vortex_feeder_sz);
	assert_equals(-1, pub_data->msg_no);
	assert_equals((void*)NULL, pub_data->nonce);
	assert_equals((void*)NULL, pub_data->headers);
	assert_equals((void*)NULL, pub_data->sys_meta);
	assert_equals((void*)NULL, pub_data->app_meta);
	assert_equals((void*)NULL, pub_data->payload);
	assert_equals(0, pub_data->headers_sz);
	assert_equals(0, pub_data->sys_meta_sz);
	assert_equals(0, pub_data->app_meta_sz);
	assert_equals(0, pub_data->payload_sz);

	assert_equals(0, pub_data->headers_off);
	assert_equals(0, pub_data->sys_meta_off);
	assert_equals(0, pub_data->app_meta_off);
	assert_equals(0, pub_data->payload_off);
	assert_equals(0, pub_data->break_off);

	assert_false(pub_data->finished_headers);
	assert_false(pub_data->finished_sys_meta);
	assert_false(pub_data->finished_sys_meta_break);
	assert_false(pub_data->finished_app_meta);
	assert_false(pub_data->finished_app_meta_break);
	assert_false(pub_data->finished_payload);
	assert_false(pub_data->finished_payload_break);

	assert_equals((void*)NULL, pub_data->dgst_inst);
	assert_equals((void*)NULL, pub_data->dgst);
}

void test_pub_data_destroy_does_not_crash()
{
	struct jaln_pub_data *pd = NULL;
	jaln_pub_data_destroy(NULL);
	jaln_pub_data_destroy(&pd);
}

void test_pub_data_destroy_sets_pointer_to_null()
{
	jaln_pub_data_destroy(&pub_data);
	assert_equals((void*)NULL, pub_data);
}

void test_sub_data_create()
{
	assert_not_equals((void*) NULL, sub_data);
	assert_equals((void*) NULL, sub_data->curr_frame_handler);
	assert_equals((void*) NULL, sub_data->sm);
}

void test_set_errored_works()
{
	assert_false(sess->errored);
	jaln_session_set_errored_no_lock(sess);
	assert_true(sess->errored);
}

void test_notify_unclean_for_rec_channel_unrefs_session_and_clears_rec_info()
{
	jaln_session_ref(sess);

	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = (VortexChannel*) 0xdeadbeef;
	sess->dgst_chan_num = 5;

	jaln_session_notify_unclean_channel_close(sess->rec_chan, sess);
	assert_equals((void*)NULL, sess->rec_chan);
	assert_equals(-1, sess->rec_chan_num);

	assert_equals((void*) 0xdeadbeef, sess->dgst_chan);
	assert_equals(5, sess->dgst_chan_num);

	assert_equals(1, sess->ref_cnt);
}

void test_notify_unclean_for_dgst_channel_unrefs_session_and_clears_rec_info()
{
	jaln_session_ref(sess);

	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = (VortexChannel*) 0xdeadbeef;
	sess->dgst_chan_num = 5;

	jaln_session_notify_unclean_channel_close(sess->dgst_chan, sess);
	assert_equals((void*)NULL, sess->dgst_chan);
	assert_equals(-1, sess->dgst_chan_num);

	assert_equals((void*) 0xbadf00d, sess->rec_chan);
	assert_equals(3, sess->rec_chan_num);

	assert_equals(1, sess->ref_cnt);
}

void test_notify_unclean_does_nothing_with_bad_channel()
{
	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = (VortexChannel*) 0xdeadbeef;
	sess->dgst_chan_num = 5;

	jaln_session_notify_unclean_channel_close((VortexChannel*) 0xcdcdcdcd, sess);

	assert_equals((void*) 0xbadf00d, sess->rec_chan);
	assert_equals(3, sess->rec_chan_num);

	assert_equals((void*)0xdeadbeef, sess->dgst_chan);
	assert_equals(5, sess->dgst_chan_num);

	assert_equals(1, sess->ref_cnt);
}

void test_notify_unclean_channel_close_ignores_dgst_channel_if_null()
{
	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = NULL;
	sess->dgst_chan_num = -1;

	jaln_session_ref(sess);
	jaln_session_notify_unclean_channel_close(sess->rec_chan, sess);

	assert_equals((void*) NULL, sess->rec_chan);
	assert_equals(-1, sess->rec_chan_num);

	assert_equals((void*)NULL, sess->dgst_chan);
	assert_equals(-1, sess->dgst_chan_num);

	assert_equals(1, sess->ref_cnt);
}

void test_notify_close_for_rec_channel_unrefs_session_and_clears_rec_info()
{
	jaln_session_ref(sess);

	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = (VortexChannel*) 0xdeadbeef;
	sess->dgst_chan_num = 5;

	jaln_session_notify_close((VortexConnection*) 0xbadf00d,
			sess->rec_chan_num, axl_true, NULL, NULL, sess);
	assert_equals((void*)NULL, sess->rec_chan);
	assert_equals(-1, sess->rec_chan_num);

	assert_equals((void*) 0xdeadbeef, sess->dgst_chan);
	assert_equals(5, sess->dgst_chan_num);

	assert_equals(1, sess->ref_cnt);
}

void test_notify_close_for_rec_channel_does_nothing_if_channel_was_not_closed()
{
	jaln_session_ref(sess);

	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = (VortexChannel*) 0xdeadbeef;
	sess->dgst_chan_num = 5;

	jaln_session_notify_close((VortexConnection*) 0xbadf00d,
			sess->rec_chan_num, axl_false, NULL, NULL, sess);
	assert_equals((void*)0xbadf00d, sess->rec_chan);
	assert_equals(3, sess->rec_chan_num);

	assert_equals((void*) 0xdeadbeef, sess->dgst_chan);
	assert_equals(5, sess->dgst_chan_num);

	assert_equals(2, sess->ref_cnt);

	jaln_session_unref(sess);
}

void test_notify_close_for_dgst_channel_unrefs_session_and_clears_rec_info()
{
	jaln_session_ref(sess);

	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = (VortexChannel*) 0xdeadbeef;
	sess->dgst_chan_num = 5;

	jaln_session_notify_close((VortexConnection*) 0xbadf00d,
			sess->dgst_chan_num, axl_true, NULL, NULL, sess);
	assert_equals((void*)NULL, sess->dgst_chan);
	assert_equals(-1, sess->dgst_chan_num);

	assert_equals((void*) 0xbadf00d, sess->rec_chan);
	assert_equals(3, sess->rec_chan_num);

	assert_equals(1, sess->ref_cnt);
}

void test_notify_close_does_nothing_with_bad_channel()
{
	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = (VortexChannel*) 0xdeadbeef;
	sess->dgst_chan_num = 5;

	jaln_session_notify_close((VortexConnection*) 0xbadf00d, 12,
			axl_true, NULL, NULL, sess);

	assert_equals((void*) 0xbadf00d, sess->rec_chan);
	assert_equals(3, sess->rec_chan_num);

	assert_equals((void*)0xdeadbeef, sess->dgst_chan);
	assert_equals(5, sess->dgst_chan_num);

	assert_equals(1, sess->ref_cnt);
}

void test_on_close_channel_for_rec_channel_unrefs_session_and_clears_rec_info()
{
	jaln_context *ctx = jaln_context_create();
	struct jaln_connection_callbacks *conn_cbs = jaln_connection_callbacks_create();

	conn_cbs->on_channel_close = fake_on_channel_close;

	ctx->conn_callbacks = conn_cbs;
	sess->jaln_ctx = ctx;

	jaln_session_ref(sess);

	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = (VortexChannel*) 0xdeadbeef;
	sess->dgst_chan_num = 5;

	jaln_session_on_close_channel(sess->rec_chan_num, (VortexConnection*) 0xdeadbeef, sess);
	assert_equals((void*)NULL, sess->rec_chan);
	assert_equals(-1, sess->rec_chan_num);

	assert_equals((void*) 0xdeadbeef, sess->dgst_chan);
	assert_equals(5, sess->dgst_chan_num);

	assert_equals(1, sess->ref_cnt);
}

void test_on_close_channel_for_dgst_channel_unrefs_session_and_clears_rec_info()
{
	jaln_context *ctx = jaln_context_create();
	struct jaln_connection_callbacks *conn_cbs = jaln_connection_callbacks_create();

	conn_cbs->on_channel_close = fake_on_channel_close;

	ctx->conn_callbacks = conn_cbs;
	sess->jaln_ctx = ctx;

	jaln_session_ref(sess);

	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = (VortexChannel*) 0xdeadbeef;
	sess->dgst_chan_num = 5;

	jaln_session_on_close_channel(sess->dgst_chan_num, (VortexConnection*) 0xdeadbeef, sess);
	assert_equals((void*)NULL, sess->dgst_chan);
	assert_equals(-1, sess->dgst_chan_num);

	assert_equals((void*) 0xbadf00d, sess->rec_chan);
	assert_equals(3, sess->rec_chan_num);

	assert_equals(1, sess->ref_cnt);
}

void test_on_close_channel_does_nothing_with_bad_channel()
{
	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = 3;
	sess->dgst_chan = (VortexChannel*) 0xdeadbeef;
	sess->dgst_chan_num = 5;

	jaln_session_on_close_channel(12, (VortexConnection*) 0xdeadbeef, sess);

	assert_equals((void*) 0xbadf00d, sess->rec_chan);
	assert_equals(3, sess->rec_chan_num);

	assert_equals((void*)0xdeadbeef, sess->dgst_chan);
	assert_equals(5, sess->dgst_chan_num);

	assert_equals(1, sess->ref_cnt);
}

void test_add_to_dgst_list_works()
{
	assert_equals(0, axl_list_length(sess->dgst_list));
	assert_equals(JAL_OK, jaln_session_add_to_dgst_list(sess, nonce, dgst_buf, dgst_len));
	assert_equals(1, axl_list_length(sess->dgst_list));
	struct jaln_digest_info *di = axl_list_get_first(sess->dgst_list);
	assert_not_equals((void*) NULL, di);
	assert_equals(0, memcmp(di->nonce, nonce, strlen(nonce) + 1));
	assert_equals(dgst_len, di->digest_len);
	assert_equals(0, memcmp(di->digest, dgst_buf, dgst_len));
}

void test_add_to_dgst_list_signals_for_subscriber()
{
	replace_function(vortex_cond_signal, fake_cond_signal);
	assert_equals(0, axl_list_length(sess->dgst_list));
	sess->dgst_list_max = 1;
	sess->role = JALN_ROLE_SUBSCRIBER;
	assert_equals(JAL_OK, jaln_session_add_to_dgst_list(sess, nonce, dgst_buf, dgst_len));
	assert_true(cond_signal_called);
}

void test_add_to_dgst_list_does_not_signal_for_publisher()
{
	replace_function(vortex_cond_signal, fake_cond_signal);
	assert_equals(0, axl_list_length(sess->dgst_list));
	sess->dgst_list_max = 1;
	sess->role = JALN_ROLE_PUBLISHER;
	assert_equals(JAL_OK, jaln_session_add_to_dgst_list(sess, nonce, dgst_buf, dgst_len));
	assert_false(cond_signal_called);
}

void test_add_to_dgst_fails_with_bad_input()
{
	assert_equals(0, axl_list_length(sess->dgst_list));
	assert_equals(JAL_E_INVAL, jaln_session_add_to_dgst_list(NULL, nonce, dgst_buf, dgst_len));
	assert_equals(0, axl_list_length(sess->dgst_list));
	assert_equals(JAL_E_INVAL, jaln_session_add_to_dgst_list(sess, NULL, dgst_buf, dgst_len));
	assert_equals(0, axl_list_length(sess->dgst_list));
	assert_equals(JAL_E_INVAL, jaln_session_add_to_dgst_list(sess, nonce, NULL, dgst_len));
	assert_equals(0, axl_list_length(sess->dgst_list));
	assert_equals(JAL_E_INVAL, jaln_session_add_to_dgst_list(sess, nonce, dgst_buf, 0));
	assert_equals(0, axl_list_length(sess->dgst_list));
}

void test_jaln_session_associate_digest_channel_no_lock_does_not_crash_with_bad_input()
{
	assert_equals(axl_false, jaln_session_associate_digest_channel_no_lock(NULL,
									(VortexChannel *)0xbadf00d, 1));
	assert_equals(axl_false, jaln_session_associate_digest_channel_no_lock(sess, NULL, 1));

}

void test_jaln_session_associate_digest_channel_no_lock_fails_when_role_unset()
{
	replace_function(vortex_channel_set_automatic_mime, fake_vortex_channel_set_automatic_mime);
	replace_function(vortex_channel_set_serialize, fake_vortex_channel_set_serialize);
	replace_function(vortex_channel_set_closed_handler, fake_vortex_channel_set_closed_handler);
	replace_function(vortex_channel_set_close_handler, fake_vortex_channel_set_close_handler);

	VortexChannel *chan = (VortexChannel *)0xdeadbeef;
	int ch_num = 1;
	
	sess->role = JALN_ROLE_UNSET;
	sess->dgst_chan = NULL;
	sess->dgst_chan_num = 0;
	assert_equals(axl_false, jaln_session_associate_digest_channel_no_lock(sess, chan, ch_num));

	restore_function(vortex_channel_set_automatic_mime);
	restore_function(vortex_channel_set_serialize);
	restore_function(vortex_channel_set_closed_handler);
	restore_function(vortex_channel_set_close_handler);
}

void test_jaln_session_associate_digest_channel_no_lock_succeeds()
{
	replace_function(vortex_channel_set_automatic_mime, fake_vortex_channel_set_automatic_mime);
	replace_function(vortex_channel_set_serialize, fake_vortex_channel_set_serialize);
	replace_function(vortex_channel_set_closed_handler, fake_vortex_channel_set_closed_handler);
	replace_function(vortex_channel_set_close_handler, fake_vortex_channel_set_close_handler);

	VortexChannel *chan = (VortexChannel *)0xdeadbeef;
	int ch_num = 1;

	sess->role = JALN_ROLE_SUBSCRIBER;
	sess->dgst_chan = NULL;
	sess->dgst_chan_num = 0;
	assert_equals(axl_true, jaln_session_associate_digest_channel_no_lock(sess, chan, ch_num));

	replace_function(vortex_channel_set_received_handler, fake_vortex_channel_set_received_handler);

	sess->role = JALN_ROLE_PUBLISHER;
	sess->dgst_chan = NULL;
	sess->dgst_chan_num = 0;
	assert_equals(axl_true, jaln_session_associate_digest_channel_no_lock(sess, chan, ch_num));

	restore_function(vortex_channel_set_automatic_mime);
	restore_function(vortex_channel_set_serialize);
	restore_function(vortex_channel_set_closed_handler);
	restore_function(vortex_channel_set_close_handler);
	restore_function(vortex_channel_set_received_handler);
}

void test_session_is_ok_fails_for_bad_input()
{
	assert_not_equals(JAL_OK, jaln_session_is_ok(NULL));

	assert_not_equals(JAL_OK, jaln_session_is_ok(sess));
}

void test_session_is_ok_fails_when_vortex_connection_ok_fails()
{
	replace_function(vortex_connection_is_ok, fake_connection_is_ok_fails);
	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	assert_not_equals(JAL_OK, jaln_session_is_ok(sess));
}

#if 0
void test_session_is_ok_returns_ok_when_curl_ctx_is_set()
{
	sess->curl_ctx = (CURL*) 0xbadf00d;
	assert_equals(JAL_OK, jaln_session_is_ok(sess));
}
#endif
