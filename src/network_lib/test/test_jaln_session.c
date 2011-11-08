/**
 * @file This file contains tests for jaln_session.c functions.
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

#include <jalop/jaln_network.h>
#include <test-dept.h>
#include <string.h>

#include "jaln_context.h"
#include "jaln_session.h"

static struct jaln_session *sess = NULL;
static struct jaln_pub_data *pub_data = NULL;
static struct jaln_sub_data *sub_data = NULL;
static struct jaln_payload_feeder zeroed_feeder;
void setup()
{
	sess = jaln_session_create();
	pub_data = jaln_pub_data_create();
	sub_data = jaln_sub_data_create();
	memset(&zeroed_feeder, 0, sizeof(zeroed_feeder));
}

void teardown()
{
	jaln_session_destroy(&sess);
	jaln_pub_data_destroy(&pub_data);
	jaln_sub_data_destroy(&sub_data);
}

void test_session_destroy_unrefs_jaln_ctx()
{
	jaln_context *ctx = jaln_context_create();
	jaln_ctx_ref(ctx);
	sess->jaln_ctx = ctx;
	assert_equals(2, ctx->ref_cnt);
	jaln_session_destroy(&sess);
	assert_equals(1, ctx->ref_cnt);
}

void test_session_create()
{
	assert_not_equals((void*) NULL, sess);
	assert_equals(1, sess->ref_cnt);
	assert_equals((void*) NULL, sess->jaln_ctx);
	assert_equals((void*) NULL, sess->dgst);
	assert_equals((void*) NULL, sess->rec_chan);
	assert_equals((void*) NULL, sess->dgst_chan);
	assert_equals(-1, sess->rec_chan_num);
	assert_equals(-1, sess->dgst_chan_num);
	assert_not_equals((void*) NULL, sess->ch_info);
	assert_false(sess->closing);
	assert_false(sess->errored);
	assert_not_equals((void*) NULL, sess->dgst_list);
	assert_equals(JALN_ROLE_UNSET, sess->role);
	assert_equals(100, sess->dgst_list_max);
	assert_equals(30 * 60 * 1000000, sess->dgst_timeout);
	assert_equals((void*) NULL, sess->sub_data);
	assert_equals((void*) NULL, sess->pub_data);
}

void test_session_destroy_does_not_crash()
{
	struct jaln_session *sess = NULL;
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

void test_pub_data_create()
{
	assert_not_equals((void*) NULL, pub_data);
	assert_equals(0, memcmp(&pub_data->journal_feeder, &zeroed_feeder, sizeof(zeroed_feeder)));
	assert_equals(0, pub_data->vortex_feeder_sz);
	assert_equals(-1, pub_data->msg_no);
	assert_equals((void*)NULL, pub_data->serial_id);
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
