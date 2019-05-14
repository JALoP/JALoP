/**
 * @file test_jaln_pub_feeder.c This file contains tests for jaln_pub_feeder.c functions.
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

#include <ctype.h>
#include <inttypes.h>
#include <jalop/jal_status.h>
#include <limits.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <test-dept.h>
#include <vortex.h>

#include "jal_alloc.h"

#include "jaln_context.h"
#include "jaln_pub_feeder.h"
#include "jaln_message_helpers.h"
#include "jaln_session.h"

#define NONCE "nonce_1234"
#define HEADERS "some headers"
#define SYS_META "system meta"
#define APP_META "app meta"
#define PAYLOAD "payload text"

#define BUF_SIZE 256

#define VORTEX_SZ (strlen(SYS_META) + strlen(APP_META) + \
		strlen(PAYLOAD) + (3 * strlen("BREAK")))

#define EXPECTED_MSG SYS_META "BREAK" APP_META "BREAK" PAYLOAD "BREAK"
#define EXPECTED_MSG_MAX_OFFSET SYS_META "BREAK" APP_META "BREAKBREAK"

static axl_bool finalized_called;

static VortexPayloadFeeder *fake_vortex_payload_feeder_new (
		__attribute__((unused)) VortexPayloadFeederHandler handler,
		__attribute__((unused)) axlPointer user_data)
{
	return (VortexPayloadFeeder*) 0xbadf00d;
}

static void fake_vortex_payload_feeder_set_on_finished(
		__attribute__((unused)) VortexPayloadFeeder *feeder,
		__attribute__((unused)) VortexPayloadFeederFinishedHandler on_finished,
		__attribute__((unused)) axlPointer user_data)
{
	return;
}

struct curl_slist * fake_create_record_ans_rpy_headers(
		__attribute__((unused)) struct jaln_record_info *rec_info,
		__attribute__((unused)) jaln_session *sess)
{
	return NULL;
}

axl_bool fake_finalize_ans_rpy(
		__attribute__((unused)) VortexChannel *chan,
		__attribute__((unused)) int msg_no)
{
	finalized_called = axl_true;
	return axl_true;
}
axl_bool fake_send_ans_rpy_from_feeder(
		__attribute__((unused)) VortexChannel *chan,
		__attribute__((unused)) VortexPayloadFeeder *feeder,
		__attribute__((unused)) int msg_no)
{
	return axl_true;
}

enum jal_status fake_add_to_dgst_list(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) char *nonce,
		__attribute__((unused)) uint8_t *dgst_buf,
		__attribute__((unused)) uint64_t dgst_len)
{
	return JAL_OK;
}

enum jal_status my_on_journal_resume(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) struct jaln_record_info *record_info,
		__attribute__((unused)) uint64_t offset,
		__attribute__((unused)) uint8_t **system_metadata_buffer,
		__attribute__((unused)) uint8_t **application_metadata_buffer,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	return JAL_OK;
}

enum jal_status my_on_subscribe(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) enum jaln_publish_mode mode,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	return JAL_OK;
}

enum jal_status journal_get_bytes(const uint64_t offset,
			uint8_t * const buffer,
			uint64_t *size,
			__attribute__((unused)) void *feeder_data)
{
	if (offset > strlen(PAYLOAD)) {
		// shouldn't happen
		return JAL_E_INVAL;
	}
	if ((offset + *size) > strlen(PAYLOAD)) {
		*size = strlen(PAYLOAD) - offset;
	}
	memcpy(buffer, PAYLOAD + offset, *size);
	return JAL_OK;
}

enum jal_status my_on_record_complete(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) char *nonce,
		__attribute__((unused)) void *user_data)
{
	return JAL_OK;
}

void my_sync(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) enum jaln_publish_mode mode,
		__attribute__((unused)) const char *nonce,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	return;
}

void my_notify_digest(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *nonce,
		__attribute__((unused)) const uint8_t *digest,
		__attribute__((unused)) const uint32_t size,
		__attribute__((unused)) void *user_data)
{
	return;
}

void my_peer_digest(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *nonce,
		__attribute__((unused)) const uint8_t *local_digest,
		__attribute__((unused)) const uint32_t local_size,
		__attribute__((unused)) const uint8_t *peer_digest,
		__attribute__((unused)) const uint32_t peer_size,
		__attribute__((unused)) void *user_data)
{
	return;
}

static jaln_session *sess;

void setup()
{
	replace_function(jaln_session_add_to_dgst_list, fake_add_to_dgst_list);
	replace_function(vortex_channel_send_ans_rpy_from_feeder, fake_send_ans_rpy_from_feeder);
	replace_function(vortex_channel_finalize_ans_rpy, fake_finalize_ans_rpy);
	replace_function(jaln_create_record_ans_rpy_headers, fake_create_record_ans_rpy_headers);
	replace_function(vortex_payload_feeder_new, fake_vortex_payload_feeder_new);
	replace_function(vortex_payload_feeder_set_on_finished, fake_vortex_payload_feeder_set_on_finished);
	sess = jaln_session_create();
	sess->jaln_ctx = jaln_context_create();
	sess->ch_info->type = JALN_RTYPE_LOG;
	sess->dgst = sess->jaln_ctx->sha256_digest;
	sess->pub_data = jaln_pub_data_create();
	sess->pub_data->dgst_inst = sess->dgst->create();
	sess->dgst->init(sess->pub_data->dgst_inst);
	sess->role = JALN_ROLE_PUBLISHER;
	sess->pub_data->headers_sz = strlen(HEADERS);
	sess->pub_data->sys_meta_sz = strlen(SYS_META);
	sess->pub_data->app_meta_sz = strlen(APP_META);
	sess->pub_data->payload_sz = strlen(PAYLOAD);
	sess->pub_data->headers = (uint8_t *) jal_strdup(HEADERS);
	sess->pub_data->sys_meta = (uint8_t *) jal_strdup(SYS_META);
	sess->pub_data->app_meta = (uint8_t *) jal_strdup(APP_META);
	sess->pub_data->payload = (uint8_t *) jal_strdup(PAYLOAD);
	struct jaln_publisher_callbacks *pub_cbs = jaln_publisher_callbacks_create();

	pub_cbs->on_journal_resume = my_on_journal_resume;
	pub_cbs->on_subscribe = my_on_subscribe;
	pub_cbs->on_record_complete = my_on_record_complete;
	pub_cbs->sync = my_sync;
	pub_cbs->notify_digest = my_notify_digest;
	pub_cbs->peer_digest = my_peer_digest;

	sess->jaln_ctx->pub_callbacks = pub_cbs;

	finalized_called = axl_false;
}

void teardown()
{
	jaln_session_unref(sess);
}

void test_pub_feeder_fill_buffer()
{
	void *buffer = jal_malloc(BUF_SIZE);

	sess->pub_data->dgst = (uint8_t*) jal_calloc(1, sess->dgst->len);

	size_t ret = jaln_pub_feeder_fill_buffer(buffer, BUF_SIZE, 1, sess);

	assert_string_equals(EXPECTED_MSG, buffer);
	assert_equals(VORTEX_SZ, ret);
}

void test_pub_feeder_fill_buffer_offset_at_end_of_payload()
{

	void *buffer = jal_malloc(BUF_SIZE);

	sess->pub_data->dgst = (uint8_t*) jal_calloc(1, sess->dgst->len);
	sess->pub_data->payload_off = VORTEX_SZ - 5; 

	size_t ret = jaln_pub_feeder_fill_buffer(buffer, BUF_SIZE, 1, sess);

	assert_string_equals(EXPECTED_MSG_MAX_OFFSET, buffer);
	assert_equals(strlen(EXPECTED_MSG_MAX_OFFSET), ret);

	free(buffer);
}

void test_pub_feeder_is_finished_returns_true_if_errored()
{
	int fin = 0;
	sess->errored = axl_true;
	assert_true(jaln_pub_feeder_is_finished(sess, &fin));
	assert_true(fin);
}

void test_pub_feeder_is_finished_returns_true_after_payload_break_is_written()
{
	int fin = 0;
	sess->pub_data->finished_payload_break = axl_true;
	assert_true(jaln_pub_feeder_is_finished(sess, &fin));
	assert_true(fin);
}

void test_pub_feeder_is_finished_returns_false_before_payload_break_is_written()
{
	int fin = 1;
	sess->pub_data->finished_payload_break = axl_false;
	assert_false(jaln_pub_feeder_is_finished(sess, &fin));
	assert_false(fin);
}

void test_pub_feeder_get_size_returns_cached_size()
{
	int sz = 0;
	sess->pub_data->vortex_feeder_sz = 24;
	sess->pub_data->finished_payload_break = axl_false;
	assert_true(jaln_pub_feeder_get_size(sess, &sz));
	assert_equals(24, sz);
}

void test_pub_feeder_calculate_size_works_correctly()
{
	struct jaln_pub_data *pd = sess->pub_data;
	pd->sys_meta_sz = 10;
	pd->app_meta_sz = 20;
	pd->payload_sz = 30;
	pd->headers_sz = 40;
	pd->vortex_feeder_sz = -1;
	jaln_pub_feeder_calculate_size_for_vortex(sess);
	// The size is the length of all the data sections, headers, and the
	// intervening "BREAK" strings
	assert_equals(10 + 20 + 30 + 40 + (strlen("BREAK") * 3), pd->vortex_feeder_sz);
}

void test_pub_feeder_calculate_size_returns_int_max_on_overflow()
{
	struct jaln_pub_data *pd = sess->pub_data;
	pd->sys_meta_sz = INT_MAX;
	pd->app_meta_sz = 1;
	pd->payload_sz = 1;
	pd->headers_sz = 1;
	pd->vortex_feeder_sz = -1;
	jaln_pub_feeder_calculate_size_for_vortex(sess);
	// The size is the length of all the data sections, headers, and the
	// intervening "BREAK" strings
	assert_equals(INT_MAX, pd->vortex_feeder_sz);
}

void test_safe_add_works()
{
	int cnt = 0;
	assert_true(jaln_pub_feeder_safe_add_size(&cnt, 1));
	assert_equals(1, cnt);

	assert_true(jaln_pub_feeder_safe_add_size(&cnt, 200));
	assert_equals(201, cnt);
}

void test_safe_add_returns_false_on_overflow()
{
	int cnt = 1;
	assert_false(jaln_pub_feeder_safe_add_size(&cnt, INT_MAX));
	assert_equals(INT_MAX, cnt);

}

void test_reset_state_clears_all_variables()
{
	sess->pub_data->vortex_feeder_sz = -1;
	jaln_pub_feeder_reset_state(sess);
	assert_equals(0, sess->pub_data->vortex_feeder_sz);
	assert_equals(0, sess->pub_data->headers_off);
	assert_equals(0, sess->pub_data->sys_meta_off);
	assert_equals(0, sess->pub_data->payload_off);
	assert_equals(0, sess->pub_data->break_off);
	assert_false(sess->pub_data->finished_headers);
	assert_false(sess->pub_data->finished_sys_meta);
	assert_false(sess->pub_data->finished_sys_meta_break);
	assert_false(sess->pub_data->finished_app_meta);
	assert_false(sess->pub_data->finished_app_meta_break);
	assert_false(sess->pub_data->finished_payload);
	assert_false(sess->pub_data->finished_payload_break);
	assert_not_equals((void*)NULL, sess->pub_data->dgst_inst);
	assert_not_equals((void*)NULL, sess->pub_data->dgst);
}

void test_reset_state_does_not_leak()
{
	// run under valgrind
	jaln_pub_feeder_reset_state(sess);
	jaln_pub_feeder_reset_state(sess);
}
