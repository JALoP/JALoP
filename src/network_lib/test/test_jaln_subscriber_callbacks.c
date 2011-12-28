/**
 * @file This file contains tests for jaln_subscriber_callbacks.c functions.
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

#include <jalop/jaln_subscriber_callbacks.h>
#include <jalop/jaln_network.h>
#include "jaln_context.h"
#include "jaln_subscriber_callbacks_internal.h"

#include <test-dept.h>
#include <string.h>

int dummy_get_subscribe_request(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) char **serial_id,
		__attribute__((unused)) uint64_t *offset)
{
	return 0;
}

int dummy_on_record_info(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const struct jaln_record_info *record_info,
		__attribute__((unused)) const struct jaln_mime_header *headers,
		__attribute__((unused)) const uint8_t *system_metadata_buffer,
		__attribute__((unused)) const uint32_t system_metadata_size,
		__attribute__((unused)) const uint8_t *application_metadata_buffer,
		__attribute__((unused)) const uint32_t application_metadata_size,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int dummy_on_audit(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) const uint8_t *buffer,
		__attribute__((unused)) const uint32_t cnt,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int dummy_on_log(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) const uint8_t *buffer,
		__attribute__((unused)) const uint32_t cnt,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int dummy_on_journal(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) const uint8_t *buffer,
		__attribute__((unused)) const uint32_t cnt,
		__attribute__((unused)) const uint64_t offset,
		__attribute__((unused)) const int more,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int dummy_notify_digest(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) char *serial_id,
		__attribute__((unused)) const uint8_t *digest,
		__attribute__((unused)) const uint32_t len,
		__attribute__((unused)) const void *user_data)
{
	return 0;
}

int dummy_on_digest_response(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) const enum jaln_digest_status status,
		__attribute__((unused)) const void *user_data)
{
	return 0;
}

void dummy_message_complete(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) void *user_data)
{
}

int dummy_acquire_journal_feeder(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

void dummy_release_journal_feeder(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
}

static struct jaln_subscriber_callbacks *sub_cbs;
static jaln_context *ctx;

void setup()
{
	ctx = jaln_context_create();

	sub_cbs = jaln_subscriber_callbacks_create();
	sub_cbs->get_subscribe_request = dummy_get_subscribe_request;
	sub_cbs->on_record_info = dummy_on_record_info;
	sub_cbs->on_audit = dummy_on_audit;
	sub_cbs->on_log = dummy_on_log;
	sub_cbs->on_journal = dummy_on_journal;
	sub_cbs->notify_digest = dummy_notify_digest;
	sub_cbs->on_digest_response = dummy_on_digest_response;
	sub_cbs->message_complete = dummy_message_complete;
	sub_cbs->acquire_journal_feeder = dummy_acquire_journal_feeder;
	sub_cbs->release_journal_feeder = dummy_release_journal_feeder;
}

void teardown()
{
	jaln_subscriber_callbacks_destroy(&sub_cbs);

	jaln_context_destroy(&ctx);
}

void test_subscriber_callbacks_create()
{
	struct jaln_subscriber_callbacks empty_cb;
	memset(&empty_cb, 0, sizeof(empty_cb));
	struct jaln_subscriber_callbacks *cb = jaln_subscriber_callbacks_create();
	assert_not_equals((void*) NULL, cb);
	assert_equals(0, memcmp(&empty_cb, cb, sizeof(*cb)));
	jaln_subscriber_callbacks_destroy(&cb);
}

void test_subscriber_callbacks_destroy_does_not_crash()
{
	struct jaln_subscriber_callbacks *cb = NULL;
	jaln_subscriber_callbacks_destroy(NULL);
	jaln_subscriber_callbacks_destroy(&cb);
}

void test_subscriber_callbacks_is_valid_returns_true_for_valid_struct()
{
	int ret;
	ret = jaln_subscriber_callbacks_is_valid(sub_cbs);
	assert_equals(1, ret);
}

void test_subscriber_callbacks_is_valid_returns_false_when_missing_get_subscribe_request()
{
	int ret;
	sub_cbs->get_subscribe_request = NULL;
	ret = jaln_subscriber_callbacks_is_valid(sub_cbs);
	assert_equals(0, ret);
}
void test_subscriber_callbacks_is_valid_returns_false_when_missing_on_audit()
{
	int ret;
	sub_cbs->on_audit = NULL;
	ret = jaln_subscriber_callbacks_is_valid(sub_cbs);
	assert_equals(0, ret);
}

void test_subscriber_callbacks_is_valid_returns_false_when_missing_on_log()
{
	int ret;
	sub_cbs->on_log = NULL;
	ret = jaln_subscriber_callbacks_is_valid(sub_cbs);
	assert_equals(0, ret);
}

void test_subscriber_callbacks_is_valid_returns_false_when_missing_on_journal()
{
	int ret;
	sub_cbs->on_journal = NULL;
	ret = jaln_subscriber_callbacks_is_valid(sub_cbs);
	assert_equals(0, ret);
}

void test_subscriber_callbacks_is_valid_returns_false_when_missing_notify_digest()
{
	int ret;
	sub_cbs->notify_digest = NULL;
	ret = jaln_subscriber_callbacks_is_valid(sub_cbs);
	assert_equals(0, ret);
}

void test_subscriber_callbacks_is_valid_returns_false_when_missing_on_digest_response()
{
	int ret;
	sub_cbs->on_digest_response = NULL;
	ret = jaln_subscriber_callbacks_is_valid(sub_cbs);
	assert_equals(0, ret);
}

void test_subscriber_callbacks_is_valid_returns_false_when_missing_message_complete()
{
	int ret;
	sub_cbs->message_complete = NULL;
	ret = jaln_subscriber_callbacks_is_valid(sub_cbs);
	assert_equals(0, ret);
}

void test_subscriber_callbacks_is_valid_returns_false_when_missing_acquire_journal_feeder()
{
	int ret;
	sub_cbs->acquire_journal_feeder = NULL;
	ret = jaln_subscriber_callbacks_is_valid(sub_cbs);
	assert_equals(0, ret);
}

void test_subscriber_callbacks_is_valid_returns_false_when_missing_release_journal_feeder()
{
	int ret;
	sub_cbs->release_journal_feeder = NULL;
	ret = jaln_subscriber_callbacks_is_valid(sub_cbs);
	assert_equals(0, ret);
}

void test_subscriber_callbacks_is_valid_returns_false_when_struct_is_null()
{
	int ret;
	ret = jaln_subscriber_callbacks_is_valid(NULL);
	assert_equals(0, ret);
}

void test_register_subscriber_callbacks_succeeds()
{
	enum jal_status ret;
	ret = jaln_register_subscriber_callbacks(ctx, sub_cbs);
	assert_equals(JAL_OK, ret);
	assert_not_equals(ctx->sub_callbacks, sub_cbs);
	assert_equals(0, memcmp(ctx->sub_callbacks, sub_cbs, sizeof(*sub_cbs)));
}

void test_register_subscriber_callbacks_fails_with_bad_callbacks()
{
	enum jal_status ret;
	sub_cbs->release_journal_feeder = NULL;
	ret = jaln_register_subscriber_callbacks(ctx, sub_cbs);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*) NULL, ctx->sub_callbacks);
}

void test_register_subscriber_callbacks_fails_to_overwrite_existing_subscriber_callbacks()
{
	enum jal_status ret;
	ctx->sub_callbacks = (struct jaln_subscriber_callbacks*) 0xbadf00d;
	ret = jaln_register_subscriber_callbacks(ctx, sub_cbs);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*) 0xbadf00d, ctx->sub_callbacks);
	ctx->sub_callbacks = NULL;
}

void test_register_subscriber_callbacks_fails_with_null_ctx()
{
	enum jal_status ret;
	ret = jaln_register_subscriber_callbacks(NULL, sub_cbs);
	assert_equals(JAL_E_INVAL, ret);
}
