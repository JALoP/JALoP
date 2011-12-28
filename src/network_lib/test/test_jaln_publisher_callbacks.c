/**
 * @file This file contains tests for jaln_publisher_callbacks.c functions.
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
#include <jalop/jaln_publisher_callbacks.h>
#include <test-dept.h>
#include <string.h>

#include "jaln_context.h"
#include "jaln_publisher_callbacks_internal.h"

static jaln_context *ctx;
static struct jaln_publisher_callbacks *pub_cbs;

int my_on_journal_resume(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) struct jaln_record_info *record_info,
		__attribute__((unused)) uint64_t offset,
		__attribute__((unused)) uint8_t **system_metadata_buffer,
		__attribute__((unused)) uint8_t **application_metadata_buffer,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int my_on_subscribe(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int my_get_next_record_info_and_metadata(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *last_serial_id,
		__attribute__((unused)) struct jaln_record_info *record_info,
		__attribute__((unused)) uint8_t **system_metadata_buffer,
		__attribute__((unused)) uint8_t **application_metadata_buffer,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int my_release_metadata_buffers(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) uint8_t *system_metadata_buffer,
		__attribute__((unused)) uint8_t *application_metadata_buffer,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int my_acquire_log_data(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) uint8_t **buffer,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int my_release_log_data(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) uint8_t *buffer,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int my_acquire_audit_data(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) uint8_t **buffer,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

int my_release_audit_data(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) uint8_t *buffer,
		__attribute__((unused)) void *user_data)
{
	return 0;
}

enum jal_status my_acquire_journal_feeder(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
	return JAL_OK;
}

enum jal_status my_release_journal_feeder(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
	return JAL_OK;
}

enum jal_status my_on_record_complete(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) char *serial_id,
		__attribute__((unused)) void *user_data)
{
	return JAL_OK;
}

void my_sync(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	return;
}

void my_notify_digest(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *serial_id,
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
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) const uint8_t *local_digest,
		__attribute__((unused)) const uint32_t local_size,
		__attribute__((unused)) const uint8_t *peer_digest,
		__attribute__((unused)) const uint32_t peer_size,
		__attribute__((unused)) void *user_data)
{
	return;
}

void setup()
{
	ctx = jaln_context_create();
	pub_cbs = jaln_publisher_callbacks_create();

	pub_cbs->on_journal_resume = my_on_journal_resume;
	pub_cbs->on_subscribe = my_on_subscribe;
	pub_cbs->get_next_record_info_and_metadata = my_get_next_record_info_and_metadata;
	pub_cbs->release_metadata_buffers = my_release_metadata_buffers;
	pub_cbs->acquire_log_data = my_acquire_log_data;
	pub_cbs->release_log_data = my_release_log_data;
	pub_cbs->acquire_audit_data = my_acquire_audit_data;
	pub_cbs->release_audit_data = my_release_audit_data;
	pub_cbs->acquire_journal_feeder = my_acquire_journal_feeder;
	pub_cbs->release_journal_feeder = my_release_journal_feeder;
	pub_cbs->on_record_complete = my_on_record_complete;
	pub_cbs->sync = my_sync;
	pub_cbs->notify_digest = my_notify_digest;
	pub_cbs->peer_digest = my_peer_digest;
}

void teardown()
{
	jaln_context_destroy(&ctx);
	jaln_publisher_callbacks_destroy(&pub_cbs);
}

void test_publish_callbacks_create()
{
	struct jaln_publisher_callbacks empty_cb;
	memset(&empty_cb, 0, sizeof(empty_cb));
	struct jaln_publisher_callbacks *cb = jaln_publisher_callbacks_create();
	assert_not_equals((void*) NULL, cb);
	assert_equals(0, memcmp(&empty_cb, cb, sizeof(*cb)));
	jaln_publisher_callbacks_destroy(&cb);
}

void test_publish_callbacks_destroy_does_not_crash()
{
	struct jaln_publisher_callbacks *cb = NULL;
	jaln_publisher_callbacks_destroy(NULL);
	jaln_publisher_callbacks_destroy(&cb);
}

void test_register_pub_callbacks_works_with_valid_input()
{
	assert_equals(JAL_OK, jaln_register_publisher_callbacks(ctx, pub_cbs));
}

void test_register_pub_callbacks_fails_on_bad_input()
{
	ctx->pub_callbacks = (struct jaln_publisher_callbacks *)0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_register_publisher_callbacks(ctx, pub_cbs));
	ctx->pub_callbacks = NULL;

	assert_equals(JAL_E_INVAL, jaln_register_publisher_callbacks(NULL, pub_cbs));

	pub_cbs->on_journal_resume = NULL;
	assert_equals(JAL_E_INVAL, jaln_register_publisher_callbacks(ctx, NULL));
	pub_cbs->on_journal_resume = my_on_journal_resume;
}
void test_pub_callbacks_is_valid_returns_false_for_invalid_structure()
{
	assert_false(jaln_publisher_callbacks_is_valid(NULL));


	pub_cbs->on_journal_resume = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->on_journal_resume = my_on_journal_resume;

	pub_cbs->on_subscribe = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->on_subscribe = my_on_subscribe;

	pub_cbs->get_next_record_info_and_metadata = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->get_next_record_info_and_metadata = my_get_next_record_info_and_metadata;

	pub_cbs->release_metadata_buffers = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->release_metadata_buffers = my_release_metadata_buffers;

	pub_cbs->acquire_log_data = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->acquire_log_data = my_acquire_log_data;

	pub_cbs->release_log_data = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->release_log_data = my_release_log_data;

	pub_cbs->acquire_audit_data = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->acquire_audit_data = my_acquire_audit_data;

	pub_cbs->release_audit_data = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->release_audit_data = my_release_audit_data;

	pub_cbs->acquire_journal_feeder = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->acquire_journal_feeder = my_acquire_journal_feeder;

	pub_cbs->release_journal_feeder = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->release_journal_feeder = my_release_journal_feeder;

	pub_cbs->on_record_complete = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->on_record_complete = my_on_record_complete;

	pub_cbs->sync = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->sync = my_sync;

	pub_cbs->notify_digest = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->notify_digest = my_notify_digest;

	pub_cbs->peer_digest = NULL;
	assert_false(jaln_publisher_callbacks_is_valid(pub_cbs));
	pub_cbs->peer_digest = my_peer_digest;

}
