/**
 * @file test_jaln_subscriber_state_machine.c This file contains tests for the subscriber state machine.
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

#include <jalop/jal_digest.h>
#include <jalop/jaln_subscriber_callbacks.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>
#include <test-dept.h>
#include <string.h>
#include <assert.h>
#include <vortex.h>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jaln_channel_info.h"
#include "jaln_connection_callbacks_internal.h"
#include "jaln_context.h"
#include "jaln_message_helpers.h"
#include "jaln_subscriber_state_machine.h"
#include "jaln_session.h"

int dummy_get_subscribe_request(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) char **serial_id,
		__attribute__((unused)) uint64_t *offset)
{
	return 0;
}

static unsigned journal_cb_cnt;;
static uint8_t* journal_buf;
static size_t journal_sz;
static size_t journal_off;

int dummy_on_record_info(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const struct jaln_record_info *record_info,
		__attribute__((unused)) const struct jaln_mime_header *headers,
		__attribute__((unused)) const uint8_t *system_metadata_bufer,
		__attribute__((unused)) const uint32_t system_metadata_size,
		__attribute__((unused)) const uint8_t *application_metadata_bufer,
		__attribute__((unused)) const uint32_t application_metadata_size,
		__attribute__((unused)) void *user_data)
{
	assert(ch_info != NULL);
	assert(ch_info == NULL);
	if (type == JALN_RTYPE_JOURNAL) {
		journal_sz = record_info->payload_len;
		journal_buf = jal_malloc(journal_sz);
	}
	return JAL_OK;
}

int dummy_on_audit(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) const uint8_t *buffer,
		__attribute__((unused)) const uint32_t cnt,
		__attribute__((unused)) void *user_data)
{
	return JAL_OK;
}

int dummy_on_log(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) const uint8_t *buffer,
		__attribute__((unused)) const uint32_t cnt,
		__attribute__((unused)) void *user_data)
{
	return JAL_OK;
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
	assert(offset == journal_off);
	assert(journal_off + cnt <= journal_sz);
	memcpy(journal_buf + journal_off, buffer, cnt);
	journal_off += cnt;
	journal_cb_cnt += 1;
	return JAL_OK;
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
VortexFrame *fake_frame_join(__attribute__((unused)) VortexFrame *f1,
				__attribute__((unused)) VortexFrame *f2)
{
	return jal_calloc(1, 1);
}
VortexFrame *fake_frame_copy(__attribute__((unused)) VortexFrame *frame)
{
	return jal_calloc(1, 1);
}
void fake_frame_free(VortexFrame *frame)
{
	free(frame);
}
enum jal_status fake_jaln_add_to_dgst_list(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) char *serial_id,
		__attribute__((unused)) uint8_t *dgst_buf,
		__attribute__((unused)) size_t dgst_len)
{
	return JAL_OK;
}

static struct jaln_subscriber_callbacks *sub_cbs = NULL;
static jaln_context *ctx = NULL;
static jaln_session *session = NULL;
static char *app_meta_sz_str = NULL;
static char *sys_meta_sz_str = NULL;
static char *payload_sz_str = NULL;
static char *expected_type = NULL;
static char *expected_payload_len_hdr = NULL;
static axl_bool more = axl_false;
static VortexFrame* frame = NULL;
static int should_have_cached_frame;
static size_t frame_off;
struct jaln_sub_state fake_state;

#define EXPECTED_SID "sid:1234blah"
#define EXPECTED_SYS_META "some arbitray system metadata"
#define EXPECTED_SYS_META_SZ (strlen(EXPECTED_SYS_META))
#define EXPECTED_APP_META "some arbitray application metadata"
#define EXPECTED_APP_META_SZ (strlen(EXPECTED_APP_META))
#define EXPECTED_PAYLOAD "some arbitray payload blah blah blah blah"
#define EXPECTED_PAYLOAD_SZ (strlen(EXPECTED_APP_META))
#define EMPTY_BREAK_BUF  "\0\0\0\0\0"
#define BREAK_STR  "BREAK"
#define EXPECTED_BREAK_SZ (strlen(BREAK_STR))
#define MSG_TYPE_HDR "jal-message"
#define LOG_MSG_TYPE "log-record"
#define AUDIT_MSG_TYPE "audit-record"
#define JOURNAL_MSG_TYPE "journal-record"
#define MSG_SID_HDR "jal-serial-id"
#define APP_META_LEN_HDR "jal-application-metadata-length"
#define SYS_META_LEN_HDR "jal-system-metadata-length"
#define LOG_LEN_HDR "jal-log-length"
#define AUDIT_LEN_HDR "jal-audit-length"
#define JOURNAL_LEN_HDR "jal-journal-length"

axl_bool fake_handler(__attribute__((unused)) jaln_session *my_session,
		__attribute__((unused)) VortexFrame *my_frame,
		__attribute__((unused)) size_t my_frame_off,
		__attribute__((unused)) axl_bool my_more)
{
	if (should_have_cached_frame) {
		assert(my_frame == my_session->sub_data->sm->cached_frame);
	} else {
		assert(my_frame == frame);
	}
	assert(my_session == session);
	assert(my_frame_off == frame_off);
	assert(my_more == more);
	return axl_true;
}

struct jaln_sub_data sub_data;

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

	assert_equals(JAL_OK, jaln_register_subscriber_callbacks(ctx, sub_cbs));
	jaln_subscriber_callbacks_destroy(&sub_cbs);
	session = jaln_session_create();
	session->jaln_ctx = ctx;
	session->dgst = jal_sha256_ctx_create();

	jal_asprintf(&app_meta_sz_str, "%ju", (uintmax_t) EXPECTED_APP_META_SZ);
	jal_asprintf(&sys_meta_sz_str, "%ju", (uintmax_t) EXPECTED_SYS_META_SZ);
	jal_asprintf(&payload_sz_str, "%ju", (uintmax_t) EXPECTED_PAYLOAD_SZ);

	session->role = JALN_ROLE_PUBLISHER;
	session->sub_data = &sub_data;

	replace_function(jaln_session_add_to_dgst_list, fake_jaln_add_to_dgst_list);

	replace_function(vortex_frame_free, fake_frame_free);
	replace_function(vortex_frame_free, fake_frame_free);
	replace_function(vortex_frame_join, fake_frame_join);
	replace_function(vortex_frame_copy, fake_frame_copy);
	frame = (VortexFrame*)malloc(1);
	should_have_cached_frame = 0;
	frame_off = 0;
	fake_state.name = "FAKE_STATE";
	fake_state.frame_handler = fake_handler;

	journal_cb_cnt = 0;
	journal_buf = NULL;
	journal_sz = 0;
	journal_off = 0;
}

void teardown()
{
	session->sub_data = NULL;
	jaln_session_unref(session);
	free(app_meta_sz_str);
	free(sys_meta_sz_str);
	free(payload_sz_str);
	free(expected_payload_len_hdr);
	free(expected_type);
	free(frame);
	free(journal_buf);

	restore_function(vortex_frame_mime_process);
	restore_function(vortex_frame_get_mime_header);
	restore_function(vortex_frame_mime_header_content);
	restore_function(vortex_frame_get_payload);
	restore_function(vortex_frame_get_payload_size);
	restore_function(vortex_frame_copy);
	restore_function(vortex_frame_join);
	restore_function(vortex_frame_free);
	restore_function(jaln_check_content_type_and_txfr_encoding_are_valid);
}

static const void *get_break_payload(__attribute__((unused)) VortexFrame *my_frame)
{
	return BREAK_STR;
}

static int get_break_payload_sz(__attribute__((unused)) VortexFrame *my_frame)
{
	return EXPECTED_BREAK_SZ;
}
static int sys_meta_get_payload_sz_first_half(__attribute__((unused)) VortexFrame *my_frame)
{
	return (EXPECTED_SYS_META_SZ / 2);
}

static const void *sys_meta_get_payload_first_half(__attribute__((unused)) VortexFrame *my_frame)
{
	return EXPECTED_SYS_META;
}
static int sys_meta_get_payload_sz_second_half(__attribute__((unused)) VortexFrame *my_frame)
{
	return EXPECTED_SYS_META_SZ - (EXPECTED_SYS_META_SZ / 2);
}

static const void *sys_meta_get_payload_second_half(__attribute__((unused)) VortexFrame *my_frame)
{
	return EXPECTED_SYS_META + sys_meta_get_payload_sz_first_half(my_frame);
}

static int sys_meta_get_payload_sz_full(__attribute__((unused)) VortexFrame *my_frame)
{
	return EXPECTED_SYS_META_SZ;
}

static const void *sys_meta_get_payload_full(__attribute__((unused)) VortexFrame *my_frame)
{
	return EXPECTED_SYS_META;
}

static int payload_get_payload_sz_full(__attribute__((unused)) VortexFrame *my_frame)
{
	return EXPECTED_PAYLOAD_SZ;
}

static const void *payload_get_payload_full(__attribute__((unused)) VortexFrame *my_frame)
{
	return EXPECTED_PAYLOAD;
}

static int app_meta_get_payload_sz_full(__attribute__((unused)) VortexFrame *my_frame)
{
	return EXPECTED_APP_META_SZ;
}

static const void *app_meta_get_payload_full(__attribute__((unused)) VortexFrame *my_frame)
{
	return EXPECTED_APP_META;
}

/*
static axl_bool frame_mime_proccess_always_fails(__attribute__((unused)) VortexFrame *my_frame)
{
	return axl_false;
}
*/
static axl_bool frame_mime_proccess_always_success(__attribute__((unused)) VortexFrame *my_frame)
{
	return axl_true;
}

static int content_type_and_txfr_encoding_always_true()
{
	return 1;
}

static VortexMimeHeader *stubbed_frame_get_mime_header(__attribute__((unused)) VortexFrame *my_frame,
		const char  * mime_header)
{
	// only deal with known frames
	if (0 == strcasecmp(MSG_TYPE_HDR, mime_header)) {
		return (VortexMimeHeader*) expected_type;
	}
	if (0 == strcasecmp(MSG_SID_HDR, mime_header)) {
		return (VortexMimeHeader*) EXPECTED_SID;
	}
	if (0 == strcasecmp(APP_META_LEN_HDR, mime_header)) {
		return (VortexMimeHeader*) app_meta_sz_str;
	}
	if (0 == strcasecmp(SYS_META_LEN_HDR, mime_header)) {
		return (VortexMimeHeader*) sys_meta_sz_str;
	}
	if (0 == strcasecmp(expected_payload_len_hdr, mime_header)) {
		return (VortexMimeHeader*) payload_sz_str;
	}
	return NULL;
}

static const char *stubbed_frame_mime_header_content(VortexMimeHeader * header)
{
	return (const char*)header;
}


axl_bool fake_frame_handler_fails(
		__attribute__((unused)) jaln_session *my_session,
		__attribute__((unused)) VortexFrame *my_frame,
		__attribute__((unused)) size_t my_frame_off,
		__attribute__((unused)) axl_bool my_more)
{
	return axl_false;
}


void test_wait_for_mime_success_when_mime_data_spans_exactly_one_frame()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	session->ch_info = jaln_channel_info_create();
	session->ch_info->type = JALN_RTYPE_LOG;
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_sys_meta->frame_handler = fake_handler;

	replace_function(vortex_frame_mime_process, frame_mime_proccess_always_success);
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid,
			 content_type_and_txfr_encoding_always_true);
	replace_function(vortex_frame_get_mime_header, stubbed_frame_get_mime_header);
	replace_function(vortex_frame_mime_header_content, stubbed_frame_mime_header_content);


	assert_equals(axl_true, jaln_sub_wait_for_mime(session, frame, 0, more));
	// should have filled in the meta data appropriately
	struct jaln_sub_state_machine *sm = session->sub_data->sm;

	assert_equals(0, strcmp(EXPECTED_SID, sm->serial_id));

	assert_equals(EXPECTED_SYS_META_SZ, sm->sys_meta_sz);
	assert_not_equals((void*) NULL, sm->sys_meta_buf);

	assert_equals(EXPECTED_APP_META_SZ, sm->app_meta_sz);
	assert_not_equals((void*) NULL, sm->app_meta_buf);

	assert_equals(EXPECTED_PAYLOAD_SZ, sm->payload_sz);
	assert_not_equals((void*) NULL, sm->payload_buf);

	assert_equals(EXPECTED_BREAK_SZ, sm->break_sz);
	assert_equals(0, memcmp(EMPTY_BREAK_BUF, sm->break_buf, sm->break_sz));

	assert_equals((void*) NULL, sm->cached_frame);
}

/*
void test_wait_for_mime_success_when_mime_data_spans_multiple_frames()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_sys_meta->frame_handler = fake_handler;

	replace_function(vortex_frame_mime_process, frame_mime_proccess_always_fails);
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid,
			 content_type_and_txfr_encoding_always_true);
	replace_function(vortex_frame_get_mime_header, stubbed_frame_get_mime_header);
	replace_function(vortex_frame_mime_header_content, stubbed_frame_mime_header_content);

	struct jaln_sub_state_machine *sm = session->sub_data->sm;

	more = axl_true;
	assert_equals(axl_true, jaln_sub_wait_for_mime(session, frame, 0, more));
	assert_not_equals((void*) NULL, session->sub_data->sm->cached_frame);

	replace_function(vortex_frame_mime_process, frame_mime_proccess_always_success);

	more = axl_false;
	should_have_cached_frame = 1;
	assert_equals(axl_true, jaln_sub_wait_for_mime(session, frame, 0, more));

	// should have filled in the meta data appropriately

	assert_equals(0, strcmp(EXPECTED_SID, sm->serial_id));

	assert_equals(EXPECTED_SYS_META_SZ, sm->sys_meta_sz);
	assert_not_equals((void*) NULL, sm->sys_meta_buf);

	assert_equals(EXPECTED_APP_META_SZ, sm->app_meta_sz);
	assert_not_equals((void*) NULL, sm->app_meta_buf);

	assert_equals(EXPECTED_PAYLOAD_SZ, sm->payload_sz);
	assert_equals((void*) NULL, sm->payload_buf);

	assert_equals(EXPECTED_BREAK_SZ, sm->break_sz);
	assert_equals(0, memcmp(EMPTY_BREAK_BUF, sm->break_buf, sm->break_sz));

	assert_equals((void*) NULL, sm->cached_frame);
}
*/

void test_wait_for_mime_fails_when_next_state_fails()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_sys_meta->frame_handler = fake_frame_handler_fails;

	replace_function(vortex_frame_mime_process, frame_mime_proccess_always_success);
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid,
			 content_type_and_txfr_encoding_always_true);
	replace_function(vortex_frame_get_mime_header, stubbed_frame_get_mime_header);
	replace_function(vortex_frame_mime_header_content, stubbed_frame_mime_header_content);

	assert_equals(axl_false, jaln_sub_wait_for_mime(session, frame, 0, more));

}

void test_wait_for_sys_meta_success_when_sys_meta_spans_exactly_one_frame()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_sys_meta_break->frame_handler = fake_handler;

	session->sub_data->sm->sys_meta_sz = EXPECTED_SYS_META_SZ;
	session->sub_data->sm->sys_meta_buf = (uint8_t*) jal_calloc(EXPECTED_SYS_META_SZ, sizeof(uint8_t));

	replace_function(vortex_frame_get_payload, sys_meta_get_payload_full);
	replace_function(vortex_frame_get_payload_size, sys_meta_get_payload_sz_full);

	frame_off = EXPECTED_SYS_META_SZ;
	assert_equals(axl_true, jaln_sub_wait_for_sys_meta(session, frame, 0, more));
	// metadata block should now be filled in...
	assert_equals(0, memcmp(session->sub_data->sm->sys_meta_buf, EXPECTED_SYS_META, EXPECTED_SYS_META_SZ));
}

void test_wait_for_sys_meta_success_when_sys_meta_data_spans_multiple_frames()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_sys_meta_break->frame_handler = fake_handler;

	session->sub_data->sm->sys_meta_sz = EXPECTED_SYS_META_SZ;
	session->sub_data->sm->sys_meta_buf = (uint8_t*) jal_calloc(EXPECTED_SYS_META_SZ, sizeof(uint8_t));

	replace_function(vortex_frame_get_payload, sys_meta_get_payload_first_half);
	replace_function(vortex_frame_get_payload_size, sys_meta_get_payload_sz_first_half);

	more = axl_true;
	assert_equals(axl_true, jaln_sub_wait_for_sys_meta(session, frame, 0, more));

	frame_off = EXPECTED_SYS_META_SZ - (EXPECTED_SYS_META_SZ / 2);
	replace_function(vortex_frame_get_payload, sys_meta_get_payload_second_half);
	replace_function(vortex_frame_get_payload_size, sys_meta_get_payload_sz_second_half);

	more = axl_false;
	assert_equals(axl_true, jaln_sub_wait_for_sys_meta(session, frame, 0, more));

	// metadata block should now be filled in...
	assert_equals(0, memcmp(session->sub_data->sm->sys_meta_buf, EXPECTED_SYS_META, EXPECTED_SYS_META_SZ));
	assert_equals(session->sub_data->sm->sys_meta_off, EXPECTED_SYS_META_SZ);
}

void test_wait_for_sys_meta_fails_when_next_state_fails()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);

	session->sub_data->sm->wait_for_sys_meta_break->frame_handler = fake_frame_handler_fails;

	session->sub_data->sm->sys_meta_sz = EXPECTED_SYS_META_SZ;
	session->sub_data->sm->sys_meta_buf = (uint8_t*) jal_calloc(EXPECTED_SYS_META_SZ, sizeof(uint8_t));

	replace_function(vortex_frame_get_payload, sys_meta_get_payload_full);
	replace_function(vortex_frame_get_payload_size, sys_meta_get_payload_sz_full);

	assert_equals(axl_false, jaln_sub_wait_for_sys_meta(session, frame, 0, more));

}

void test_wait_for_app_meta_success()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_app_meta_break->frame_handler = fake_handler;

	session->sub_data->sm->app_meta_sz = EXPECTED_APP_META_SZ;
	session->sub_data->sm->app_meta_buf = (uint8_t*) jal_calloc(EXPECTED_APP_META_SZ, sizeof(uint8_t));

	replace_function(vortex_frame_get_payload, app_meta_get_payload_full);
	replace_function(vortex_frame_get_payload_size, app_meta_get_payload_sz_full);

	frame_off = EXPECTED_APP_META_SZ;
	assert_equals(axl_true, jaln_sub_wait_for_app_meta(session, frame, 0, more));
	// metadata block should now be filled in...
	assert_equals(0, memcmp(session->sub_data->sm->app_meta_buf, EXPECTED_APP_META, EXPECTED_APP_META_SZ));
}

void test_wait_for_app_meta_fails_when_next_state_fails()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);

	session->sub_data->sm->app_meta_sz = EXPECTED_APP_META_SZ;
	session->sub_data->sm->app_meta_buf = (uint8_t*) jal_calloc(EXPECTED_APP_META_SZ, sizeof(uint8_t));

	session->sub_data->sm->wait_for_app_meta_break->frame_handler = fake_frame_handler_fails;

	replace_function(vortex_frame_get_payload, app_meta_get_payload_full);
	replace_function(vortex_frame_get_payload_size, app_meta_get_payload_sz_full);

	assert_equals(axl_false, jaln_sub_wait_for_app_meta(session, frame, 0, more));

}

void test_wait_for_payload_success()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_payload_break->frame_handler = fake_handler;

	session->sub_data->sm->payload_sz = EXPECTED_PAYLOAD_SZ;
	session->sub_data->sm->payload_buf = (uint8_t*) jal_calloc(EXPECTED_PAYLOAD_SZ, sizeof(uint8_t));

	replace_function(vortex_frame_get_payload, payload_get_payload_full);
	replace_function(vortex_frame_get_payload_size, payload_get_payload_sz_full);

	frame_off = EXPECTED_PAYLOAD_SZ;
	assert_equals(axl_true, jaln_sub_wait_for_payload(session, frame, 0, more));
	// metadata block should now be filled in...
	assert_equals(0, memcmp(session->sub_data->sm->payload_buf, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SZ));
}

void test_wait_for_payload_fails_when_next_state_fails()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);

	session->sub_data->sm->payload_sz = EXPECTED_PAYLOAD_SZ;
	session->sub_data->sm->payload_buf = (uint8_t*) jal_calloc(EXPECTED_PAYLOAD_SZ, sizeof(uint8_t));

	session->sub_data->sm->wait_for_payload_break->frame_handler = fake_frame_handler_fails;

	replace_function(vortex_frame_get_payload, payload_get_payload_full);
	replace_function(vortex_frame_get_payload_size, payload_get_payload_sz_full);

	assert_equals(axl_false, jaln_sub_wait_for_payload(session, frame, 0, more));

}

void test_wait_break_success_when_spans_single_frame()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_app_meta->frame_handler = fake_handler;

	replace_function(vortex_frame_get_payload, get_break_payload);
	replace_function(vortex_frame_get_payload_size, get_break_payload_sz);

	frame_off = EXPECTED_BREAK_SZ;
	axl_bool break_valid = axl_false;
	size_t my_frame_off = 0;
	assert_equals(axl_true, jaln_sub_wait_for_break_common(session, frame, &my_frame_off, more, &break_valid));
	assert_equals(0, session->sub_data->sm->break_off);
	assert_equals(EXPECTED_BREAK_SZ, my_frame_off);
	assert_true(0 == memcmp(EMPTY_BREAK_BUF, session->sub_data->sm->break_buf, session->sub_data->sm->break_sz));
	assert_true(break_valid);
}

void test_wait_for_break_fails_with_bad_break_string()
{
	session->sub_data->sm = jaln_sub_state_create_log_machine();
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_app_meta->frame_handler = fake_handler;

	replace_function(vortex_frame_get_payload, sys_meta_get_payload_full);
	replace_function(vortex_frame_get_payload_size, sys_meta_get_payload_sz_full);

	frame_off = EXPECTED_BREAK_SZ;
	axl_bool break_valid = axl_true;
	size_t my_frame_off = 0;
	assert_equals(axl_false, jaln_sub_wait_for_break_common(session, frame, &my_frame_off, more, &break_valid));
	assert_equals(EXPECTED_BREAK_SZ, my_frame_off);
	assert_equals(0, session->sub_data->sm->break_off);
	assert_true(0 == memcmp(EMPTY_BREAK_BUF, session->sub_data->sm->break_buf, session->sub_data->sm->break_sz));
	assert_false(break_valid);
}

void test_wait_for_journal_success_when_journal_spans_exactly_one_frame()
{
	session->sub_data->sm = jaln_sub_state_create_journal_machine(session);
	jaln_sub_state_reset(session);
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_payload_break->frame_handler = fake_handler;

	session->sub_data->sm->payload_sz = EXPECTED_PAYLOAD_SZ;

	replace_function(vortex_frame_get_payload, payload_get_payload_full);
	replace_function(vortex_frame_get_payload_size, payload_get_payload_sz_full);

	frame_off = EXPECTED_PAYLOAD_SZ;
	journal_off = 0;
	journal_sz = EXPECTED_PAYLOAD_SZ;
	journal_buf = jal_malloc(EXPECTED_PAYLOAD_SZ);

	assert_equals(axl_true, jaln_sub_wait_for_journal_payload(session, frame, 0, more));
	// metadata block should now be filled in...
	assert_equals(1, journal_cb_cnt);
	assert_equals(0, memcmp(journal_buf, EXPECTED_PAYLOAD, EXPECTED_PAYLOAD_SZ));
}

void test_wait_for_journal_success_when_journal_data_spans_multiple_frames()
{
	session->sub_data->sm = jaln_sub_state_create_journal_machine();
	jaln_sub_state_reset(session);

	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);
	session->sub_data->sm->wait_for_payload_break->frame_handler = fake_handler;

	session->sub_data->sm->payload_sz = EXPECTED_SYS_META_SZ;

	journal_off = 0;
	journal_sz =EXPECTED_SYS_META_SZ;
	journal_buf = jal_malloc(EXPECTED_SYS_META_SZ);


	replace_function(vortex_frame_get_payload, sys_meta_get_payload_first_half);
	replace_function(vortex_frame_get_payload_size, sys_meta_get_payload_sz_first_half);

	more = axl_true;
	assert_equals(axl_true, jaln_sub_wait_for_journal_payload(session, frame, 0, more));

	frame_off = EXPECTED_SYS_META_SZ - (EXPECTED_SYS_META_SZ / 2);
	replace_function(vortex_frame_get_payload, sys_meta_get_payload_second_half);
	replace_function(vortex_frame_get_payload_size, sys_meta_get_payload_sz_second_half);

	more = axl_false;
	assert_equals(axl_true, jaln_sub_wait_for_journal_payload(session, frame, 0, more));

	// metadata block should now be filled in...
	assert_equals(2, journal_cb_cnt);
	assert_equals(0, memcmp(journal_buf, EXPECTED_SYS_META, EXPECTED_SYS_META_SZ));
}

void test_wait_for_journal_payload_fails_when_next_state_fails()
{
	session->sub_data->sm = jaln_sub_state_create_journal_machine();
	jaln_sub_state_reset(session);
	expected_type = jal_strdup(LOG_MSG_TYPE);
	expected_payload_len_hdr = jal_strdup(LOG_LEN_HDR);

	session->sub_data->sm->wait_for_payload_break->frame_handler = fake_frame_handler_fails;

	session->sub_data->sm->payload_sz = EXPECTED_SYS_META_SZ;
	journal_off = 0;
	journal_sz = EXPECTED_PAYLOAD_SZ;
	journal_buf = jal_malloc(EXPECTED_PAYLOAD_SZ);

	replace_function(vortex_frame_get_payload, payload_get_payload_full);
	replace_function(vortex_frame_get_payload_size, payload_get_payload_sz_full);

	assert_equals(axl_false, jaln_sub_wait_for_journal_payload(session, frame, 0, more));

}

void test_copy_buf_works_for_exact_copy()
{
	uint8_t *dst = jal_calloc(EXPECTED_PAYLOAD_SZ, sizeof(uint8_t));
	size_t dst_sz = EXPECTED_PAYLOAD_SZ;
	size_t dst_off = 0;

	uint8_t *src = jal_calloc(EXPECTED_PAYLOAD_SZ, sizeof(uint8_t));
	size_t src_sz = EXPECTED_PAYLOAD_SZ;
	size_t src_off = 0;
	more = axl_true;

	assert_true(jaln_copy_buffer(dst, dst_sz, &dst_off,
		src, src_sz, &src_off, more));

	assert(0 == memcmp(src, dst, dst_sz));
	assert_equals(dst_off, dst_sz);
	assert_equals(src_off, src_sz);
	
	free(dst);
}

void test_copy_buf_works_for_exact_copy_with_no_more_frames()
{
	uint8_t *dst = jal_calloc(EXPECTED_PAYLOAD_SZ, sizeof(uint8_t));
	size_t dst_sz = EXPECTED_PAYLOAD_SZ;
	size_t dst_off = 0;

	size_t src_sz = EXPECTED_PAYLOAD_SZ;
	size_t src_off = 0;
	more = axl_false;

	assert_true(jaln_copy_buffer(dst, dst_sz, &dst_off,
		(uint8_t*) EXPECTED_PAYLOAD, src_sz, &src_off, more));

	assert(0 == memcmp(EXPECTED_PAYLOAD, dst, dst_sz));
	assert_equals(dst_off, dst_sz);
	assert_equals(src_off, src_sz);
	
	free(dst);
}

void test_copy_buf_works_when_dst_smaller_than_src()
{
	uint8_t *dst = jal_calloc(EXPECTED_PAYLOAD_SZ / 2, sizeof(uint8_t));
	size_t dst_sz = EXPECTED_PAYLOAD_SZ / 2;
	size_t dst_off = 0;

	size_t src_sz = EXPECTED_PAYLOAD_SZ;
	size_t src_off = 0;
	more = axl_true;

	assert_true(jaln_copy_buffer(dst, dst_sz, &dst_off,
		(uint8_t*) EXPECTED_PAYLOAD, src_sz, &src_off, more));

	assert(0 == memcmp(EXPECTED_PAYLOAD, dst, dst_sz));
	assert_equals(dst_off, dst_sz);
	assert_equals(src_off, dst_sz);
	
	free(dst);
}

void test_copy_buf_works_when_dst_smaller_than_src_with_no_more_expected_frames()
{
	uint8_t *dst = jal_calloc(EXPECTED_PAYLOAD_SZ / 2, sizeof(uint8_t));
	size_t dst_sz = EXPECTED_PAYLOAD_SZ / 2;
	size_t dst_off = 0;

	size_t src_sz = EXPECTED_PAYLOAD_SZ;
	size_t src_off = 0;
	more = axl_false;

	assert_true(jaln_copy_buffer(dst, dst_sz, &dst_off,
		(uint8_t*) EXPECTED_PAYLOAD, src_sz, &src_off, more));

	assert(0 == memcmp(EXPECTED_PAYLOAD, dst, dst_sz));
	assert_equals(dst_off, dst_sz);
	assert_equals(src_off, dst_sz);
	
	free(dst);
}

void test_copy_buf_works_when_src_smaller_than_dst()
{
	uint8_t *dst = jal_calloc(EXPECTED_PAYLOAD_SZ, sizeof(uint8_t));
	size_t dst_sz = EXPECTED_PAYLOAD_SZ;
	size_t dst_off = 0;

	size_t src_sz = EXPECTED_PAYLOAD_SZ / 2;
	size_t src_off = 0;
	more = axl_true;

	assert_true(jaln_copy_buffer(dst, dst_sz, &dst_off,
		(uint8_t*) EXPECTED_PAYLOAD, src_sz, &src_off, more));

	assert(0 == memcmp(EXPECTED_PAYLOAD, dst, src_sz));
	assert_equals(dst_off, src_sz);
	assert_equals(src_off, src_sz);

	free(dst);
}

void test_copy_buf_fails_when_src_smaller_than_dst_and_no_more_frames()
{
	uint8_t *dst = jal_calloc(EXPECTED_PAYLOAD_SZ, sizeof(uint8_t));
	size_t dst_sz = EXPECTED_PAYLOAD_SZ;
	size_t dst_off = 0;

	size_t src_sz = EXPECTED_PAYLOAD_SZ / 2;
	size_t src_off = 0;
	more = axl_false;

	assert_false(jaln_copy_buffer(dst, dst_sz, &dst_off,
		(uint8_t*) EXPECTED_PAYLOAD, src_sz, &src_off, more));

	free(dst);
}
void test_copy_buf_works_with_offsets()
{
	uint8_t *dst = jal_calloc(EXPECTED_PAYLOAD_SZ, sizeof(uint8_t));
	size_t dst_sz = EXPECTED_PAYLOAD_SZ / 2;
	size_t dst_off = 3;
	memcpy(dst, EXPECTED_PAYLOAD, dst_off);

	size_t src_sz = EXPECTED_PAYLOAD_SZ;
	size_t src_off = 7;
	uint8_t* src = (uint8_t*) EXPECTED_PAYLOAD;
	// made of ugly. Don't want to use the same offsets for both source and
	// destination, so force them to be different with some pointer ugly.

	src = src - src_off + dst_off;
	more = axl_false;

	size_t should_copy = dst_sz - dst_off;
	size_t expected_src_offset = src_off + should_copy;
	assert_true(jaln_copy_buffer(dst, dst_sz, &dst_off,
		src, src_sz, &src_off, more));

	assert(0 == memcmp(EXPECTED_PAYLOAD, dst, dst_sz));
	assert_equals(dst_off, dst_sz);
	// should have copied enough to fill the src buffer...
	assert_equals(src_off, expected_src_offset);

	free(dst);
}

void test_create_common_initializes_machine_correctly()
{
	struct jaln_sub_state_machine *sm =
		jaln_sub_state_machine_create_common("expected_msg", "expected_payload_len");
	assert_not_equals((void*) NULL, sm);

	assert_string_equals("expected_msg", sm->expected_msg);
	assert_string_equals("expected_payload_len", sm->payload_len_hdr);

	assert_equals((void*) NULL, sm->serial_id);

	assert_equals((void*) NULL, sm->sys_meta_buf);
	assert_equals(0, sm->sys_meta_sz);
	assert_equals(0, sm->sys_meta_off);

	assert_equals((void*) NULL, sm->app_meta_buf);
	assert_equals(0, sm->app_meta_sz);
	assert_equals(0, sm->app_meta_off);

	assert_equals((void*) NULL, sm->payload_buf);
	assert_equals(0, sm->payload_sz);
	assert_equals(0, sm->payload_off);

	assert_not_equals((void*) NULL, sm->break_buf);
	assert_equals(strlen(BREAK_STR), sm->break_sz);
	assert_equals(0, sm->break_off);

	assert_equals((void*) NULL, sm->cached_frame);
	assert_equals((void*) NULL, sm->dgst_inst);
	assert_equals((void*) NULL, sm->dgst);

	assert_not_equals((void*) NULL, sm->curr_state);
	assert_not_equals((void*) NULL, sm->curr_state->name);
	assert_equals((void*)jaln_sub_wait_for_mime, sm->curr_state->frame_handler);

	assert_not_equals((void*) NULL, sm->wait_for_mime);
	assert_not_equals((void*) NULL, sm->wait_for_mime->name);
	assert_equals((void*)jaln_sub_wait_for_mime, sm->wait_for_mime->frame_handler);

	assert_not_equals((void*) NULL, sm->wait_for_sys_meta);
	assert_not_equals((void*) NULL, sm->wait_for_sys_meta->name);
	assert_equals((void*)jaln_sub_wait_for_sys_meta, sm->wait_for_sys_meta->frame_handler);

	assert_not_equals((void*) NULL, sm->wait_for_sys_meta_break);
	assert_not_equals((void*) NULL, sm->wait_for_sys_meta_break->name);
	assert_equals((void*)jaln_sub_wait_for_sys_meta_break, sm->wait_for_sys_meta_break->frame_handler);

	assert_not_equals((void*) NULL, sm->wait_for_app_meta);
	assert_not_equals((void*) NULL, sm->wait_for_app_meta->name);
	assert_equals((void*)jaln_sub_wait_for_app_meta, sm->wait_for_app_meta->frame_handler);

	assert_not_equals((void*) NULL, sm->wait_for_app_meta_break);
	assert_not_equals((void*) NULL, sm->wait_for_app_meta_break->name);
	assert_equals((void*)jaln_sub_wait_for_app_meta_break, sm->wait_for_app_meta_break->frame_handler);

	assert_equals((void*) NULL, sm->wait_for_payload);

	assert_not_equals((void*) NULL, sm->wait_for_payload_break);
	assert_not_equals((void*) NULL, sm->wait_for_payload_break->name);
	assert_equals((void*)jaln_sub_wait_for_payload_break, sm->wait_for_payload_break->frame_handler);

	assert_equals((void*) NULL, sm->record_complete);

	assert_not_equals((void*) NULL, sm->error_state);
	assert_not_equals((void*) NULL, sm->error_state->name);
	assert_equals((void*)jaln_sub_state_error_state, sm->error_state->frame_handler);
}

void test_jaln_create_log_machine()
{
	struct jaln_sub_state_machine *sm =
		jaln_sub_state_create_log_machine();

	assert_not_equals((void*) NULL, sm);
	assert_not_equals((void*) NULL, sm->wait_for_payload);
	assert_not_equals((void*) NULL, sm->wait_for_payload->name);
	assert_equals((void*)jaln_sub_wait_for_payload, sm->wait_for_payload->frame_handler);

	assert_not_equals((void*) NULL, sm->record_complete);
	assert_not_equals((void*) NULL, sm->record_complete->name);
	assert_equals((void*)jaln_sub_log_record_complete, sm->record_complete->frame_handler);
}

void test_jaln_create_audit_machine()
{
	struct jaln_sub_state_machine *sm =
		jaln_sub_state_create_audit_machine();

	assert_not_equals((void*) NULL, sm);
	assert_not_equals((void*) NULL, sm->wait_for_payload);
	assert_not_equals((void*) NULL, sm->wait_for_payload->name);
	assert_equals((void*)jaln_sub_wait_for_payload, sm->wait_for_payload->frame_handler);

	assert_not_equals((void*) NULL, sm->record_complete);
	assert_not_equals((void*) NULL, sm->record_complete->name);
	assert_equals((void*)jaln_sub_audit_record_complete, sm->record_complete->frame_handler);
}

void test_jaln_create_journal_machine()
{
	struct jaln_sub_state_machine *sm =
		jaln_sub_state_create_journal_machine();

	assert_not_equals((void*) NULL, sm);
	assert_not_equals((void*) NULL, sm->wait_for_payload);
	assert_not_equals((void*) NULL, sm->wait_for_payload->name);
	assert_equals((void*)jaln_sub_wait_for_journal_payload, sm->wait_for_payload->frame_handler);

	assert_not_equals((void*) NULL, sm->record_complete);
	assert_not_equals((void*) NULL, sm->record_complete->name);
	assert_equals((void*)jaln_sub_journal_record_complete, sm->record_complete->frame_handler);
}
