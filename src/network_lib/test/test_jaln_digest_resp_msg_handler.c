/**
 * @file This file contains tests for jaln_message_helpers.c functions.
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

#include <inttypes.h>
#include <jalop/jal_status.h>
#include <stdint.h>
#include <stdlib.h>
#include <vortex.h>

#include "jal_alloc.h"

#include "jaln_message_helpers.h"

#include "jaln_digest_info.h"
#include "jaln_digest_resp_msg_handler.h"
#include <test-dept.h>
#include <string.h>
#include <ctype.h>

#define sid_1_str "sid_1"
#define sid_2_str "sid_2"
#define sid_3_str "sid_3"

#define dr_1_str "confirmed=sid_1\r\n"
#define dr_2_str "invalid=sid_2\r\n"
#define dr_3_str "unknown=sid_3\r\n"

#define bad_sid_line_one   "unknown =sid_9\r\n"
#define bad_sid_line_two   " unknown=sid_9\r\n"
#define bad_sid_line_three "unkown=sid_9\r\n"
#define bad_sid_line_four  "=sid_9\r\n"
#define bad_sid_line_five  "unknown=sid_9\n"
#define bad_sid_line_six   "unknown=sid_9\r"
#define bad_sid_line_seven "\r\nunknown=sid_9"
#define bad_sid_line_eight "unknown=sid_9"
#define bad_sid_line_nine "unknown=\r\n"
#define bad_sid_line_ten "unknown="
#define bad_sid_line_eleven "unknown"
#define bad_sid_line_twelve "unknow"

#define GOOD_PAYLOAD \
	dr_1_str \
	dr_2_str \
	dr_3_str

#define BAD_PAYLOAD_ONE \
	dr_1_str \
	dr_2_str \
	bad_sid_line_one

#define BAD_PAYLOAD_TWO \
	dr_1_str \
	dr_2_str \
	bad_sid_line_two

#define BAD_PAYLOAD_THREE \
	dr_1_str \
	dr_2_str \
	bad_sid_line_three

#define BAD_PAYLOAD_FOUR \
	dr_1_str \
	dr_2_str \
	bad_sid_line_four

#define BAD_PAYLOAD_FIVE \
	dr_1_str \
	dr_2_str \
	bad_sid_line_five

#define BAD_PAYLOAD_SIX_A \
	dr_1_str \
	dr_3_str \
	bad_sid_line_six

#define BAD_PAYLOAD_SIX \
	dr_1_str \
	bad_sid_line_six \
	dr_3_str

#define BAD_PAYLOAD_SEVEN \
	dr_1_str \
	bad_sid_line_seven \
	dr_3_str

#define BAD_PAYLOAD_EIGHT \
	dr_1_str \
	bad_sid_line_eight \
	dr_3_str

#define BAD_PAYLOAD_EIGHT_A \
	dr_1_str \
	dr_3_str \
	bad_sid_line_eight

#define BAD_PAYLOAD_NINE \
	dr_1_str \
	bad_sid_line_nine \
	dr_3_str

#define BAD_PAYLOAD_TEN \
	dr_1_str \
	dr_2_str \
	dr_3_str \
	bad_sid_line_ten

#define BAD_PAYLOAD_TEN_A \
	dr_1_str \
	dr_2_str \
	bad_sid_line_ten

#define BAD_PAYLOAD_ELEVEN \
	dr_1_str \
	dr_2_str \
	dr_3_str \
	bad_sid_line_eleven

#define BAD_PAYLOAD_ELEVEN_A \
	dr_1_str \
	dr_2_str \
	bad_sid_line_eleven

#define BAD_PAYLOAD_TWELVE \
	dr_1_str \
	dr_2_str \
	dr_3_str \
	bad_sid_line_twelve

#define BAD_PAYLOAD_TWELVE_A \
	dr_1_str \
	dr_2_str \
	bad_sid_line_twelve

#define BAD_PAYLOAD_THIRTEEN \
	dr_1_str \
	dr_2_str \
	dr_3_str \
	"asdf"

#define BAD_PAYLOAD_FOURTEEN \
	dr_1_str \
	dr_2_str \
	dr_3_str \
	"\0a"


static const char *fake_get_mime_content(VortexMimeHeader *header)
{
	return (char*)header;
}

static VortexMimeHeader *fake_get_mime_header(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-message")) {
		return (VortexMimeHeader*) "digest-response";
	} else if (0 == strcasecmp(header_name, "jal-count")) {
		return (VortexMimeHeader*) "3";
	}
	return NULL;
}

static VortexMimeHeader *get_mime_header_returns_unexpected_msg(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-message")) {
		return (VortexMimeHeader*) "jal-sync";
	}
	return fake_get_mime_header(frame, header_name);
}

static VortexMimeHeader *get_mime_header_returns_count_too_small(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-count")) {
		return (VortexMimeHeader*) "2";
	}
	return fake_get_mime_header(frame, header_name);
}

static VortexMimeHeader *get_mime_header_returns_zero_count(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-count")) {
		return (VortexMimeHeader*) "0";
	}
	return fake_get_mime_header(frame, header_name);
}

static VortexMimeHeader *get_mime_header_returns_count_too_big(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-count")) {
		return (VortexMimeHeader*) "4";
	}
	return fake_get_mime_header(frame, header_name);
}

static VortexMimeHeader *get_mime_header_returns_null_for_msg(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-message")) {
		return (VortexMimeHeader*) NULL;
	}
	return fake_get_mime_header(frame, header_name);
}

static VortexMimeHeader *get_mime_header_returns_null_for_count(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-count")) {
		return (VortexMimeHeader*) NULL;
	}
	return fake_get_mime_header(frame, header_name);
}


static char *payload;
static const void *fake_get_payload_returns_null(__attribute__((unused)) VortexFrame *frame)
{
	return NULL;
}

static int fake_get_payload_size_returns_negative(__attribute__((unused)) VortexFrame *frame)
{
	return -1;
}

static int fake_get_payload_size_returns_zero(__attribute__((unused)) VortexFrame *frame)
{
	return 0;
}

static const void *fake_get_payload(__attribute__((unused)) VortexFrame *frame)
{
	return payload;
}
static int fake_get_payload_size_with_trailing_garbage(__attribute__((unused)) VortexFrame *frame)
{
	return strlen(BAD_PAYLOAD_FOURTEEN) + 2;
}
static int fake_get_payload_size(__attribute__((unused)) VortexFrame *frame)
{
	return strlen(payload);
}

static axl_bool ct_and_enc_always_succeed(__attribute__((unused)) VortexFrame *frame)
{
	return axl_true;
}

static axl_bool ct_and_enc_always_fail(__attribute__((unused)) VortexFrame *frame)
{
	return axl_false;
}

#define DGST_RESP_MSG \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: digest-response\r\n" \
	"JAL-Count: 3\r\n\r\n" \
	dr_1_str \
	dr_2_str \
	dr_3_str

axlList *dgst_resp_list;
void setup()
{
	dgst_resp_list = NULL;
	payload = GOOD_PAYLOAD;
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_frame_mime_header_content, fake_get_mime_content);
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid, ct_and_enc_always_succeed);
	replace_function(vortex_frame_get_payload, fake_get_payload);
	replace_function(vortex_frame_get_payload_size, fake_get_payload_size);
}

void teardown()
{
	if (dgst_resp_list) {
		axl_list_free(dgst_resp_list);
	}
	restore_function(vortex_frame_get_mime_header);
	restore_function(vortex_frame_mime_header_content);
	restore_function(jaln_check_content_type_and_txfr_encoding_are_valid);
	restore_function(vortex_frame_get_payload);
	restore_function(vortex_frame_get_payload_size);
}

void test_process_dgst_resp_works_with_good_input()
{
	assert_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
	assert_not_equals((void*) NULL, dgst_resp_list);
	assert_equals(3, axl_list_length(dgst_resp_list));
	axlListCursor *cursor = axl_list_cursor_new(dgst_resp_list);
	assert_not_equals((void*) NULL, cursor);

	struct jaln_digest_resp_info *dr = NULL;

	assert_true(axl_list_cursor_has_item(cursor));
	dr = (struct jaln_digest_resp_info*) axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, dr);
	assert_string_equals(sid_1_str, dr->serial_id);
	assert_equals(JALN_DIGEST_STATUS_CONFIRMED, dr->status);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	dr = (struct jaln_digest_resp_info*) axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, dr);
	assert_string_equals(sid_2_str, dr->serial_id);
	assert_equals(JALN_DIGEST_STATUS_INVALID, dr->status);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	dr = (struct jaln_digest_resp_info*) axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, dr);
	assert_string_equals(sid_3_str, dr->serial_id);
	assert_equals(JALN_DIGEST_STATUS_UNKNOWN, dr->status);
	axl_list_cursor_free(cursor);
}

void test_process_dgst_resp_fails_when_ct_and_xfr_check_fails()
{
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid, ct_and_enc_always_fail);
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}

void test_process_dgst_resp_fails_with_wrong_message()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_returns_unexpected_msg);
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}
void test_process_dgst_resp_fails_with_count_equals_zero()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_returns_zero_count);
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}
void test_process_dgst_resp_fails_with_count_too_big()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_returns_count_too_big);
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}

void test_process_dgst_resp_fails_with_NULL_msg()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_returns_null_for_msg);
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}

void test_process_dgst_resp_fails_with_null_count()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_returns_null_for_count);
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}

void test_process_dgst_resp_fails_with_count_too_small()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_returns_count_too_small);
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}

void test_process_dgst_resp_fails_with_payload_size_zero()
{
	replace_function(vortex_frame_get_payload_size, fake_get_payload_size_returns_zero);
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}

void test_process_dgst_resp_fails_with_negative_payload_size()
{
	replace_function(vortex_frame_get_payload_size, fake_get_payload_size_returns_negative);
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}

void test_process_dgst_resp_fails_with_null_payload()
{
	replace_function(vortex_frame_get_payload, fake_get_payload_returns_null);
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}

void test_process_dgst_resp_fails_with_bad_inputs()
{
	assert_not_equals(JAL_OK, jaln_process_digest_resp(NULL, &dgst_resp_list));
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, NULL));

	dgst_resp_list = (axlList*)0xbadf00d;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
	dgst_resp_list = NULL;
}

void test_process_dgst_resp_fails_with_poorly_formed_payload()
{
	payload = BAD_PAYLOAD_ONE;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_TWO;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_THREE;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_FOUR;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_FIVE;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_SIX;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_SIX_A;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_SEVEN;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_EIGHT;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_EIGHT_A;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_NINE;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_TEN;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_TEN_A;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_ELEVEN;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_ELEVEN_A;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_TWELVE;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_TWELVE_A;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	payload = BAD_PAYLOAD_THIRTEEN;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));

	replace_function(vortex_frame_get_payload_size, fake_get_payload_size_with_trailing_garbage);
	payload = BAD_PAYLOAD_FOURTEEN;
	assert_not_equals(JAL_OK, jaln_process_digest_resp((VortexFrame*) 0xbadf00d, &dgst_resp_list));
}
