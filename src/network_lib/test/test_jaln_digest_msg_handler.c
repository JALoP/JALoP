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

#include <ctype.h>
#include <inttypes.h>
#include <jalop/jal_status.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <test-dept.h>
#include <vortex.h>

#include "jal_alloc.h"

#include "jaln_message_helpers.h"
#include "jaln_digest_info.h"
#include "jaln_digest_msg_handler.h"

#define sid_1_str "sid_1"
#define sid_2_str "sid_2"
#define sid_3_str "sid_3"

#define dr_1_str "abcd1234=sid_1\r\n"
#define dr_2_str "1234abcd=sid_2\r\n"
#define dr_3_str "11aa22bb=sid_3\r\n"
#define dgst_len 4

static uint8_t dgst_1_val[dgst_len] = { 0xab, 0xcd, 0x12, 0x34 };
static uint8_t dgst_2_val[dgst_len] = { 0x12, 0x34, 0xab, 0xcd };
static uint8_t dgst_3_val[dgst_len] = { 0x11, 0xaa, 0x22, 0xbb };

#define bad_sid_line_one   "1234 =sid_9\r\n"
#define bad_sid_line_two   " 1234=sid_9\r\n"
#define bad_sid_line_three  "=sid_9\r\n"
#define bad_sid_line_four  "1234=sid_9\n"
#define bad_sid_line_five   "1234=sid_9\r"
#define bad_sid_line_six "\r\n1234=sid_9"
#define bad_sid_line_seven "1234=sid_9"
#define bad_sid_line_eight "1234=\r\n"
#define bad_sid_line_nine "1234="
#define bad_sid_line_ten "1234"

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
	bad_sid_line_four \
	dr_2_str

#define BAD_PAYLOAD_FIVE \
	dr_1_str \
	bad_sid_line_five \
	dr_2_str

#define BAD_PAYLOAD_SIX \
	dr_1_str \
	dr_3_str \
	bad_sid_line_six

#define BAD_PAYLOAD_SEVEN \
	dr_1_str \
	bad_sid_line_seven \
	dr_3_str

#define BAD_PAYLOAD_SEVEN_A \
	dr_1_str \
	dr_3_str \
	bad_sid_line_seven

#define BAD_PAYLOAD_EIGHT \
	dr_1_str \
	dr_2_str \
	bad_sid_line_eight

#define BAD_PAYLOAD_EIGHT_A \
	dr_1_str \
	dr_2_str \
	dr_3_str \
	bad_sid_line_eight

#define BAD_PAYLOAD_NINE \
	dr_1_str \
	bad_sid_line_nine \
	dr_3_str

#define BAD_PAYLOAD_NINE_A \
	dr_1_str \
	dr_2_str \
	dr_3_str \
	bad_sid_line_nine

#define BAD_PAYLOAD_TEN \
	dr_1_str \
	dr_2_str \
	bad_sid_line_ten

#define BAD_PAYLOAD_TEN_A \
	dr_1_str \
	dr_2_str \
	dr_3_str \
	bad_sid_line_ten

#define BAD_PAYLOAD_ELEVEN \
	"\0"

#define BAD_PAYLOAD_TWELVE \
	dr_1_str \
	dr_2_str \
	dr_3_str "\0foo"

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
		return (VortexMimeHeader*) "digest";
	} else if (0 == strcasecmp(header_name, "jal-count")) {
		return (VortexMimeHeader*) "3";
	}
	return NULL;
}

#define DECL_MIME_HANDLER(func_name__, header_name__, header_val__) \
static VortexMimeHeader * func_name__ (VortexFrame *frame, const char *header_name) \
{ \
	if (!frame) { \
		return NULL; \
	} \
	if (0 == strcasecmp(header_name, header_name__)) { \
		return (VortexMimeHeader*) header_val__ ; \
	} \
	return fake_get_mime_header(frame, header_name); \
}

DECL_MIME_HANDLER(get_mime_header_returns_unexpected_msg, "jal-message", "jal-sync");
DECL_MIME_HANDLER(get_mime_header_missing_msg, "jal-message", NULL);
DECL_MIME_HANDLER(get_mime_header_missing_count, "jal-count", NULL);
DECL_MIME_HANDLER(get_mime_header_returns_count_too_small, "jal-count", "2");
DECL_MIME_HANDLER(get_mime_header_returns_zero_count, "jal-count", "0");
DECL_MIME_HANDLER(get_mime_header_returns_count_too_big, "jal-count", "4");
DECL_MIME_HANDLER(get_mime_header_count_is_bad, "jal-count", "4a");

static char *payload;
static int fake_get_payload_size_returns_zero(__attribute__((unused)) VortexFrame *frame)
{
	return 0;
}
static const void *fake_get_payload_returns_null(__attribute__((unused)) VortexFrame *frame)
{
	return NULL;
}
static const void *fake_get_payload(__attribute__((unused)) VortexFrame *frame)
{
	return payload;
}

// for use with bad_payload_eleven
static int fake_get_message_with_just_null_byte(__attribute__((unused)) VortexFrame *frame)
{
	return 1;
}

static int fake_get_trailing_garbage_size(__attribute__((unused)) VortexFrame *frame)
{
	return strlen(BAD_PAYLOAD_TWELVE) + 4;
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

axlList *dgst_list;
void setup()
{
	dgst_list = NULL;
	payload = GOOD_PAYLOAD;
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_frame_mime_header_content, fake_get_mime_content);
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid, ct_and_enc_always_succeed);
	replace_function(vortex_frame_get_payload, fake_get_payload);
	replace_function(vortex_frame_get_payload_size, fake_get_payload_size);
}

void teardown()
{
	if (dgst_list) {
		axl_list_free(dgst_list);
	}
	restore_function(vortex_frame_get_mime_header);
	restore_function(vortex_frame_mime_header_content);
	restore_function(jaln_check_content_type_and_txfr_encoding_are_valid);
	restore_function(vortex_frame_get_payload);
	restore_function(vortex_frame_get_payload_size);
}

void test_process_dgst_works_with_good_input()
{
	assert_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
	assert_not_equals((void*) NULL, dgst_list);
	assert_equals(3, axl_list_length(dgst_list));
	axlListCursor *cursor = axl_list_cursor_new(dgst_list);
	assert_not_equals((void*) NULL, cursor);

	struct jaln_digest_info *di = NULL;

	assert_true(axl_list_cursor_has_item(cursor));
	di = (struct jaln_digest_info*) axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, di);
	assert_string_equals(sid_1_str, di->serial_id);
	assert_equals(dgst_len, di->digest_len);
	assert_equals(0, memcmp(dgst_1_val, di->digest, di->digest_len));

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	di = (struct jaln_digest_info*) axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, di);
	assert_string_equals(sid_2_str, di->serial_id);
	assert_equals(dgst_len, di->digest_len);
	assert_equals(0, memcmp(dgst_2_val, di->digest, di->digest_len));

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	di = (struct jaln_digest_info*) axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, di);
	assert_string_equals(sid_3_str, di->serial_id);
	assert_equals(dgst_len, di->digest_len);
	assert_equals(0, memcmp(dgst_3_val, di->digest, di->digest_len));

	axl_list_cursor_free(cursor);
}

void test_process_dgst_fails_when_ct_and_xfr_check_fails()
{
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid, ct_and_enc_always_fail);
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
}

void test_process_dgst_fails_with_wrong_message()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_returns_unexpected_msg);
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
}
void test_process_dgst_fails_with_count_equals_zero()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_returns_zero_count);
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
}
void test_process_dgst_fails_with_count_too_big()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_returns_count_too_big);
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
}

void test_process_dgst_fails_when_count()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_missing_count);
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
}

void test_process_dgst_fails_when_missing_msg()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_missing_msg);
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
}

void test_process_dgst_fails_with_count_too_small()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_returns_count_too_small);
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
}

void test_process_dgst_fails_fails_when_get_payload_returns_null()
{
	replace_function(vortex_frame_get_payload, fake_get_payload_returns_null);
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
}

void test_process_dgst_fails_when_get_payload_size_returns_zero()
{
	replace_function(vortex_frame_get_payload_size, fake_get_payload_size_returns_zero);
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
}

void test_process_dgst_fails_with_poorly_formed_count()
{
	replace_function(vortex_frame_get_mime_header, get_mime_header_count_is_bad);
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
}

void test_process_dgst_fails_with_bad_inputs()
{
	assert_not_equals(JAL_OK, jaln_process_digest(NULL, &dgst_list));
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, NULL));

	dgst_list = (axlList*)0xbadf00d;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));
	dgst_list = NULL;
}

void test_process_dgst_fails_with_poorly_formed_payload()
{
	payload = BAD_PAYLOAD_ONE;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_TWO;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_THREE;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_FOUR;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_FIVE;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_SIX;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_SEVEN;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_SEVEN_A;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_EIGHT;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_EIGHT_A;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_NINE;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_NINE_A;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_TEN;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	payload = BAD_PAYLOAD_TEN_A;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	replace_function(vortex_frame_get_payload_size, fake_get_message_with_just_null_byte);
	payload = BAD_PAYLOAD_ELEVEN;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

	replace_function(vortex_frame_get_payload_size, fake_get_trailing_garbage_size);
	payload = BAD_PAYLOAD_TWELVE;
	assert_not_equals(JAL_OK, jaln_process_digest((VortexFrame*) 0xbadf00d, &dgst_list));

}
