/**
 * @file test_jaln_init_msg_handler.c This file contains tests for jaln_init_msg_handler.c functions.
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

#include "jaln_init_info.h"
#include "jaln_init_msg_handler.h"
#include <test-dept.h>
#include <string.h>
#include <ctype.h>

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
		return (VortexMimeHeader*) "initialize";
	} else if (0 == strcasecmp(header_name, "jal-mode")) {
		return (VortexMimeHeader*) "subscribe-live";
	} else if (0 == strcasecmp(header_name, "jal-agent")) {
		return (VortexMimeHeader*) "some/agent";
	} else if (0 == strcasecmp(header_name, "jal-data-class")) {
		return (VortexMimeHeader*) "journal";
	} else if (0 == strcasecmp(header_name, "jal-accept-digest")) {
		return (VortexMimeHeader*) "digest_1, digest_2, digest_3";
	} else if (0 == strcasecmp(header_name, "jal-accept-xml-compression")) {
		return (VortexMimeHeader*) "encoding_1, encoding_2, encoding_3";
	}
	return NULL;
}

#define DECL_MIME_HANDLER(func_name, header__, val__) \
static VortexMimeHeader * func_name (VortexFrame *frame, const char *header_name) \
{ \
	if (!frame) { \
		return NULL; \
	} \
	if (0 == strcasecmp(header_name, header__)) { \
		return (VortexMimeHeader*) val__; \
	} \
	return fake_get_mime_header(frame, header_name); \
}

DECL_MIME_HANDLER(fake_get_mime_header_missing_msg, "jal-message", NULL);
DECL_MIME_HANDLER(fake_get_mime_header_missing_data_class, "jal-data-class", NULL);
DECL_MIME_HANDLER(fake_get_mime_header_missing_mode, "jal-mode", NULL);
DECL_MIME_HANDLER(fake_get_mime_header_bad_msg, "jal-message", "jal-sync")
DECL_MIME_HANDLER(fake_get_mime_header_bad_data_class, "jal-data-class", "bad_class")
DECL_MIME_HANDLER(fake_get_mime_header_bad_mode, "jal-mode", "bad_mode")
DECL_MIME_HANDLER(fake_get_mime_header_no_dgst_algs, "jal-accept-digest", NULL)
DECL_MIME_HANDLER(fake_get_mime_header_no_encs, "jal-accept-xml-compression", NULL)
DECL_MIME_HANDLER(fake_get_mime_header_no_agent, "jal-agent", NULL)
DECL_MIME_HANDLER(fake_get_mime_header_audit, "jal-data-class", "audit");
DECL_MIME_HANDLER(fake_get_mime_header_log, "jal-data-class", "log");
DECL_MIME_HANDLER(fake_get_mime_header_publisher, "jal-mode", "live");

static axl_bool ct_and_enc_always_succeed(__attribute__((unused)) VortexFrame *frame)
{
	return axl_true;
}

static axl_bool ct_and_enc_always_fail(__attribute__((unused)) VortexFrame *frame)
{
	return axl_false;
}
struct jaln_init_info *info;
void setup()
{
	info = NULL;
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_frame_mime_header_content, fake_get_mime_content);
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid, ct_and_enc_always_succeed);
}

void teardown()
{
	jaln_init_info_destroy(&info);
	restore_function(vortex_frame_get_mime_header);
	restore_function(vortex_frame_mime_header_content);
	restore_function(jaln_check_content_type_and_txfr_encoding_are_valid);
}

void test_process_init_works_with_good_input()
{
	assert_equals(JAL_OK, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
	assert_not_equals((void*) NULL, info);
	assert_not_equals((void*) NULL, info->digest_algs);
	assert_not_equals((void*) NULL, info->encodings);

	assert_equals(JALN_ROLE_SUBSCRIBER, info->role);
	assert_equals(JALN_LIVE_MODE, info->mode);
	assert_equals(JALN_RTYPE_JOURNAL, info->type);
	assert_string_equals("some/agent", info->peer_agent);
	assert_equals(3, axl_list_length(info->digest_algs));
	assert_equals(3, axl_list_length(info->encodings));

	axlListCursor *cursor = axl_list_cursor_new(info->digest_algs);
	assert_not_equals((void*) NULL, cursor);

	char *str = NULL;
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_3", str);

	axl_list_cursor_free(cursor);
	cursor = axl_list_cursor_new(info->encodings);
	assert_not_equals((void*) NULL, cursor);

	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_3", str);

	axl_list_cursor_free(cursor);
}

void test_process_init_works_for_audit()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_audit);
	assert_equals(JAL_OK, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
	assert_not_equals((void*) NULL, info);

	assert_equals(JALN_ROLE_SUBSCRIBER, info->role);
	assert_equals(JALN_RTYPE_AUDIT, info->type);
	assert_string_equals("some/agent", info->peer_agent);
	assert_equals(3, axl_list_length(info->digest_algs));
	assert_equals(3, axl_list_length(info->encodings));

	axlListCursor *cursor = axl_list_cursor_new(info->digest_algs);
	assert_not_equals((void*) NULL, cursor);

	char *str = NULL;
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_3", str);
	axl_list_cursor_free(cursor);

	cursor = axl_list_cursor_new(info->encodings);
	assert_not_equals((void*) NULL, cursor);

	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_3", str);
	axl_list_cursor_free(cursor);
}

void test_process_init_works_for_log()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_log);
	assert_equals(JAL_OK, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
	assert_not_equals((void*) NULL, info);

	assert_equals(JALN_ROLE_SUBSCRIBER, info->role);
	assert_equals(JALN_RTYPE_LOG, info->type);
	assert_string_equals("some/agent", info->peer_agent);
	assert_equals(3, axl_list_length(info->digest_algs));
	assert_equals(3, axl_list_length(info->encodings));

	axlListCursor *cursor = axl_list_cursor_new(info->digest_algs);
	assert_not_equals((void*) NULL, cursor);

	char *str = NULL;
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_3", str);
	axl_list_cursor_free(cursor);

	cursor = axl_list_cursor_new(info->encodings);
	assert_not_equals((void*) NULL, cursor);

	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_3", str);
	axl_list_cursor_free(cursor);
}
void test_process_init_works_for_publisher()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_publisher);
	assert_equals(JAL_OK, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
	assert_not_equals((void*) NULL, info);

	assert_equals(JALN_ROLE_PUBLISHER, info->role);
	assert_equals(JALN_LIVE_MODE, info->mode);
	assert_equals(JALN_RTYPE_JOURNAL, info->type);
	assert_string_equals("some/agent", info->peer_agent);
	assert_equals(3, axl_list_length(info->digest_algs));
	assert_equals(3, axl_list_length(info->encodings));

	axlListCursor *cursor = axl_list_cursor_new(info->digest_algs);
	assert_not_equals((void*) NULL, cursor);

	char *str = NULL;
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_3", str);
	axl_list_cursor_free(cursor);

	cursor = axl_list_cursor_new(info->encodings);
	assert_not_equals((void*) NULL, cursor);

	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_3", str);
	axl_list_cursor_free(cursor);
}
void test_process_init_works_when_missing_agent()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_no_agent);
	assert_equals(JAL_OK, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
	assert_not_equals((void*) NULL, info);

	assert_equals(JALN_ROLE_SUBSCRIBER, info->role);
	assert_equals(JALN_RTYPE_JOURNAL, info->type);
	assert_pointer_equals((void*) NULL, info->peer_agent);
	assert_equals(3, axl_list_length(info->digest_algs));
	assert_equals(3, axl_list_length(info->encodings));

	axlListCursor *cursor = axl_list_cursor_new(info->digest_algs);
	assert_not_equals((void*) NULL, cursor);

	char *str = NULL;
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_3", str);
	axl_list_cursor_free(cursor);

	cursor = axl_list_cursor_new(info->encodings);
	assert_not_equals((void*) NULL, cursor);

	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_3", str);
	axl_list_cursor_free(cursor);
}

void test_process_init_works_with_no_dsgt_algs()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_no_dgst_algs);
	assert_equals(JAL_OK, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
	assert_not_equals((void*) NULL, info);

	assert_equals(JALN_ROLE_SUBSCRIBER, info->role);
	assert_equals(JALN_RTYPE_JOURNAL, info->type);
	assert_string_equals("some/agent", info->peer_agent);
	assert_equals(1, axl_list_length(info->digest_algs));
	assert_equals(3, axl_list_length(info->encodings));

	axlListCursor *cursor = axl_list_cursor_new(info->digest_algs);
	assert_not_equals((void*) NULL, cursor);

	char *str = NULL;
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("sha256", str);

	axl_list_cursor_free(cursor);
	cursor = axl_list_cursor_new(info->encodings);
	assert_not_equals((void*) NULL, cursor);

	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("encoding_3", str);
	axl_list_cursor_free(cursor);
}

void test_process_init_works_with_no_encodings()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_no_encs);
	assert_equals(JAL_OK, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
	assert_not_equals((void*) NULL, info);

	assert_equals(JALN_ROLE_SUBSCRIBER, info->role);
	assert_equals(JALN_RTYPE_JOURNAL, info->type);
	assert_string_equals("some/agent", info->peer_agent);
	assert_equals(3, axl_list_length(info->digest_algs));
	assert_equals(1, axl_list_length(info->encodings));

	axlListCursor *cursor = axl_list_cursor_new(info->digest_algs);
	assert_not_equals((void*) NULL, cursor);

	char *str = NULL;
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_1", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_2", str);

	axl_list_cursor_next(cursor);
	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("digest_3", str);

	axl_list_cursor_free(cursor);
	cursor = axl_list_cursor_new(info->encodings);
	assert_not_equals((void*) NULL, cursor);

	assert_true(axl_list_cursor_has_item(cursor));
	str = (char *)axl_list_cursor_get(cursor);
	assert_not_equals((void*) NULL, str);
	assert_string_equals("none", str);
	axl_list_cursor_free(cursor);
}

void test_process_init_fails_with_missing_role()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_missing_mode);
	assert_equals(JAL_E_INVAL, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
}

void test_process_init_fails_with_bad_role()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_bad_mode);
	assert_equals(JAL_E_INVAL, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
}

void test_process_init_fails_with_bad_data_class()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_bad_data_class);
	assert_equals(JAL_E_INVAL, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
}
void test_process_init_fails_with_missing_data_class()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_missing_data_class);
	assert_equals(JAL_E_INVAL, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
}

void test_process_init_fails_when_ct_and_xfr_check_fails()
{
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid, ct_and_enc_always_fail);
	assert_equals(JAL_E_INVAL, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
}

void test_process_init_fails_with_wrong_message()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_bad_msg);
	assert_equals(JAL_E_INVAL, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
}
void test_process_init_fails_with_missing_message()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_missing_msg);
	assert_equals(JAL_E_INVAL, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
}

void test_process_init_fails_with_bad_inputs()
{
	assert_not_equals(JAL_OK, jaln_process_init(NULL, &info));
	assert_not_equals(JAL_OK, jaln_process_init((VortexFrame*) 0xbadf00d, NULL));

	info = (struct jaln_init_info*)0xbadf00d;
	assert_not_equals(JAL_OK, jaln_process_init((VortexFrame*) 0xbadf00d, &info));
	info = NULL;
}

