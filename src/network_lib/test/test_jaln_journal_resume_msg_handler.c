/**
 * @file test_jaln_journal_resume_msg_handler.c This file contains tests for jaln_journal_resume_msg_handler.c functions.
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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <test-dept.h>
#include <vortex.h>

#include "jal_alloc.h"

#include "jaln_message_helpers.h"
#include "jaln_journal_resume_msg_handler.h"

#define EXPECTED_OFFSET 1234567

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
		return (VortexMimeHeader*) "journal-resume";
	} else if (0 == strcasecmp(header_name, "jal-id")) {
		return (VortexMimeHeader*) "the_nonce_string";
	} else if (0 == strcasecmp(header_name, "jal-journal-offset")) {
		return (VortexMimeHeader*) "1234567";
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
DECL_MIME_HANDLER(fake_get_mime_header_bad_msg, "jal-message", "jal-sync")
DECL_MIME_HANDLER(fake_get_mime_header_missing_nonce, "jal-id", NULL);
DECL_MIME_HANDLER(fake_get_mime_header_missing_offset, "jal-journal-offset", NULL);
DECL_MIME_HANDLER(fake_get_mime_header_bad_offset, "jal-journal-offset", "123b123");

static axl_bool ct_and_enc_always_succeed(__attribute__((unused)) VortexFrame *frame)
{
	return axl_true;
}

static axl_bool ct_and_enc_always_fail(__attribute__((unused)) VortexFrame *frame)
{
	return axl_false;
}

static char *nonce;
void setup()
{
	nonce = NULL;
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_frame_mime_header_content, fake_get_mime_content);
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid, ct_and_enc_always_succeed);
}

void teardown()
{
	free(nonce);
	restore_function(vortex_frame_get_mime_header);
	restore_function(vortex_frame_mime_header_content);
	restore_function(jaln_check_content_type_and_txfr_encoding_are_valid);
}

void test_process_journal_resume_works_with_good_input()
{
	uint64_t offset = 0;
	assert_equals(JAL_OK, jaln_process_journal_resume((VortexFrame*) 0xbadf00d, &nonce, &offset));
	assert_not_equals((void*) NULL, nonce);
	assert_string_equals("the_nonce_string", nonce);
	assert_equals(EXPECTED_OFFSET, offset);
}

void test_process_journal_resume_fails_when_ct_and_xfr_check_fails()
{
	uint64_t offset = 0;
	replace_function(jaln_check_content_type_and_txfr_encoding_are_valid, ct_and_enc_always_fail);
	assert_equals(JAL_E_INVAL, jaln_process_journal_resume((VortexFrame*) 0xbadf00d, &nonce, &offset));
}

void test_process_journal_resume_fails_with_missing_offset()
{
	uint64_t offset = 0;
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_missing_offset);
	assert_equals(JAL_E_INVAL, jaln_process_journal_resume((VortexFrame*) 0xbadf00d, &nonce, &offset));
}

void test_process_journal_resume_fails_with_bad_offset()
{
	uint64_t offset = 0;
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_bad_offset);
	assert_equals(JAL_E_INVAL, jaln_process_journal_resume((VortexFrame*) 0xbadf00d, &nonce, &offset));
}

void test_process_journal_resume_fails_with_wrong_message()
{
	uint64_t offset = 0;
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_bad_msg);
	assert_equals(JAL_E_INVAL, jaln_process_journal_resume((VortexFrame*) 0xbadf00d, &nonce, &offset));
}

void test_process_journal_resume_fails_with_missing_message()
{
	uint64_t offset = 0;
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_missing_msg);
	assert_equals(JAL_E_INVAL, jaln_process_journal_resume((VortexFrame*) 0xbadf00d, &nonce, &offset));
}

void test_process_journal_resume_fails_with_missing_nonce()
{
	uint64_t offset = 0;
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header_missing_nonce);
	assert_equals(JAL_E_INVAL, jaln_process_journal_resume((VortexFrame*) 0xbadf00d, &nonce, &offset));
}

void test_process_journal_resume_fails_with_bad_inputs()
{
	uint64_t offset = 0;
	assert_not_equals(JAL_OK, jaln_process_journal_resume(NULL, &nonce, &offset));
	assert_not_equals(JAL_OK, jaln_process_journal_resume((VortexFrame*) 0xbadf00d, NULL, &offset));

	nonce = (char*)0xbadf00d;
	assert_not_equals(JAL_OK, jaln_process_journal_resume((VortexFrame*) 0xbadf00d, &nonce, &offset));
	nonce = NULL;

	assert_not_equals(JAL_OK, jaln_process_journal_resume((VortexFrame*) 0xbadf00d, &nonce, NULL));
}

