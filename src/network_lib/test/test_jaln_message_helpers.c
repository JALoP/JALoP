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
#include <test-dept.h>
#include <string.h>
#include <ctype.h>

#define sid_1_str "sid_1"

#define EXPECTED_SYNC_MSG \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n" \
	"JAL-Message: sync\r\n" \
	"JAL-Serial-Id: " sid_1_str "\r\n\r\n"

VortexMimeHeader *wrong_encoding_get_mime_header(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (strcasecmp(header_name, "content-type") == 0) {
		return (VortexMimeHeader*) "application/beep+jalop";
	} else if (strcasecmp(header_name, "content-transfer-encoding") == 0) {
		return (VortexMimeHeader*) "utf-16";
	}
	return NULL;
}
VortexMimeHeader *wrong_content_type_get_mime_header(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (strcasecmp(header_name, "content-type") == 0) {
		return (VortexMimeHeader*) "application/flubber";
	} else if (strcasecmp(header_name, "content-transfer-encoding") == 0) {
		return (VortexMimeHeader*) "binary";
	}
	return NULL;
}
VortexMimeHeader *fake_get_mime_header(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (strcasecmp(header_name, "content-type") == 0) {
		return (VortexMimeHeader*) "application/beep+jalop";
	} else if (strcasecmp(header_name, "content-transfer-encoding") == 0) {
		return (VortexMimeHeader*) "binary";
	}
	return NULL;
}

VortexMimeHeader *only_content_type_get_mime_header(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (strcasecmp(header_name, "content-type") == 0) {
		return (VortexMimeHeader*) "application/beep+jalop";
	}
	return NULL;
}

VortexMimeHeader *only_enc_get_mime_header(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (strcasecmp(header_name, "content-transfer-encoding") == 0) {
		return (VortexMimeHeader*) "binary";
	}
	return NULL;
}

const char *fake_get_mime_content(VortexMimeHeader *header)
{
	return (const char*) header;
}

static struct jaln_digest_info *di_1;
static struct jaln_digest_info *di_2;
static struct jaln_digest_info *di_3;

#define DGST_LEN 7
static uint8_t di_buf_1[DGST_LEN] = {  0,  1,  2,  3,  4, 5,   6 };
static uint8_t di_buf_2[DGST_LEN] = {  7,  8,  9, 10, 11, 12, 13 };
static uint8_t di_buf_3[DGST_LEN] = { 14, 15, 16, 17, 18, 19, 20 };
static char *output_str;
#define di_1_str "00010203040506=sid_1\r\n"
#define di_2_str "0708090a0b0c0d=sid_2\r\n"
#define di_3_str "0e0f1011121314=sid_3\r\n"

#define EXPECTED_DGST_MSG \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: digest\r\n" \
	"JAL-Count: 3\r\n\r\n" \
	di_1_str \
	di_2_str \
	di_3_str

axlList *dgst_list;
void setup()
{
	replace_function(vortex_frame_mime_header_content, fake_get_mime_content);
	di_1 = jaln_digest_info_create("sid_1", di_buf_1, DGST_LEN);
	di_2 = jaln_digest_info_create("sid_2", di_buf_2, DGST_LEN);
	di_3 = jaln_digest_info_create("sid_3", di_buf_3, DGST_LEN);
	output_str = jal_calloc(strlen(di_1_str) + 1, sizeof(char));
	dgst_list = axl_list_new(jaln_axl_equals_func_digest_info_serial_id, jaln_axl_destroy_digest_info);
	axl_list_append(dgst_list, di_1);
	axl_list_append(dgst_list, di_2);
	axl_list_append(dgst_list, di_3);
}

void teardown()
{
	restore_function(vortex_frame_get_mime_header);
	restore_function(vortex_frame_mime_header_content);
	free(output_str);
	axl_list_free(dgst_list);
}

void test_create_journal_resume_msg_with_valid_parameters()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialID";
	uint64_t offset = 1;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);
	assert_equals(JAL_OK, ret);
	free(msg_out);
}

void test_create_journal_resume_msg_with_valid_parameters_is_formatted_correctly()
{
	enum jal_status ret = JAL_OK;

	char *correct_msg = "Content-Type: application/beep+jalop\r\nContent-Transfer-Encoding: binary\r\nJAL-Message: journal-resume\r\nJAL-Serial-Id: 1234562\r\nJAL-Journal-Offset: 47996\r\n\r\n";

	char *serial_id = "1234562";
	uint64_t offset = 47996;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);

	assert_equals(JAL_OK, ret);
	assert_string_equals(correct_msg, msg_out);
	free(msg_out);
}

void test_create_journal_resume_msg_with_invalid_parameters_serial_id_is_null()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = NULL;
	uint64_t offset = 1;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);
	free(msg_out);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_invalid_parameters_msg_out_not_null()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialid";
	uint64_t offset = 1;
	char *msg_out = "some text!";
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_invalid_parameters_msg_out_len_is_null()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialid";
	uint64_t offset = 1;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);
	free(msg_out);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_invalid_parameters_offset_is_zero()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialid";
	uint64_t offset = 0;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);
	free(msg_out);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_valid_parameters_offset_is_very_large()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "1234562";
	uint64_t offset = UINT64_MAX;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);

	assert_equals(JAL_OK, ret);

	// Code below parses the offset string back out of the journal-resume message.
	// Format assumptions come from the JALoP Specification v1.0 document
	// 	Expects "JAL-Journal-Offset: ###..#\r\n"
	// 	Where # is a digit 0-9
	char *journal_offset = strstr(msg_out, "JAL-Journal-Offset");

	strtok(journal_offset, ":");

	char *offset_string = strtok(NULL, " ");
	char *final_offset_string = NULL;
	char *beg = NULL;
	beg = offset_string;

	while (*beg != '\0') {
		if (*beg == '\r' || *beg == '\n') {
			char *tmp = beg;
			*beg = '\0';
			final_offset_string = strdup(offset_string);
			*beg = *tmp;
			break;
		}
		beg++;
	}
	assert_equals(offset, strtoull(final_offset_string, NULL, 10));
	free(msg_out);
	free(final_offset_string);
}

void test_create_sync_msg_works()
{
	char *msg_out = NULL;
	size_t len;
	assert_equals(JAL_OK, jaln_create_sync_msg(sid_1_str, &msg_out, &len));
	assert_equals(strlen(EXPECTED_SYNC_MSG) + 1, len);
	assert_equals(0, memcmp(EXPECTED_SYNC_MSG, msg_out, len));
	free(msg_out);
}

void test_create_sync_msg_does_not_crash_on_bad_input()
{
	char *msg_out = NULL;
	size_t len;
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(NULL, &msg_out, &len));
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(sid_1_str, NULL, &len));
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(sid_1_str, &msg_out, NULL));
	msg_out = (char*)0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(sid_1_str, &msg_out, &len));
}

void test_create_subscribe_msg_with_valid_parameters()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialID";
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_subscribe_msg(serial_id, &msg_out, msg_out_len);
	free(msg_out);
	assert_equals(JAL_OK, ret);
}

void test_create_subscribe_msg_with_valid_parameters_is_formatted_correctly()
{
	enum jal_status ret = JAL_OK;

	char *correct_msg = "Content-Type: application/beep+jalop\r\nContent-Transfer-Encoding: binary\r\nJAL-Message: subscribe\r\nJAL-Serial-Id: 1234562\r\n\r\n";

	char *serial_id = "1234562";
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_subscribe_msg(serial_id, &msg_out, msg_out_len);

	assert_equals(JAL_OK, ret);
	assert_string_equals(correct_msg, msg_out);
	free(msg_out);
}

void test_create_subscribe_msg_with_invalid_parameters_serial_id_is_null()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = NULL;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_subscribe_msg(serial_id, &msg_out, msg_out_len);
	free(msg_out);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_subscribe_msg_with_invalid_parameters_msg_out_not_null()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialid";
	char *msg_out = "some text!";
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_subscribe_msg(serial_id, &msg_out, msg_out_len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_subscribe_msg_with_invalid_parameters_msg_out_len_is_null()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialid";
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;

	ret = jaln_create_subscribe_msg(serial_id, &msg_out, msg_out_len);
	free(msg_out);
	assert_equals(JAL_E_INVAL, ret);
}


void test_check_ct_and_txf_encoding_are_valid_returns_success_with_correct_ct_and_txf_enc()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	assert_true(jaln_check_content_type_and_txfr_encoding_are_valid((VortexFrame*)0xbadf00d));
}

void test_check_ct_and_txf_encoding_are_valid_returns_failure_when_missing_content_type()
{
	replace_function(vortex_frame_get_mime_header, only_enc_get_mime_header);
	assert_false(jaln_check_content_type_and_txfr_encoding_are_valid((VortexFrame*)0xbadf00d));
}

void test_check_ct_and_txf_encoding_are_valid_returns_failure_with_incorrect_content_type()
{
	replace_function(vortex_frame_get_mime_header, wrong_content_type_get_mime_header);
	assert_false(jaln_check_content_type_and_txfr_encoding_are_valid((VortexFrame*)0xbadf00d));
}

void test_check_ct_and_txf_encoding_are_valid_returns_failure_with_incorrect_encoding()
{
	replace_function(vortex_frame_get_mime_header, wrong_encoding_get_mime_header);
	assert_false(jaln_check_content_type_and_txfr_encoding_are_valid((VortexFrame*)0xbadf00d));
}

void test_check_ct_and_txf_encoding_are_valid_returns_success_when_missing_transfer_encoding()
{
	replace_function(vortex_frame_get_mime_header, only_content_type_get_mime_header);
	assert_true(jaln_check_content_type_and_txfr_encoding_are_valid((VortexFrame*)0xbadf00d));
}

void test_check_ct_and_txf_encoding_are_valid_returns_failure_on_null()
{
	assert_false(jaln_check_content_type_and_txfr_encoding_are_valid(NULL));
}

void test_digest_info_strlen_works_for_valid_input()
{
	size_t len = jaln_digest_info_strlen(di_1);
	assert_equals(strlen(di_1_str), len);
}

void test_digest_info_strlen_returns_0_when_missing_sid()
{
	free(di_1->serial_id);
	di_1->serial_id = NULL;
	size_t len = jaln_digest_info_strlen(di_1);
	assert_equals(0, len);
}

void test_digest_info_strlen_fails_for_zero_length_sid()
{
	free(di_1->serial_id);
	di_1->serial_id = jal_strdup("");;
	size_t len = jaln_digest_info_strlen(di_1);
	assert_equals(0, len);
}

void test_digest_info_strlen_returns_0_when_missing_digest()
{
	free(di_1->digest);
	di_1->digest = NULL;
	size_t len = jaln_digest_info_strlen(di_1);
	assert_equals(0, len);
}

void test_digest_info_strlen_returns_0_when_digest_len_is_0()
{
	di_1->digest_len = 0;
	size_t len = jaln_digest_info_strlen(di_1);
	assert_equals(0, len);
}

void test_digest_info_strcat_works_for_good_info()
{
	char *ret = jaln_digest_info_strcat(output_str, di_1);
	assert_string_equals(di_1_str, output_str);
	assert_pointer_equals(output_str, ret);
}

void test_digest_info_strcat_returns_null_with_null_string()
{
	char *ret = jaln_digest_info_strcat(NULL, di_1);
	assert_pointer_equals((void*)NULL, ret);
}

void test_digest_info_strcat_returns_null_for_null_digest_info()
{
	char *ret = jaln_digest_info_strcat(output_str, NULL);
	assert_pointer_equals((void*)NULL, ret);
}


void test_digest_info_strcat_returns_null_for_bad_digest_info()
{
	free(di_1->serial_id);
	di_1->serial_id = NULL;

	char *ret = jaln_digest_info_strcat(output_str, di_1);
	assert_pointer_equals((void*)NULL, ret);
}

void test_create_digest_message_works()
{
	char *msg_out = NULL;
	size_t msg_out_len = 0;
	assert_equals(JAL_OK, jaln_create_digest_msg(dgst_list, &msg_out, &msg_out_len));

	assert_equals(0, strcmp(EXPECTED_DGST_MSG, msg_out));
	assert_equals(strlen(EXPECTED_DGST_MSG) + 1, msg_out_len);
	free(msg_out);
}

void test_create_returns_error_with_bad_input()
{
	char *msg_out = NULL;
	size_t msg_out_len = 0;
	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(NULL, &msg_out, &msg_out_len));

	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(dgst_list, NULL, &msg_out_len));

	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(dgst_list, &msg_out, NULL));

	msg_out = (char*) 0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(dgst_list, &msg_out, &msg_out_len));

}

void test_create_returns_error_with_bad_digest_list()
{
	char *msg_out = NULL;
	size_t msg_out_len = 0;

	axlList *empty_list = axl_list_new(jaln_axl_equals_func_digest_info_serial_id, jaln_axl_destroy_digest_info);
	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(empty_list, &msg_out, &msg_out_len));
	axl_list_free(empty_list);

}

void test_create_returns_error_with_bad_digest_info()
{
	char *msg_out = NULL;
	size_t msg_out_len = 0;

	axl_list_append(dgst_list, NULL);
	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(dgst_list, &msg_out, &msg_out_len));

}

void test_safe_add_does_not_crash()
{
	assert_false(jaln_safe_add_size(NULL, 1));
}
void test_safe_add_prevents_overflow()
{
	size_t cnt = SIZE_MAX - 100;
	assert_false(jaln_safe_add_size(&cnt, 101));
	assert_equals(SIZE_MAX - 100, cnt);
}

void test_safe_add_works_at_size_max()
{
	size_t cnt = SIZE_MAX - 100;
	assert_true(jaln_safe_add_size(&cnt, 100));
	assert_equals(SIZE_MAX, cnt);
}

void test_safe_add_works()
{
	size_t cnt = 12;
	assert_true(jaln_safe_add_size(&cnt, 43));
	assert_equals(12 + 43, cnt);
}

