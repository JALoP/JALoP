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

#include "jaln_digest.c"
#include "jaln_digest_info.h"
#include "jaln_digest_resp_info.h"
#include "jaln_encoding.c"
#include "jaln_message_helpers.h"
#include "jaln_record_info.h"

#define sid_1_str "sid_1"

#define EXPECTED_SYNC_MSG \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n" \
	"JAL-Message: sync\r\n" \
	"JAL-Serial-Id: " sid_1_str "\r\n\r\n"

#define EXPECTED_NACK_UNSUPP_VERSION \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unsupported-Version: \r\n\r\n"

#define EXPECTED_NACK_UNSUPP_ENC \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unsupported-Encoding: \r\n\r\n"

#define EXPECTED_NACK_UNSUPP_DIGEST \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unsupported-Digest: \r\n\r\n"

#define EXPECTED_NACK_UNSUPP_MODE \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unsupported-Mode: \r\n\r\n"

#define EXPECTED_NACK_UNAUTH_MODE \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unauthorized-Mode: \r\n\r\n"

#define EXPECTED_NACK_ALL_ERRORS \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unsupported-Version: \r\n" \
	"JAL-Unsupported-Encoding: \r\n" \
	"JAL-Unsupported-Digest: \r\n" \
	"JAL-Unsupported-Mode: \r\n" \
	"JAL-Unauthorized-Mode: \r\n\r\n"

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

static struct jaln_digest_resp_info *dr_1;
static struct jaln_digest_resp_info *dr_2;
static struct jaln_digest_resp_info *dr_3;

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

#define INIT_PUB_LOG \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Mode: publish\r\n" \
	"JAL-Data-Class: log\r\n" \
	"JAL-Accept-Digest: sha256, sha512\r\n" \
	"JAL-Accept-Encoding: xml_enc_1, xml_enc_2\r\n\r\n"

#define INIT_SUB_LOG \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Mode: subscribe\r\n" \
	"JAL-Data-Class: log\r\n" \
	"JAL-Accept-Digest: sha256, sha512\r\n" \
	"JAL-Accept-Encoding: xml_enc_1, xml_enc_2\r\n\r\n"

#define INIT_SUB_JOURNAL \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Mode: subscribe\r\n" \
	"JAL-Data-Class: journal\r\n" \
	"JAL-Accept-Digest: sha256, sha512\r\n" \
	"JAL-Accept-Encoding: xml_enc_1, xml_enc_2\r\n\r\n"

#define INIT_SUB_AUDIT \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Mode: subscribe\r\n" \
	"JAL-Data-Class: audit\r\n" \
	"JAL-Accept-Digest: sha256, sha512\r\n" \
	"JAL-Accept-Encoding: xml_enc_1, xml_enc_2\r\n\r\n"

#define INIT_SUB_LOG_NO_ENC \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Mode: subscribe\r\n" \
	"JAL-Data-Class: log\r\n" \
	"JAL-Accept-Digest: sha256, sha512\r\n\r\n" \

#define INIT_SUB_LOG_NO_DGST \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Mode: subscribe\r\n" \
	"JAL-Data-Class: log\r\n" \
	"JAL-Accept-Encoding: xml_enc_1, xml_enc_2\r\n\r\n"

#define EXPECTED_JOURNAL_REC_HDRS \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: journal-record\r\n" \
	"JAL-Serial-Id: " sid_1_str "\r\n" \
	"JAL-System-Metadata-Length: 10\r\n" \
	"JAL-Application-Metadata-Length: 20\r\n" \
	"JAL-Journal-Length: 30\r\n\r\n"

#define EXPECTED_AUDIT_REC_HDRS \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: audit-record\r\n" \
	"JAL-Serial-Id: " sid_1_str "\r\n" \
	"JAL-System-Metadata-Length: 10\r\n" \
	"JAL-Application-Metadata-Length: 20\r\n" \
	"JAL-Audit-Length: 30\r\n\r\n"

#define EXPECTED_LOG_REC_HDRS \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: log-record\r\n" \
	"JAL-Serial-Id: " sid_1_str "\r\n" \
	"JAL-System-Metadata-Length: 10\r\n" \
	"JAL-Application-Metadata-Length: 20\r\n" \
	"JAL-Log-Length: 30\r\n\r\n"

#define EXPECTED_DGST_RESP_MSG \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n"\
	"JAL-Message: digest-response\r\n" \
	"JAL-Count: 3\r\n\r\n" \
	dr_1_str \
	dr_2_str \
	dr_3_str

#define dr_1_str "confirmed=sid_1\r\n"
#define dr_2_str "invalid=sid_2\r\n"
#define dr_3_str "unknown=sid_3\r\n"

static struct jaln_record_info *rec_info;

axlList *dgst_list;
axlList *dgst_algs;
axlList *xml_encs;
axlList *dgst_resp_list;

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

	dgst_algs = axl_list_new(jaln_digest_list_equal_func, jaln_digest_list_destroy);
	struct jal_digest_ctx *dc_1 = jal_sha256_ctx_create();
	free(dc_1->algorithm_uri);
	dc_1->algorithm_uri = strdup("sha256");

	struct jal_digest_ctx *dc_2 = jal_sha256_ctx_create();
	free(dc_2->algorithm_uri);
	dc_2->algorithm_uri = strdup("sha512");

	axl_list_append(dgst_algs, dc_1);
	axl_list_append(dgst_algs, dc_2);

	xml_encs = axl_list_new(jaln_string_list_case_insensitive_func, free);
	axl_list_append(xml_encs, strdup("xml_enc_1"));
	axl_list_append(xml_encs, strdup("xml_enc_2"));

	rec_info = jaln_record_info_create();
	rec_info->type = JALN_RTYPE_LOG;
	rec_info->serial_id = jal_strdup(sid_1_str);

	rec_info->sys_meta_len = 10;
	rec_info->app_meta_len = 20;
	rec_info->payload_len = 30;

	dr_1 = jaln_digest_resp_info_create("sid_1", JALN_DIGEST_STATUS_CONFIRMED);
	dr_2 = jaln_digest_resp_info_create("sid_2", JALN_DIGEST_STATUS_INVALID);
	dr_3 = jaln_digest_resp_info_create("sid_3", JALN_DIGEST_STATUS_UNKNOWN);
	dgst_resp_list = axl_list_new(jaln_axl_equals_func_digest_resp_info_serial_id,
			jaln_axl_destroy_digest_resp_info);
	axl_list_append(dgst_resp_list, dr_1);
	axl_list_append(dgst_resp_list, dr_2);
	axl_list_append(dgst_resp_list, dr_3);
}

void teardown()
{
	restore_function(vortex_frame_get_mime_header);
	restore_function(vortex_frame_mime_header_content);
	free(output_str);
	axl_list_free(dgst_list);
	axl_list_free(dgst_algs);
	axl_list_free(xml_encs);
	axl_list_free(dgst_resp_list);
	jaln_record_info_destroy(&rec_info);
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

void test_create_init_msg_works_for_publish()
{
	char *msg_out = NULL;
	size_t len;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ROLE_PUBLISHER, JALN_RTYPE_LOG,
				dgst_algs, xml_encs, &msg_out, &len));
	assert_equals(strlen(INIT_PUB_LOG) + 1, len);
	assert_equals(0, memcmp(INIT_PUB_LOG, msg_out, len));
	free(msg_out);
}

void test_create_init_msg_works_for_log()
{
	char *msg_out = NULL;
	size_t len;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ROLE_SUBSCRIBER, JALN_RTYPE_LOG,
				dgst_algs, xml_encs, &msg_out, &len));
	assert_equals(strlen(INIT_SUB_LOG) + 1, len);
	assert_equals(0, memcmp(INIT_SUB_LOG, msg_out, len));
	free(msg_out);
}

void test_create_init_msg_works_for_audit()
{
	char *msg_out = NULL;
	size_t len;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ROLE_SUBSCRIBER, JALN_RTYPE_AUDIT,
				dgst_algs, xml_encs, &msg_out, &len));
	assert_equals(strlen(INIT_SUB_AUDIT) + 1, len);
	assert_equals(0, memcmp(INIT_SUB_AUDIT, msg_out, len));
	free(msg_out);
}

void test_create_init_msg_works_for_journal_data()
{
	char *msg_out = NULL;
	size_t len;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ROLE_SUBSCRIBER, JALN_RTYPE_JOURNAL,
				dgst_algs, xml_encs, &msg_out, &len));
	assert_equals(strlen(INIT_SUB_JOURNAL) + 1, len);
	assert_equals(0, memcmp(INIT_SUB_JOURNAL, msg_out, len));
	free(msg_out);
}

void test_create_init_msg_works_with_no_enc()
{
	axlList *empty_list = axl_list_new(jaln_string_list_case_insensitive_func, free);
	char *msg_out = NULL;
	size_t len;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ROLE_SUBSCRIBER, JALN_RTYPE_LOG,
				dgst_algs, empty_list, &msg_out, &len));
	assert_equals(strlen(INIT_SUB_LOG_NO_ENC) + 1, len);
	assert_equals(0, memcmp(INIT_SUB_LOG_NO_ENC, msg_out, len));
	axl_list_free(empty_list);
	free(msg_out);
}

void test_create_init_msg_works_with_no_digests()
{
	axlList *empty_list = axl_list_new(jaln_digest_list_equal_func, jaln_digest_list_destroy);
	char *msg_out = NULL;
	size_t len;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ROLE_SUBSCRIBER, JALN_RTYPE_LOG,
				empty_list, xml_encs, &msg_out, &len));
	assert_equals(strlen(INIT_SUB_LOG_NO_DGST) + 1, len);
	assert_equals(0, memcmp(INIT_SUB_LOG_NO_DGST, msg_out, len));
	axl_list_free(empty_list);
	free(msg_out);
}

void test_create_init_msg_does_not_crash_on_bad_input()
{
	enum jaln_role role = JALN_ROLE_SUBSCRIBER;
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;
	char *msg_out = NULL;
	size_t len;

	assert_equals(JAL_E_INVAL, jaln_create_init_msg(JALN_ROLE_SUBSCRIBER - 1, type, dgst_algs,
							xml_encs, &msg_out, &len));

	assert_equals(JAL_E_INVAL, jaln_create_init_msg(role, JALN_RTYPE_JOURNAL | JALN_RTYPE_AUDIT,
							dgst_algs, xml_encs, &msg_out, &len));

	assert_equals(JAL_E_INVAL, jaln_create_init_msg(role, type, NULL, xml_encs, &msg_out, &len));

	assert_equals(JAL_E_INVAL, jaln_create_init_msg(role, type, dgst_algs, NULL, &msg_out, &len));

	assert_equals(JAL_E_INVAL, jaln_create_init_msg(role, type, dgst_algs, xml_encs, NULL, &len));

	assert_equals(JAL_E_INVAL, jaln_create_init_msg(role, type, dgst_algs, xml_encs, &msg_out, NULL));

	msg_out = (char*) 0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_create_init_msg(role, type, dgst_algs, xml_encs, &msg_out, &len));
}

void test_create_record_ans_rpy_headers_fails_for_invalid_record_info()
{
	char *headers_out = NULL;
	size_t headers_out_len = 0;
	rec_info->type = 0;
	assert_not_equals(JAL_OK, jaln_create_record_ans_rpy_headers(rec_info, &headers_out, &headers_out_len));
}

void test_create_record_ans_rpy_headers_fails_for_bad_input()
{
	char *headers_out = NULL;
	size_t headers_out_len = 0;
	assert_not_equals(JAL_OK, jaln_create_record_ans_rpy_headers(NULL, &headers_out, &headers_out_len));
	assert_not_equals(JAL_OK, jaln_create_record_ans_rpy_headers(rec_info, NULL, &headers_out_len));
	headers_out = (char*) 0xbadf00d;
	assert_not_equals(JAL_OK, jaln_create_record_ans_rpy_headers(rec_info, &headers_out, &headers_out_len));
	headers_out = NULL;
	assert_not_equals(JAL_OK, jaln_create_record_ans_rpy_headers(rec_info, &headers_out, NULL));
}

void test_create_record_ans_rpy_headers_works_for_journal()
{
	char *headers_out = NULL;
	size_t headers_out_len = 0;
	rec_info->type = JALN_RTYPE_JOURNAL;
	assert_equals(JAL_OK, jaln_create_record_ans_rpy_headers(rec_info, &headers_out, &headers_out_len));
	assert_not_equals((void*)NULL, headers_out);
	assert_equals(strlen(EXPECTED_JOURNAL_REC_HDRS), headers_out_len);
	assert_equals(0, memcmp(EXPECTED_JOURNAL_REC_HDRS, headers_out, headers_out_len));
	free(headers_out);
}

void test_create_record_ans_rpy_headers_works_for_audit()
{
	char *headers_out = NULL;
	size_t headers_out_len = 0;
	rec_info->type = JALN_RTYPE_AUDIT;
	assert_equals(JAL_OK, jaln_create_record_ans_rpy_headers(rec_info, &headers_out, &headers_out_len));
	assert_not_equals((void*)NULL, headers_out);
	assert_equals(strlen(EXPECTED_AUDIT_REC_HDRS), headers_out_len);
	assert_equals(0, memcmp(EXPECTED_AUDIT_REC_HDRS, headers_out, headers_out_len));
	free(headers_out);
}

void test_create_record_ans_rpy_headers_works_for_log()
{
	char *headers_out = NULL;
	size_t headers_out_len = 0;
	rec_info->type = JALN_RTYPE_LOG;
	assert_equals(JAL_OK, jaln_create_record_ans_rpy_headers(rec_info, &headers_out, &headers_out_len));
	assert_not_equals((void*)NULL, headers_out);
	assert_equals(strlen(EXPECTED_LOG_REC_HDRS), headers_out_len);
	assert_equals(0, memcmp(EXPECTED_LOG_REC_HDRS, headers_out, headers_out_len));
	free(headers_out);
}

void test_digest_resp_info_strlen_works_for_valid_input()
{
	size_t len = jaln_digest_resp_info_strlen(dr_1);
	assert_equals(strlen(dr_1_str), len);

	len = jaln_digest_resp_info_strlen(dr_2);
	assert_equals(strlen(dr_2_str), len);

	len = jaln_digest_resp_info_strlen(dr_3);
	assert_equals(strlen(dr_3_str), len);
}

void test_digest_resp_info_strlen_returns_0_when_missing_sid()
{
	free(dr_1->serial_id);
	dr_1->serial_id = NULL;
	size_t len = jaln_digest_resp_info_strlen(dr_1);
	assert_equals(0, len);
}

void test_digest_resp_info_strlen_returns_0_when_sid_is_emtpy()
{
	free(dr_1->serial_id);
	dr_1->serial_id = jal_strdup("");
	size_t len = jaln_digest_resp_info_strlen(dr_1);
	assert_equals(0, len);
}

void test_digest_resp_info_strlen_returns_0_with_bad_status()
{
	dr_1->status = JALN_DIGEST_STATUS_UNKNOWN + 1;;
	size_t len = jaln_digest_resp_info_strlen(dr_1);
	assert_equals(0, len);
}

void test_digest_resp_info_strcat_works_for_good_confirmed()
{
	char *ret = jaln_digest_resp_info_strcat(output_str, dr_1);
	assert_string_equals(dr_1_str, output_str);
	assert_pointer_equals(output_str, ret);
}

void test_digest_resp_info_strcat_works_for_good_invalid()
{
	char *ret = jaln_digest_resp_info_strcat(output_str, dr_2);
	assert_string_equals(dr_2_str, output_str);
	assert_pointer_equals(output_str, ret);
}

void test_digest_resp_info_strcat_works_for_good_unknown()
{
	char *ret = jaln_digest_resp_info_strcat(output_str, dr_3);
	assert_string_equals(dr_3_str, output_str);
	assert_pointer_equals(output_str, ret);
}

void test_digest_resp_info_strcat_returns_null_with_null_string()
{
	char *ret = jaln_digest_resp_info_strcat(NULL, dr_1);
	assert_pointer_equals((void*)NULL, ret);
}

void test_digest_resp_info_strcat_returns_null_for_null_digest_resp_info()
{
	char *ret = jaln_digest_resp_info_strcat(output_str, NULL);
	assert_pointer_equals((void*)NULL, ret);
}

void test_digest_resp_info_strcat_returns_null_for_bad_digest_resp_info()
{
	free(dr_1->serial_id);
	dr_1->serial_id = NULL;

	char *ret = jaln_digest_resp_info_strcat(output_str, dr_1);
	assert_pointer_equals((void*)NULL, ret);
}

void test_create_digest_resp_message_works()
{
	char *msg_out = NULL;
	size_t msg_out_len = 0;
	assert_equals(JAL_OK, jaln_create_digest_response_msg(dgst_resp_list, &msg_out, &msg_out_len));

	assert_equals(0, strcmp(EXPECTED_DGST_RESP_MSG, msg_out));
	assert_equals(strlen(EXPECTED_DGST_RESP_MSG) + 1, msg_out_len);
	free(msg_out);
}

void test_create_digest_resp_returns_error_with_bad_input()
{
	char *msg_out = NULL;
	size_t msg_out_len = 0;
	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(NULL, &msg_out, &msg_out_len));

	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(dgst_resp_list, NULL, &msg_out_len));

	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(dgst_resp_list, &msg_out, NULL));

	msg_out = (char*) 0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(dgst_resp_list, &msg_out, &msg_out_len));

}

void test_create_digest_resp_returns_error_with_bad_digest_list()
{
	char *msg_out = NULL;
	size_t msg_out_len = 0;

	axlList *empty_list = axl_list_new(jaln_axl_equals_func_digest_resp_info_serial_id, jaln_axl_destroy_digest_resp_info);
	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(empty_list, &msg_out, &msg_out_len));
	axl_list_free(empty_list);

}

void test_create_digest_resp_returns_error_with_bad_digest_info()
{
	char *msg_out = NULL;
	size_t msg_out_len = 0;

	axl_list_append(dgst_resp_list, NULL);
	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(dgst_resp_list, &msg_out, &msg_out_len));
}

void test_create_init_nack_msg_works_for_unsupported_version()
{
	char *msg_out = NULL;
	size_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_VERSION, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_UNSUPP_VERSION), len);
	assert_equals(0, memcmp(EXPECTED_NACK_UNSUPP_VERSION, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_works_for_unsupported_encoding()
{
	char *msg_out = NULL;
	size_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_ENCODING, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_UNSUPP_ENC), len);
	assert_equals(0, memcmp(EXPECTED_NACK_UNSUPP_ENC, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_works_for_unsupported_digest()
{
	char *msg_out = NULL;
	size_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_DIGEST, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_UNSUPP_DIGEST), len);
	assert_equals(0, memcmp(EXPECTED_NACK_UNSUPP_DIGEST, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_works_for_unsupported_mode()
{
	char *msg_out = NULL;
	size_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_MODE, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_UNSUPP_MODE), len);
	assert_equals(0, memcmp(EXPECTED_NACK_UNSUPP_MODE, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_works_with_all_errors()
{
	char *msg_out = NULL;
	size_t len = 0;
	enum jaln_connect_error errs =
			JALN_CE_UNSUPPORTED_VERSION   |
			JALN_CE_UNSUPPORTED_ENCODING  |
			JALN_CE_UNSUPPORTED_DIGEST    |
			JALN_CE_UNSUPPORTED_MODE      |
			JALN_CE_UNAUTHORIZED_MODE;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(errs, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_ALL_ERRORS), len);
	assert_equals(0, memcmp(EXPECTED_NACK_ALL_ERRORS, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_works_for_unauth_mode()
{
	char *msg_out = NULL;
	size_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(JALN_CE_UNAUTHORIZED_MODE, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_UNAUTH_MODE), len);
	assert_equals(0, memcmp(EXPECTED_NACK_UNAUTH_MODE, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_fails_if_no_err_specified()
{
	char *msg_out = NULL;
	size_t len = 0;
	assert_equals(JAL_E_INVAL, jaln_create_init_nack_msg(JALN_CE_ACCEPT, &msg_out, &len));
}

void test_create_init_nack_msg_does_not_crash_on_bad_input()
{
	char *msg_out = NULL;
	size_t len = 0;
	assert_equals(JAL_E_INVAL, jaln_create_init_nack_msg(1 << 5, &msg_out, &len));

	msg_out = NULL;
	assert_equals(JAL_E_INVAL, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_VERSION, NULL, &len));

	msg_out = NULL;
	assert_equals(JAL_E_INVAL, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_VERSION, &msg_out, NULL));

	msg_out = (char*) 0xbadf00d;;
	assert_equals(JAL_E_INVAL, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_VERSION, &msg_out, &len));
}

