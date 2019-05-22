/**
 * @file test_jaln_message_helpers.c This file contains tests for jaln_message_helpers.c functions.
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <test-dept.h>
#include <vortex.h>
#include <curl/curl.h>

#include "jal_alloc.h"

#include "jaln_channel_info.h"
#include "jaln_context.h"
#include "jaln_digest.c"
#include "jaln_digest_info.h"
#include "jaln_digest_resp_info.h"
#include "jaln_encoding.c"
#include "jaln_message_helpers.h"
#include "jaln_record_info.h"
#include "jaln_session.h"

#define BAD_PTR(_t) (_t *)0xdeadbeef

#define nonce_1_str "nonce_1"

#define DC_HEADER_PREFIX "JAL-Accept-Configure-Digest-Challenge: "

#define EXPECTED_SYNC_MSG \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n" \
	"JAL-Message: sync\r\n" \
	"JAL-Id: " nonce_1_str "\r\n\r\n"

#define EXPECTED_NACK_UNSUPP_VERSION \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unsupported-Version: \r\n\r\n"

#define EXPECTED_NACK_UNSUPP_ENC \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unsupported-XML-Compression: \r\n\r\n"

#define EXPECTED_NACK_UNSUPP_DIGEST \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unsupported-Digest: \r\n\r\n"

#define EXPECTED_NACK_UNSUPP_MODE \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unsupported-Mode: \r\n\r\n"

#define EXPECTED_NACK_UNAUTH_MODE \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unauthorized-Mode: \r\n\r\n"

#define EXPECTED_NACK_ALL_ERRORS \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n" \
	"JAL-Message: initialize-nack\r\n" \
	"JAL-Unsupported-Version: \r\n" \
	"JAL-Unsupported-XML-Compression: \r\n" \
	"JAL-Unsupported-Digest: \r\n" \
	"JAL-Unsupported-Mode: \r\n" \
	"JAL-Unauthorized-Mode: \r\n\r\n"

#define SOME_ENCODING "an_encoding"
#define SOME_DIGEST "a_digest"
#define EXPECTED_ACK\
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n" \
	"JAL-Message: initialize-ack\r\n" \
	"JAL-XML-Compression: " SOME_ENCODING "\r\n" \
	"JAL-Digest: " SOME_DIGEST "\r\n\r\n" \

#define SAMPLE_UUID "abcdabcd-abcd-abcd-abcd-abcdabcdabcd"
#define SAMPLE_RECORD_ID JALN_HDRS_ID JALN_COLON_SPACE SAMPLE_UUID "\r\n"
#define SAMPLE_OFFSET_VAL 512
#define SAMPLE_OFFSET_VAL_STR "512"
#define SAMPLE_OFFSET JALN_HDRS_JOURNAL_OFFSET JALN_COLON_SPACE SAMPLE_OFFSET_VAL_STR "\r\n"
#define SAMPLE_JOURNAL_MISSING_RESP_MSG JALN_HDRS_MESSAGE JALN_COLON_SPACE JALN_MSG_JOURNAL_MISSING_RESPONSE "\r\n"
#define SAMPLE_INIT_ACK_MSG JALN_HDRS_MESSAGE JALN_COLON_SPACE JALN_MSG_INIT_ACK "\r\n"
#define SAMPLE_DGST_CHAL_MSG JALN_HDRS_MESSAGE JALN_COLON_SPACE JALN_MSG_DIGEST_CHALLENGE "\r\n"
#define SAMPLE_DGST_VAL_MSG JALN_HDRS_DIGEST_VALUE JALN_COLON_SPACE SOME_DIGEST "\r\n"

VortexMimeHeader *wrong_encoding_get_mime_header(VortexFrame *frame, const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (strcasecmp(header_name, "content-type") == 0) {
		return (VortexMimeHeader*) "application/http+jalop";
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
		return (VortexMimeHeader*) "application/http+jalop";
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
		return (VortexMimeHeader*) "application/http+jalop";
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
#define di_1_str "00010203040506=nonce_1\r\n"
#define di_2_str "0708090a0b0c0d=nonce_2\r\n"
#define di_3_str "0e0f1011121314=nonce_3\r\n"

#define EXPECTED_DGST_MSG \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n"\
	"JAL-Message: digest\r\n" \
	"JAL-Count: 3\r\n\r\n" \
	di_1_str \
	di_2_str \
	di_3_str

#define INIT_PUB_LOG_ARCHIVE \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Publisher-Id: " SAMPLE_UUID "\r\n" \
	"JAL-Mode: archival\r\n" \
	"JAL-Record-Type: log\r\n" \
	"JAL-Accept-Digest: sha256, sha512\r\n" \
	"JAL-Accept-XML-Compression: xml_enc_1, xml_enc_2\r\n\r\n"

#define INIT_PUB_JOURNAL_ARCHIVE \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Publisher-Id: " SAMPLE_UUID "\r\n" \
	"JAL-Mode: archival\r\n" \
	"JAL-Record-Type: journal\r\n" \
	"JAL-Accept-Digest: sha256, sha512\r\n" \
	"JAL-Accept-XML-Compression: xml_enc_1, xml_enc_2\r\n\r\n"

#define INIT_PUB_AUDIT_ARCHIVE \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Publisher-Id: " SAMPLE_UUID "\r\n" \
	"JAL-Mode: archival\r\n" \
	"JAL-Record-Type: audit\r\n" \
	"JAL-Accept-Digest: sha256, sha512\r\n" \
	"JAL-Accept-XML-Compression: xml_enc_1, xml_enc_2\r\n\r\n"

#define INIT_PUB_LOG_ARCHIVE_NO_ENC \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Publisher-Id: " SAMPLE_UUID "\r\n" \
	"JAL-Mode: archival\r\n" \
	"JAL-Record-Type: log\r\n" \
	"JAL-Accept-Digest: sha256, sha512\r\n\r\n" \

#define INIT_PUB_LOG_ARCHIVE_NO_DGST \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n"\
	"JAL-Message: initialize\r\n" \
	"JAL-Publisher-Id: " SAMPLE_UUID "\r\n" \
	"JAL-Mode: archival\r\n" \
	"JAL-Record-Type: log\r\n" \
	"JAL-Accept-XML-Compression: xml_enc_1, xml_enc_2\r\n\r\n"

#define EXPECTED_JOURNAL_REC_HDRS \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n"\
	"JAL-Message: journal-record\r\n" \
	"JAL-Id: " nonce_1_str "\r\n" \
	"JAL-System-Metadata-Length: 10\r\n" \
	"JAL-Application-Metadata-Length: 20\r\n" \
	"JAL-Journal-Length: 30\r\n\r\n"

#define EXPECTED_AUDIT_REC_HDRS \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n"\
	"JAL-Message: audit-record\r\n" \
	"JAL-Id: " nonce_1_str "\r\n" \
	"JAL-System-Metadata-Length: 10\r\n" \
	"JAL-Application-Metadata-Length: 20\r\n" \
	"JAL-Audit-Length: 30\r\n\r\n"

#define EXPECTED_LOG_REC_HDRS \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n"\
	"JAL-Message: log-record\r\n" \
	"JAL-Id: " nonce_1_str "\r\n" \
	"JAL-System-Metadata-Length: 10\r\n" \
	"JAL-Application-Metadata-Length: 20\r\n" \
	"JAL-Log-Length: 30\r\n\r\n"

#define EXPECTED_DGST_RESP_MSG \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Version: 2.0.0.0\r\n"\
	"JAL-Message: digest-response\r\n" \
	"JAL-Count: 3\r\n\r\n" \
	dr_1_str \
	dr_2_str \
	dr_3_str

#define EXPECTED_JOURNAL_MISSING_MSG \
	"Content-Type: application/http+jalop\r\n" \
	"JAL-Message: journal-missing\r\n" \
	"JAL-Session-Id: id\r\n" \
	"JAL-Id: " nonce_1_str "\r\n\r\n"

#define dr_1_str "confirmed=nonce_1\r\n"
#define dr_2_str "invalid=nonce_2\r\n"
#define dr_3_str "unknown=nonce_3\r\n"

static struct jaln_record_info *rec_info;

axlList *dgst_list;
axlList *dgst_algs;
axlList *xml_encs;
axlList *dgst_resp_list;
jaln_context ctx;
jaln_session *sess;
struct jaln_response_header_info *info;

void setup()
{
	replace_function(vortex_frame_mime_header_content, fake_get_mime_content);
	di_1 = jaln_digest_info_create("nonce_1", di_buf_1, DGST_LEN);
	di_2 = jaln_digest_info_create("nonce_2", di_buf_2, DGST_LEN);
	di_3 = jaln_digest_info_create("nonce_3", di_buf_3, DGST_LEN);
	output_str = jal_calloc(strlen(di_1_str) + 1, sizeof(char));
	dgst_list = axl_list_new(jaln_axl_equals_func_digest_info_nonce, jaln_axl_destroy_digest_info);
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
	rec_info->nonce = jal_strdup(nonce_1_str);

	rec_info->sys_meta_len = 10;
	rec_info->app_meta_len = 20;
	rec_info->payload_len = 30;

	dr_1 = jaln_digest_resp_info_create("nonce_1", JALN_DIGEST_STATUS_CONFIRMED);
	dr_2 = jaln_digest_resp_info_create("nonce_2", JALN_DIGEST_STATUS_INVALID);
	dr_3 = jaln_digest_resp_info_create("nonce_3", JALN_DIGEST_STATUS_UNKNOWN);
	dgst_resp_list = axl_list_new(jaln_axl_equals_func_digest_resp_info_nonce,
			jaln_axl_destroy_digest_resp_info);
	axl_list_append(dgst_resp_list, dr_1);
	axl_list_append(dgst_resp_list, dr_2);
	axl_list_append(dgst_resp_list, dr_3);
	ctx.dgst_algs = dgst_algs;
	ctx.xml_encodings = xml_encs;
	strcpy(ctx.pub_id, SAMPLE_UUID);

	sess = jaln_session_create();
	sess->jaln_ctx = &ctx;
	info = jaln_response_header_info_create(sess);
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
	ctx.dgst_algs = NULL;
	ctx.xml_encodings = NULL;
	sess->jaln_ctx = NULL;
	jaln_session_destroy(&sess);
	jaln_response_header_info_destroy(&info);
}

static char *flatten_headers(struct curl_slist *list)
{
	const char *separator = "\r\n";
	const size_t sep_len = strlen(separator);
	char *flat = NULL;
	size_t flat_size = 0, flat_len = 0, new_len;
	size_t data_len;
	while (list) {
		data_len = strlen(list->data);
		new_len = flat_len + data_len + sep_len;
		if (new_len >= flat_size) {
			flat_size = new_len * 2;
			flat = realloc(flat, flat_size);
			if (!flat)
				return NULL;
		}
		strcpy(flat + flat_len, list->data);
		strcpy(flat + flat_len + data_len, separator);
		flat_len = new_len;
		list = list->next;
	}
	flat = realloc(flat, flat_len + sep_len + 1);
	strcpy(flat + flat_len, separator);
	return flat;
}

static int find_in_headers(struct curl_slist *list, const char *header)
{
	while (list) {
		if (!strcmp(list->data, header)) {
			return 1;
		}
		list = list->next;
	}
	return 0;
}

void test_create_journal_resume_msg_with_valid_parameters()
{
	enum jal_status ret = JAL_OK;

	char *nonce = "nonce";
	uint64_t offset = 1;
	char *msg_out = NULL;
	uint64_t *msg_out_len = NULL;
	uint64_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(nonce, offset, &msg_out, msg_out_len);
	assert_equals(JAL_OK, ret);
	free(msg_out);
}

void test_create_journal_resume_msg_with_valid_parameters_is_formatted_correctly()
{
	enum jal_status ret = JAL_OK;

	char *correct_msg = "Content-Type: application/http+jalop\r\nJAL-Version: 2.0.0.0\r\nJAL-Message: journal-resume\r\nJAL-Id: 1234562\r\nJAL-Journal-Offset: 47996\r\n\r\n";

	char *nonce = "1234562";
	uint64_t offset = 47996;
	char *msg_out = NULL;
	uint64_t *msg_out_len = NULL;
	uint64_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(nonce, offset, &msg_out, msg_out_len);

	assert_equals(JAL_OK, ret);
	assert_string_equals(correct_msg, msg_out);
	free(msg_out);
}

void test_create_journal_resume_msg_with_invalid_parameters_nonce_is_null()
{
	enum jal_status ret = JAL_OK;

	char *nonce = NULL;
	uint64_t offset = 1;
	char *msg_out = NULL;
	uint64_t *msg_out_len = NULL;
	uint64_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(nonce, offset, &msg_out, msg_out_len);
	free(msg_out);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_invalid_parameters_msg_out_not_null()
{
	enum jal_status ret = JAL_OK;

	char *nonce = "nonce";
	uint64_t offset = 1;
	char *msg_out = "some text!";
	uint64_t *msg_out_len = NULL;
	uint64_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(nonce, offset, &msg_out, msg_out_len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_invalid_parameters_msg_out_len_is_null()
{
	enum jal_status ret = JAL_OK;

	char *nonce = "nonce";
	uint64_t offset = 1;
	char *msg_out = NULL;
	uint64_t *msg_out_len = NULL;

	ret = jaln_create_journal_resume_msg(nonce, offset, &msg_out, msg_out_len);
	free(msg_out);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_invalid_parameters_offset_is_zero()
{
	enum jal_status ret = JAL_OK;

	char *nonce = "nonce";
	uint64_t offset = 0;
	char *msg_out = NULL;
	uint64_t *msg_out_len = NULL;
	uint64_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(nonce, offset, &msg_out, msg_out_len);
	free(msg_out);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_valid_parameters_offset_is_very_large()
{
	enum jal_status ret = JAL_OK;

	char *nonce = "1234562";
	uint64_t offset = UINT64_MAX;
	char *msg_out = NULL;
	uint64_t *msg_out_len = NULL;
	uint64_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(nonce, offset, &msg_out, msg_out_len);

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
	uint64_t len;
	assert_equals(JAL_OK, jaln_create_sync_msg(nonce_1_str, &msg_out, &len));
	assert_equals(strlen(EXPECTED_SYNC_MSG), len);
	assert_equals(0, memcmp(EXPECTED_SYNC_MSG, msg_out, len));
	free(msg_out);
}

void test_create_sync_msg_does_not_crash_on_bad_input()
{
	char *msg_out = NULL;
	uint64_t len;
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(NULL, &msg_out, &len));
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(nonce_1_str, NULL, &len));
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(nonce_1_str, &msg_out, NULL));
	msg_out = (char*)0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(nonce_1_str, &msg_out, &len));
}

void test_create_subscribe_msg_with_valid_parameters()
{
	enum jal_status ret = JAL_OK;

	char *msg_out = NULL;
	uint64_t *msg_out_len = NULL;
	uint64_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_subscribe_msg(&msg_out, msg_out_len);
	free(msg_out);
	assert_equals(JAL_OK, ret);
}

void test_create_subscribe_msg_with_valid_parameters_is_formatted_correctly()
{
	enum jal_status ret = JAL_OK;

	char *correct_msg = "Content-Type: application/http+jalop\r\nJAL-Version: 2.0.0.0\r\nJAL-Message: subscribe\r\n\r\n";

	char *msg_out = NULL;
	uint64_t *msg_out_len = NULL;
	uint64_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_subscribe_msg(&msg_out, msg_out_len);

	assert_equals(JAL_OK, ret);
	assert_string_equals(correct_msg, msg_out);
	free(msg_out);
}

void test_create_subscribe_msg_with_invalid_parameters_msg_out_not_null()
{
	enum jal_status ret = JAL_OK;

	char *msg_out = "some text!";
	uint64_t *msg_out_len = NULL;
	uint64_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_subscribe_msg(&msg_out, msg_out_len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_subscribe_msg_with_invalid_parameters_msg_out_len_is_null()
{
	enum jal_status ret = JAL_OK;

	char *msg_out = NULL;
	uint64_t *msg_out_len = NULL;

	ret = jaln_create_subscribe_msg(&msg_out, msg_out_len);
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
	uint64_t len = jaln_digest_info_strlen(di_1);
	assert_equals(strlen(di_1_str), len);
}

void test_digest_info_strlen_returns_0_when_missing_nonce()
{
	free(di_1->nonce);
	di_1->nonce = NULL;
	uint64_t len = jaln_digest_info_strlen(di_1);
	assert_equals(0, len);
}

void test_digest_info_strlen_fails_for_zero_length_nonce()
{
	free(di_1->nonce);
	di_1->nonce = jal_strdup("");;
	uint64_t len = jaln_digest_info_strlen(di_1);
	assert_equals(0, len);
}

void test_digest_info_strlen_returns_0_when_missing_digest()
{
	free(di_1->digest);
	di_1->digest = NULL;
	uint64_t len = jaln_digest_info_strlen(di_1);
	assert_equals(0, len);
}

void test_digest_info_strlen_returns_0_when_digest_len_is_0()
{
	di_1->digest_len = 0;
	uint64_t len = jaln_digest_info_strlen(di_1);
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
	free(di_1->nonce);
	di_1->nonce = NULL;

	char *ret = jaln_digest_info_strcat(output_str, di_1);
	assert_pointer_equals((void*)NULL, ret);
}

void test_create_digest_message_works()
{
	char *msg_out = NULL;
	uint64_t msg_out_len = 0;
	assert_equals(JAL_OK, jaln_create_digest_msg(dgst_list, &msg_out, &msg_out_len));

	assert_equals(0, strcmp(EXPECTED_DGST_MSG, msg_out));
	assert_equals(strlen(EXPECTED_DGST_MSG), msg_out_len);
	free(msg_out);
}

void test_create_returns_error_with_bad_input()
{
	char *msg_out = NULL;
	uint64_t msg_out_len = 0;
	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(NULL, &msg_out, &msg_out_len));

	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(dgst_list, NULL, &msg_out_len));

	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(dgst_list, &msg_out, NULL));

	msg_out = (char*) 0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(dgst_list, &msg_out, &msg_out_len));

}

void test_create_returns_error_with_bad_digest_list()
{
	char *msg_out = NULL;
	uint64_t msg_out_len = 0;

	axlList *empty_list = axl_list_new(jaln_axl_equals_func_digest_info_nonce, jaln_axl_destroy_digest_info);
	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(empty_list, &msg_out, &msg_out_len));
	axl_list_free(empty_list);

}

void test_create_returns_error_with_bad_digest_info()
{
	char *msg_out = NULL;
	uint64_t msg_out_len = 0;

	axl_list_append(dgst_list, NULL);
	assert_equals(JAL_E_INVAL, jaln_create_digest_msg(dgst_list, &msg_out, &msg_out_len));

}

void test_safe_add_does_not_crash()
{
	assert_false(jaln_safe_add_size(NULL, 1));
}
void test_safe_add_prevents_overflow()
{
	uint64_t cnt = SIZE_MAX - 100;
	assert_false(jaln_safe_add_size(&cnt, 101));
	assert_equals(SIZE_MAX - 100, cnt);
}

void test_safe_add_works_at_size_max()
{
	uint64_t cnt = SIZE_MAX - 100;
	assert_true(jaln_safe_add_size(&cnt, 100));
	assert_equals(SIZE_MAX, cnt);
}

void test_safe_add_works()
{
	uint64_t cnt = 12;
	assert_true(jaln_safe_add_size(&cnt, 43));
	assert_equals(12 + 43, cnt);
}

void test_create_init_msg_works_for_log()
{
	struct curl_slist *headers = NULL;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ARCHIVE_MODE, JALN_RTYPE_LOG,
				&ctx, &headers));
	assert_not_equals(NULL, headers);
	assert_equals(0, strcmp(flatten_headers(headers), INIT_PUB_LOG_ARCHIVE));
	curl_slist_free_all(headers);
}

void test_create_init_msg_works_for_audit()
{
	struct curl_slist *headers = NULL;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ARCHIVE_MODE, JALN_RTYPE_AUDIT,
				&ctx, &headers));
	assert_not_equals(NULL, headers);
	assert_equals(0, strcmp(flatten_headers(headers), INIT_PUB_AUDIT_ARCHIVE));
	curl_slist_free_all(headers);
}

void test_create_init_msg_works_for_journal_data()
{
	struct curl_slist *headers = NULL;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ARCHIVE_MODE, JALN_RTYPE_JOURNAL,
				&ctx, &headers));
	assert_not_equals(NULL, headers);
	assert_equals(0, strcmp(flatten_headers(headers), INIT_PUB_JOURNAL_ARCHIVE));
	curl_slist_free_all(headers);
}

void test_create_init_msg_works_with_no_enc()
{
	axlList *empty_list = axl_list_new(jaln_string_list_case_insensitive_func, free);
	struct curl_slist *headers = NULL;
	ctx.xml_encodings = empty_list;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ARCHIVE_MODE, JALN_RTYPE_LOG,
				&ctx, &headers));
	assert_not_equals(NULL, headers);
	assert_equals(0, strcmp(flatten_headers(headers), INIT_PUB_LOG_ARCHIVE_NO_ENC));
	axl_list_free(empty_list);
	curl_slist_free_all(headers);
}

void test_create_init_msg_works_with_no_digests()
{
	axlList *empty_list = axl_list_new(jaln_digest_list_equal_func, jaln_digest_list_destroy);
	struct curl_slist *headers = NULL;
	ctx.dgst_algs = empty_list;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ARCHIVE_MODE, JALN_RTYPE_LOG,
				&ctx, &headers));
	assert_not_equals(NULL, headers);
	assert_equals(0, strcmp(flatten_headers(headers), INIT_PUB_LOG_ARCHIVE_NO_DGST));
	axl_list_free(empty_list);
	curl_slist_free_all(headers);
}

void test_create_init_msg_works_with_challenge_on()
{
	struct curl_slist *headers = NULL;
	const char *dc_str = DC_HEADER_PREFIX "on";
	ctx.digest_challenge = JALN_DC_ON;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ARCHIVE_MODE, JALN_RTYPE_LOG,
				&ctx, &headers));
	assert_not_equals(NULL, headers);
	assert_not_equals(0, find_in_headers(headers, dc_str));
	curl_slist_free_all(headers);
}

void test_create_init_msg_works_with_challenge_off()
{
	struct curl_slist *headers = NULL;
	const char *dc_str = DC_HEADER_PREFIX "off";
	ctx.digest_challenge = JALN_DC_OFF;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ARCHIVE_MODE, JALN_RTYPE_LOG,
				&ctx, &headers));
	assert_not_equals(NULL, headers);
	assert_not_equals(0, find_in_headers(headers, dc_str));
	curl_slist_free_all(headers);
}

void test_create_init_msg_works_with_challenge_pref_on()
{
	struct curl_slist *headers = NULL;
	const char *dc_str = DC_HEADER_PREFIX "on, off";
	ctx.digest_challenge = JALN_DC_PREF_ON;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ARCHIVE_MODE, JALN_RTYPE_LOG,
				&ctx, &headers));
	assert_not_equals(NULL, headers);
	assert_not_equals(0, find_in_headers(headers, dc_str));
	curl_slist_free_all(headers);
}

void test_create_init_msg_works_with_challenge_pref_off()
{
	struct curl_slist *headers = NULL;
	const char *dc_str = DC_HEADER_PREFIX "off, on";
	ctx.digest_challenge = JALN_DC_PREF_OFF;
	assert_equals(JAL_OK, jaln_create_init_msg(JALN_ARCHIVE_MODE, JALN_RTYPE_LOG,
				&ctx, &headers));
	assert_not_equals(NULL, headers);
	assert_not_equals(0, find_in_headers(headers, dc_str));
	curl_slist_free_all(headers);
}

void test_create_init_msg_does_not_crash_on_bad_input()
{
	enum jaln_record_type type = JALN_RTYPE_JOURNAL;
	struct curl_slist *headers = NULL;

	assert_equals(JAL_E_INVAL, jaln_create_init_msg(JALN_ARCHIVE_MODE - 1, type, &ctx, &headers));

	assert_equals(JAL_E_INVAL, jaln_create_init_msg(JALN_ARCHIVE_MODE, JALN_RTYPE_JOURNAL | JALN_RTYPE_AUDIT,
							&ctx, &headers));

	jaln_context inval_ctx = ctx;
	memset(inval_ctx.pub_id, '\0', sizeof(inval_ctx.pub_id));
	assert_equals(JAL_E_INVAL, jaln_create_init_msg(JALN_ARCHIVE_MODE, type, &inval_ctx, &headers));

	strcpy(inval_ctx.pub_id, ctx.pub_id);
	inval_ctx.dgst_algs = NULL;
	assert_equals(JAL_E_INVAL, jaln_create_init_msg(JALN_ARCHIVE_MODE, type, &inval_ctx, &headers));

	inval_ctx.dgst_algs = ctx.dgst_algs;
	inval_ctx.xml_encodings = NULL;
	assert_equals(JAL_E_INVAL, jaln_create_init_msg(JALN_ARCHIVE_MODE, type, &inval_ctx, &headers));

	inval_ctx.xml_encodings = ctx.xml_encodings;
	assert_equals(JAL_E_INVAL, jaln_create_init_msg(JALN_ARCHIVE_MODE, type, &ctx, NULL));

	headers = (struct curl_slist *) 0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_create_init_msg(JALN_ARCHIVE_MODE, type, &ctx, &headers));
}

void test_verify_init_ack_headers()
{
	enum jal_status rc = jaln_verify_init_ack_headers(info);
	assert_equals(JAL_E_INVAL, rc);

	info->content_type_valid = axl_true;
	rc = jaln_verify_init_ack_headers(info);
	assert_equals(JAL_E_INVAL, rc);

	info->message_type_valid = axl_true;
	rc = jaln_verify_init_ack_headers(info);
	assert_equals(JAL_E_INVAL, rc);

	info->version_valid = axl_true;
	rc = jaln_verify_init_ack_headers(info);
	assert_equals(JAL_E_INVAL, rc);

	info->sess->dgst = BAD_PTR(struct jal_digest_ctx);
	rc = jaln_verify_init_ack_headers(info);
	assert_equals(JAL_E_INVAL, rc);

	info->sess->ch_info->encoding = BAD_PTR(char);
	rc = jaln_verify_init_ack_headers(info);
	assert_equals(JAL_E_INVAL, rc);

	info->sess->id = BAD_PTR(char);
	rc = jaln_verify_init_ack_headers(info);
	assert_equals(JAL_OK, rc);
/*
	info->content_type_valid = axl_false;
	rc = jaln_verify_init_ack_headers(info);
	assert_equals(JAL_E_INVAL, rc);
*/ // TODO: is content type required?

	info->sess->dgst = NULL;
	info->sess->ch_info->encoding = NULL;
	info->sess->id = NULL;
}

void test_create_journal_missing_msg()
{
	struct curl_slist *headers = NULL;
	assert_equals(JAL_OK, jaln_create_journal_missing_msg("id", nonce_1_str, &headers));
	assert_not_equals(NULL, headers);
	assert_equals(0, strcmp(flatten_headers(headers), EXPECTED_JOURNAL_MISSING_MSG));
}

void test_parse_init_ack_header_record_id()
{
	sess->pub_data = jaln_pub_data_create();
	jaln_parse_init_ack_header(SAMPLE_RECORD_ID, strlen(SAMPLE_RECORD_ID), info);

	assert_not_equals(NULL, sess->pub_data->nonce);
	assert_string_equals(SAMPLE_UUID, sess->pub_data->nonce);
	assert_equals(axl_false, sess->errored);
}

void test_parse_init_ack_header_offset()
{
	sess->pub_data = jaln_pub_data_create();
	info->sess = sess;
	jaln_parse_init_ack_header(SAMPLE_OFFSET, strlen(SAMPLE_OFFSET), info);

	assert_true(sess->pub_data->payload_off > 0);
	assert_equals(SAMPLE_OFFSET_VAL, sess->pub_data->payload_off);
	assert_equals(axl_false, sess->errored);
}

void test_parse_init_ack_header_content_type_valid()
{
	char ct_valid[] = "Content-Type: application/http+jalop\r\n";
	jaln_parse_init_ack_header(ct_valid, strlen(ct_valid), info);
	assert_equals(axl_false, sess->errored);
	assert_equals(axl_true, info->content_type_valid);
}

void test_parse_init_ack_header_content_type_invalid()
{
	char ct_invalid[] = "Content-Type: text/json\r\n";
	jaln_parse_init_ack_header(ct_invalid, strlen(ct_invalid), info);
	assert_equals(axl_true, sess->errored);
	assert_equals(axl_false, info->content_type_valid);
}

void test_parse_init_ack_header_message_ack()
{
	char ack[] = "JAL-Message: initialize-ack\r\n";
	jaln_parse_init_ack_header(ack, strlen(ack), info);
	assert_equals(axl_false, sess->errored);
	assert_equals(axl_true, info->message_type_valid);
}

void test_parse_init_ack_header_message_nack()
{
	char nack[] = "JAL-Message: initialize-nack\r\n";
	jaln_parse_init_ack_header(nack, strlen(nack), info);
	assert_equals(axl_false, sess->errored);
	assert_equals(axl_true, info->message_type_valid);
}

void test_parse_init_ack_header_message_invalid()
{
	char invalid[] = "JAL-Message: foo\r\n";
	jaln_parse_init_ack_header(invalid, strlen(invalid), info);
	assert_equals(axl_true, sess->errored);
	assert_equals(axl_false, info->message_type_valid);
}

void test_parse_init_ack_header_version_valid()
{
	char vers[] = "JAL-Version: 2.0.0.0\r\n";
	jaln_parse_init_ack_header(vers, strlen(vers), info);
	assert_equals(axl_false, sess->errored);
	assert_equals(axl_true, info->version_valid);
}

void test_parse_init_ack_header_version_invalid()
{
	char invalid[] = "JAL-Version: 127.0.0.1\r\n";
	jaln_parse_init_ack_header(invalid, strlen(invalid), info);
	assert_equals(axl_true, sess->errored);
	assert_equals(axl_false, info->message_type_valid);
}

void test_parse_init_ack_header_compression_valid()
{
	char comp[] = "JAL-XML-Compression: xml_enc_1\r\n";
	jaln_parse_init_ack_header(comp, strlen(comp), info);
	assert_equals(axl_false, sess->errored);
	assert_string_equals("xml_enc_1", sess->ch_info->encoding);
}

void test_parse_init_ack_header_compression_invalid()
{
	char invalid[] = "JAL-XML-Compression: fake\r\n";
	jaln_parse_init_ack_header(invalid, strlen(invalid), info);
	assert_equals(axl_true, sess->errored);
	assert_pointer_equals(NULL, sess->ch_info->encoding);
}

void test_parse_init_ack_header_digest_valid()
{
	char dgst[] = "JAL-Digest: sha256\r\n";
	jaln_parse_init_ack_header(dgst, strlen(dgst), info);
	assert_equals(axl_false, sess->errored);
	assert_not_equals(NULL, sess->dgst);
	assert_string_equals("sha256", sess->ch_info->digest_method);
}

void test_parse_init_ack_header_digest_invalid()
{
	char invalid[] = "JAL-Digest: fakehash\r\n";
	jaln_parse_init_ack_header(invalid, strlen(invalid), info);
	assert_equals(axl_true, sess->errored);
	assert_pointer_equals(NULL, sess->dgst);
	assert_pointer_equals(NULL, sess->ch_info->digest_method);
}

void test_parse_init_ack_config_dc_on()
{
	ctx.digest_challenge = JALN_DC_PREF_ON;
	char dc[] = "JAL-Configure-Digest-Challenge: on\r\n";
	jaln_parse_init_ack_header(dc, strlen(dc), info);
	assert_equals(axl_false, sess->errored);
	assert_equals(axl_true, sess->dgst_on);
}

void test_parse_init_ack_config_dc_off()
{
	ctx.digest_challenge = JALN_DC_PREF_ON;
	char dc[] = "JAL-Configure-Digest-Challenge: off\r\n";
	jaln_parse_init_ack_header(dc, strlen(dc), info);
	assert_equals(axl_false, sess->errored);
	assert_equals(axl_false, sess->dgst_on);
}

void test_parse_init_ack_config_dc_invalid()
{
	ctx.digest_challenge = JALN_DC_PREF_ON;
	char invalid[] = "JAL-Configure-Digest-Challenge: foo\r\n";
	jaln_parse_init_ack_header(invalid, strlen(invalid), info);
	assert_equals(axl_true, sess->errored);
}

void test_parse_init_ack_session_id()
{
	char id[] = "JAL-Session-Id: " SAMPLE_UUID "\r\n";
	jaln_parse_init_ack_header(id, strlen(id), info);
	assert_equals(axl_false, sess->errored);
	assert_string_equals(SAMPLE_UUID, sess->id);
}

void test_parse_init_ack_nack_errors_valid()
{
	char errs[] = "JAL-Error-Message: AAA|BBB\r\n";
	jaln_parse_init_ack_header(errs, strlen(errs), info);
	assert_equals(axl_false, sess->errored);
	assert_equals(2, info->error_cnt);
	assert_string_equals("AAA", info->error_list[0]);
	assert_string_equals("BBB", info->error_list[1]);
}

void test_parse_init_ack_nack_errors_invalid()
{
        char invalid[] = "JAL-Error-Message: \r\n";
        jaln_parse_init_ack_header(invalid, strlen(invalid), info);
        assert_equals(axl_true, sess->errored);
}

void test_parse_journal_missing_response()
{
	jaln_session *sess = jaln_session_create();
	enum jal_status rc = jaln_parse_journal_missing_response(SAMPLE_JOURNAL_MISSING_RESP_MSG, strlen(SAMPLE_JOURNAL_MISSING_RESP_MSG), sess);

	assert_equals(JAL_OK, rc);
	assert_string_equals(sess->last_message, JALN_MSG_JOURNAL_MISSING_RESPONSE);
	assert_equals(axl_false, sess->errored);

	rc = jaln_parse_journal_missing_response(SAMPLE_RECORD_ID, strlen(SAMPLE_RECORD_ID), sess);

	assert_equals(JAL_OK, rc);
	assert_string_equals(sess->last_message, JALN_MSG_JOURNAL_MISSING_RESPONSE);
	assert_equals(axl_false, sess->errored);

	rc = jaln_parse_journal_missing_response(SAMPLE_INIT_ACK_MSG, strlen(SAMPLE_INIT_ACK_MSG), sess);

	assert_equals(JAL_E_INVAL, rc);
	assert_pointer_equals(NULL, sess->last_message);
	assert_equals(axl_true, sess->errored);
}

void test_parse_digest_challenge_header()
{
	sess->pub_data = jaln_pub_data_create();
	info->expected_nonce = jal_strdup(SAMPLE_UUID);

	enum jal_status rc = jaln_parse_digest_challenge_header(SAMPLE_DGST_CHAL_MSG, strlen(SAMPLE_DGST_CHAL_MSG), info);

	assert_equals(JAL_OK, rc);
	assert_string_equals(JALN_MSG_DIGEST_CHALLENGE, sess->last_message);

	rc = jaln_parse_digest_challenge_header(SAMPLE_RECORD_ID, strlen(SAMPLE_RECORD_ID), info);

	assert_equals(JAL_OK, rc);
	assert_equals(info->id_valid, axl_true);

	rc = jaln_parse_digest_challenge_header(SAMPLE_DGST_VAL_MSG, strlen(SAMPLE_DGST_VAL_MSG), info);

	assert_equals(JAL_OK, rc);
	assert_string_equals(info->calc_dgst, SOME_DIGEST);
	assert_equals(axl_false, sess->errored);
}

/*
void test_create_record_ans_rpy_headers_fails_for_invalid_record_info()
{
	char *headers_out = NULL;
	uint64_t headers_out_len = 0;
	rec_info->type = 0;
	assert_not_equals(JAL_OK, jaln_create_record_ans_rpy_headers(rec_info, &headers_out, &headers_out_len));
}

void test_create_record_ans_rpy_headers_fails_for_bad_input()
{
	char *headers_out = NULL;
	uint64_t headers_out_len = 0;
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
	uint64_t headers_out_len = 0;
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
	uint64_t headers_out_len = 0;
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
	uint64_t headers_out_len = 0;
	rec_info->type = JALN_RTYPE_LOG;
	assert_equals(JAL_OK, jaln_create_record_ans_rpy_headers(rec_info, &headers_out, &headers_out_len));
	assert_not_equals((void*)NULL, headers_out);
	assert_equals(strlen(EXPECTED_LOG_REC_HDRS), headers_out_len);
	assert_equals(0, memcmp(EXPECTED_LOG_REC_HDRS, headers_out, headers_out_len));
	free(headers_out);
}
*/

void test_digest_resp_info_strlen_works_for_valid_input()
{
	uint64_t len = jaln_digest_resp_info_strlen(dr_1);
	assert_equals(strlen(dr_1_str), len);

	len = jaln_digest_resp_info_strlen(dr_2);
	assert_equals(strlen(dr_2_str), len);

	len = jaln_digest_resp_info_strlen(dr_3);
	assert_equals(strlen(dr_3_str), len);
}

void test_digest_resp_info_strlen_returns_0_when_missing_nonce()
{
	free(dr_1->nonce);
	dr_1->nonce = NULL;
	uint64_t len = jaln_digest_resp_info_strlen(dr_1);
	assert_equals(0, len);
}

void test_digest_resp_info_strlen_returns_0_when_nonce_is_emtpy()
{
	free(dr_1->nonce);
	dr_1->nonce = jal_strdup("");
	uint64_t len = jaln_digest_resp_info_strlen(dr_1);
	assert_equals(0, len);
}

void test_digest_resp_info_strlen_returns_0_with_bad_status()
{
	dr_1->status = JALN_DIGEST_STATUS_UNKNOWN + 1;;
	uint64_t len = jaln_digest_resp_info_strlen(dr_1);
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
	free(dr_1->nonce);
	dr_1->nonce = NULL;

	char *ret = jaln_digest_resp_info_strcat(output_str, dr_1);
	assert_pointer_equals((void*)NULL, ret);
}

void test_create_digest_resp_message_works()
{
	char *msg_out = NULL;
	uint64_t msg_out_len = 0;
	assert_equals(JAL_OK, jaln_create_digest_response_msg(dgst_resp_list, &msg_out, &msg_out_len));

	assert_equals(0, strcmp(EXPECTED_DGST_RESP_MSG, msg_out));
	assert_equals(strlen(EXPECTED_DGST_RESP_MSG), msg_out_len);
	free(msg_out);
}

void test_create_digest_resp_returns_error_with_bad_input()
{
	char *msg_out = NULL;
	uint64_t msg_out_len = 0;
	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(NULL, &msg_out, &msg_out_len));

	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(dgst_resp_list, NULL, &msg_out_len));

	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(dgst_resp_list, &msg_out, NULL));

	msg_out = (char*) 0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(dgst_resp_list, &msg_out, &msg_out_len));

}

void test_create_digest_resp_returns_error_with_bad_digest_list()
{
	char *msg_out = NULL;
	uint64_t msg_out_len = 0;

	axlList *empty_list = axl_list_new(jaln_axl_equals_func_digest_resp_info_nonce, jaln_axl_destroy_digest_resp_info);
	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(empty_list, &msg_out, &msg_out_len));
	axl_list_free(empty_list);

}

void test_create_digest_resp_returns_error_with_bad_digest_info()
{
	char *msg_out = NULL;
	uint64_t msg_out_len = 0;

	axl_list_append(dgst_resp_list, NULL);
	assert_equals(JAL_E_INVAL, jaln_create_digest_response_msg(dgst_resp_list, &msg_out, &msg_out_len));
}

void test_create_init_nack_msg_works_for_unsupported_version()
{
	char *msg_out = NULL;
	uint64_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_VERSION, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_UNSUPP_VERSION), len);
	assert_equals(0, memcmp(EXPECTED_NACK_UNSUPP_VERSION, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_works_for_unsupported_encoding()
{
	char *msg_out = NULL;
	uint64_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_ENCODING, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_UNSUPP_ENC), len);
	assert_equals(0, memcmp(EXPECTED_NACK_UNSUPP_ENC, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_works_for_unsupported_digest()
{
	char *msg_out = NULL;
	uint64_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_DIGEST, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_UNSUPP_DIGEST), len);
	assert_equals(0, memcmp(EXPECTED_NACK_UNSUPP_DIGEST, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_works_for_unsupported_mode()
{
	char *msg_out = NULL;
	uint64_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_MODE, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_UNSUPP_MODE), len);
	assert_equals(0, memcmp(EXPECTED_NACK_UNSUPP_MODE, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_works_with_all_errors()
{
	char *msg_out = NULL;
	uint64_t len = 0;
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
	uint64_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_nack_msg(JALN_CE_UNAUTHORIZED_MODE, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_NACK_UNAUTH_MODE), len);
	assert_equals(0, memcmp(EXPECTED_NACK_UNAUTH_MODE, msg_out, len));
	free(msg_out);
}

void test_create_init_nack_msg_fails_if_no_err_specified()
{
	char *msg_out = NULL;
	uint64_t len = 0;
	assert_equals(JAL_E_INVAL, jaln_create_init_nack_msg(JALN_CE_ACCEPT, &msg_out, &len));
}

void test_create_init_nack_msg_does_not_crash_on_bad_input()
{
	char *msg_out = NULL;
	uint64_t len = 0;
	assert_equals(JAL_E_INVAL, jaln_create_init_nack_msg(1 << 5, &msg_out, &len));

	msg_out = NULL;
	assert_equals(JAL_E_INVAL, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_VERSION, NULL, &len));

	msg_out = NULL;
	assert_equals(JAL_E_INVAL, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_VERSION, &msg_out, NULL));

	msg_out = (char*) 0xbadf00d;;
	assert_equals(JAL_E_INVAL, jaln_create_init_nack_msg(JALN_CE_UNSUPPORTED_VERSION, &msg_out, &len));
}

void test_create_init_ack_msg_works_for_valid_input()
{
	char *msg_out = NULL;
	uint64_t len = 0;
	assert_equals(JAL_OK, jaln_create_init_ack_msg(SOME_ENCODING, SOME_DIGEST, &msg_out, &len));
	assert_not_equals((void*) NULL, msg_out);
	assert_equals(strlen(EXPECTED_ACK), len);
	assert_equals(0, memcmp(EXPECTED_ACK, msg_out, len));
	free(msg_out);
}

void test_create_init_ack_msg_returns_error_on_bad_input()
{
	char *msg_out = NULL;
	uint64_t len = 0;

	assert_equals(JAL_E_INVAL, jaln_create_init_ack_msg(NULL, SOME_DIGEST, &msg_out, &len));

	msg_out = NULL;
	assert_equals(JAL_E_INVAL, jaln_create_init_ack_msg(SOME_ENCODING, NULL, &msg_out, &len));

	msg_out = NULL;
	assert_equals(JAL_E_INVAL, jaln_create_init_ack_msg(SOME_ENCODING, SOME_DIGEST, NULL, &len));

	msg_out = (char*) 0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_create_init_ack_msg(SOME_ENCODING, SOME_DIGEST, &msg_out, &len));

	msg_out = NULL;
	assert_equals(JAL_E_INVAL, jaln_create_init_ack_msg(SOME_ENCODING, SOME_DIGEST, &msg_out, NULL));

}
