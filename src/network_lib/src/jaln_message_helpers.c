/**
 * @file jaln_message_helpers.c This file contains function
 * definitions for internal library functions related to creating JALoP
 * messages
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

#include <inttypes.h>
#include <jalop/jal_status.h>
#include <jalop/jaln_network_types.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jaln_context.h"
#include "jaln_digest.h"
#include "jaln_digest_info.h"
#include "jaln_digest_resp_info.h"
#include "jaln_encoding.h"
#include "jaln_message_helpers.h"
#include "jaln_record_info.h"
#include "jaln_session.h"
#include "jaln_strings.h"

enum jal_status jaln_create_journal_resume_msg(const char *nonce,
		uint64_t offset, char **msg_out, uint64_t *msg_out_len)
{
	static const char * const preamble = JALN_MIME_PREAMBLE JALN_MSG_JOURNAL_RESUME JALN_CRLF \
		JALN_HDRS_ID JALN_COLON_SPACE;

	enum jal_status ret = JAL_E_INVAL;
	char *offset_str = NULL;
	if (!msg_out || *msg_out || !msg_out_len) {
		return JAL_E_INVAL;
	}
	if (!nonce || (offset == 0)) {
		return JAL_E_INVAL;
	}
	jal_asprintf(&offset_str, "%"PRIu64, offset);
	uint64_t cnt = strlen(preamble) + 1;
	uint64_t tmp = strlen(nonce) + strlen(JALN_CRLF);
	if (cnt > (SIZE_MAX - tmp)) {
		goto out;
	}
	cnt += tmp;
	tmp = strlen(JALN_HDRS_JOURNAL_OFFSET JALN_COLON_SPACE);
	if (cnt > (SIZE_MAX - tmp)) {
		goto out;
	}
	cnt += tmp;
	tmp = strlen(offset_str) + strlen(JALN_CRLF) + strlen(JALN_CRLF);
	if (cnt > (SIZE_MAX - tmp)) {
		goto out;
	}
	cnt += tmp;

	char *msg = (char*) jal_malloc(cnt);
	msg[0] = '\0';
	strcat(msg, preamble);
	strcat(msg, nonce);
	strcat(msg, JALN_CRLF);
	strcat(msg, JALN_HDRS_JOURNAL_OFFSET JALN_COLON_SPACE);
	strcat(msg, offset_str);
	strcat(msg, JALN_CRLF JALN_CRLF);
	*msg_out = msg;
	*msg_out_len = cnt - 1;
	ret = JAL_OK;
	goto out;
out:
	free(offset_str);
	return ret;
}

enum jal_status jaln_create_sync_msg(const char *nonce, char **msg_out, uint64_t *msg_len)
{
#define SYNC_MSG_HDRS JALN_MIME_PREAMBLE JALN_MSG_SYNC JALN_CRLF \
		JALN_HDRS_ID JALN_COLON_SPACE "%s" JALN_CRLF JALN_CRLF

	if (!nonce || !msg_out || *msg_out || !msg_len) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = JAL_E_INVAL;
	char *msg = NULL;

	int len = jal_asprintf(&msg, SYNC_MSG_HDRS, nonce);
	if (len <= 0) {
		goto err_out;
	}
	*msg_len = (uint64_t) len;
	*msg_out = msg;
	ret = JAL_OK;

	goto out;

err_out:
	free(msg);
out:
	return ret;

}

enum jal_status jaln_create_subscribe_msg(char **msg_out, uint64_t *msg_out_len)
{
	static const char *preamble = JALN_MIME_PREAMBLE JALN_MSG_SUBSCRIBE;
	enum jal_status ret = JAL_E_INVAL;
	if (!msg_out || *msg_out || !msg_out_len) {
		goto out;
	}
	uint64_t cnt = strlen(preamble) + 1;
	uint64_t tmp = 2 * strlen(JALN_CRLF);
	if (cnt > (SIZE_MAX - tmp)) {
		goto out;
	}
	cnt += tmp;
	char *msg = (char*) jal_malloc(cnt);
	msg[0] = '\0';
	strcat(msg, preamble);
	strcat(msg, JALN_CRLF JALN_CRLF);
	*msg_out = msg;
	*msg_out_len = cnt - 1;
	ret = JAL_OK;
out:
	return ret;
}

axl_bool jaln_check_content_type_and_txfr_encoding_are_valid(VortexFrame *frame)
{
	if (!frame) {
		return axl_false;
	}
	const char *ct = VORTEX_FRAME_GET_MIME_HEADER(frame, (JALN_HDRS_CONTENT_TYPE));
	if (!ct) {
		return axl_false;
	}
	if (0 != strcasecmp(ct, JALN_STR_CT_JALOP)) {
		return axl_false;
	}
	// the assumption for beep is if there is no content transfer encoding,
	// it is binary.
	const char *te = VORTEX_FRAME_GET_MIME_HEADER(frame, (JALN_HDRS_CONTENT_TXFR_ENCODING));
	if (te) {
		if (0 != strcasecmp(te, JALN_STR_BINARY)) {
			return axl_false;
		}
	}
	return axl_true;
}

static int jaln_header_name_match(const char *content, const size_t content_len,
		const char *name, const size_t name_len)
{
	if (content_len <= name_len) {
		return 0;
	}
	if (strncasecmp(content, name, name_len)) {
		return 0;
	}
	return (':' == content[name_len]);
}

static enum jal_status jaln_header_value_match(const char *content, const size_t content_len,
		const char *value, const size_t value_len)
{
	size_t offset = 0;
	// Skip whitespace
	for (; offset < content_len && (content[offset] == ' ' || content[offset] == '\t'); ++offset);
	if (content_len - offset != value_len + strlen("\r\n")) {
		return JAL_E_INVAL;
	}
	return !memcmp(content + offset, value, value_len)? JAL_OK : JAL_E_INVAL;
}

// There needs to be a struct or masked int to keep track of what has been parsed/validated.
// That way jaln_publish can see what headers have been received and set defaults/fail if some were not.
enum jal_status jaln_parse_init_ack_header(char *content, size_t len, jaln_session *sess)
{
#define JALN_STR_W_LEN(_str) _str, strlen(_str)
	enum jal_status rc = JAL_OK; // Allow headers with names that aren't validated.
	if (jaln_header_name_match(content, len, JALN_STR_W_LEN(JALN_HDRS_CONTENT_TYPE))) {
		const size_t name_len = strlen(JALN_HDRS_CONTENT_TYPE);
		const char *value_start = content + name_len + 1;
		const size_t value_len = len - name_len - 1;
		rc = jaln_header_value_match(value_start, value_len, JALN_STR_W_LEN(JALN_STR_CT_JALOP));
		if (JAL_OK == rc) {
			// TODO: Store that we validated this.
		}
	} else if (jaln_header_name_match(content, len, JALN_STR_W_LEN(JALN_HDRS_MESSAGE))) {
		const size_t name_len = strlen(JALN_HDRS_MESSAGE);
		const char *value_start = content + name_len + 1;
		const size_t value_len = len - name_len - 1;
		rc =  jaln_header_value_match(value_start, value_len, JALN_STR_W_LEN(JALN_MSG_INIT_ACK));
		if (JAL_OK == rc) {
			// TODO: Store that we validated this.
		}
	} else if (jaln_header_name_match(content, len, JALN_STR_W_LEN(JALN_HDRS_VERSION))) {
		const size_t name_len = strlen(JALN_HDRS_VERSION);
		const char *value_start = content + name_len + 1;
		const size_t value_len = len - name_len - 1;
		rc =  jaln_header_value_match(value_start, value_len, JALN_STR_W_LEN(JALN_VERSION));
		if (JAL_OK == rc) {
			// TODO: Store that we validated this.
		}
	} else if (jaln_header_name_match(content, len, JALN_STR_W_LEN(JALN_HDRS_ENCODING))) {
		rc = jaln_parse_xml_compression_header(content, len, sess);
		if (JAL_OK == rc) {
			// TODO: Store that we validated this.
		}
	} else if (jaln_header_name_match(content, len, JALN_STR_W_LEN(JALN_HDRS_DIGEST))) {
		rc = jaln_parse_digest_header(content, len, sess);
		if (JAL_OK == rc) {
			// TODO: Store that we validated this.
		}
	} else if (jaln_header_name_match(content, len, JALN_STR_W_LEN(JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE))) {
		rc = jaln_parse_configure_digest_challenge_header(content, len, sess);
		if (JAL_OK == rc) {
			// TODO: Store that we validated this.
		}
	} else if (jaln_header_name_match(content, len, JALN_STR_W_LEN(JALN_HDRS_SESSION_ID))) {
		rc = jaln_parse_session_id(content, len, sess);
		if (JAL_OK == rc) {
			// TODO: Store that we validated this.
		}
	}
	if (JAL_OK != rc) {
		sess->errored = 1;
	}
	return rc;
#undef JAL_STR_W_LEN
}

static char *jaln_get_header_value(const char *content, const size_t len, size_t offset)
{
       // Skip whitespace
       for (; offset < len && (content[offset] == ' ' || content[offset] == '\t'); ++offset);
       size_t ret_len = len - offset - strlen("\r\n");
       char *ret = (char *)jal_malloc(ret_len + 1);
       ret[ret_len] = '\0';
       memcpy(ret, content + offset, ret_len);
       return ret;
}

enum jal_status jaln_parse_xml_compression_header(char *content, size_t len, jaln_session *sess)
{
	char *compression  = jaln_get_header_value(content, len, strlen(JALN_HDRS_ENCODING) + 1);
	axlPointer ptr = axl_list_lookup(sess->jaln_ctx->xml_encodings,
		jaln_string_list_case_insensitive_lookup_func, compression);
	if (!ptr) {
		free(compression);
		return JAL_E_INVAL;
	}
	// TODO: Store the compression scheme somewhere.
	// 1.0 never did, so there's no place in session for it yet.
	free(compression);
	return JAL_OK;
}

enum jal_status jaln_parse_digest_header(char *content, size_t len, jaln_session *sess)
{
	char *digest = jaln_get_header_value(content, len, strlen(JALN_HDRS_DIGEST) + 1);
	axlPointer ptr = axl_list_lookup(sess->jaln_ctx->dgst_algs, jaln_digest_lookup_func, digest);
	if (!ptr) {
		free(digest);
		return JAL_E_INVAL;
	}
	sess->dgst = (struct jal_digest_ctx*) ptr;
	free(digest);
	return JAL_OK;
}

enum jal_status jaln_parse_configure_digest_challenge_header(
		__attribute__((unused)) char *content,
		__attribute__((unused)) size_t len,
		__attribute__((unused)) jaln_session *sess)
{
	//TODO: check if this matches the expected value from the context
	return JAL_OK;
}

enum jal_status jaln_parse_session_id(char *content, size_t len, jaln_session *sess)
{
	// fail if a JAL-Session-Id header has already been parsed
	if (sess->id) {
		return JAL_E_INVAL;
	}
	sess->id = jaln_get_header_value(content, len, strlen(JALN_HDRS_SESSION_ID) + 1);
	return JAL_OK;
}

uint64_t jaln_digest_info_strlen(const struct jaln_digest_info *di)
{
	// output for each line should be:
	// <dgst_as_hex>=<nonce>CRLF
	if (!di || !di->nonce || !di->digest || 0 == di->digest_len) {
		return 0;
	}
	if (0 == strlen(di->nonce)) {
		return 0;
	}
	// start with cnt == 3 ('=' CR LF)
	uint64_t cnt = 3;
	uint64_t tmp = strlen(di->nonce);
	if (cnt > (SIZE_MAX - tmp)) {
		cnt = 0;
		goto out;
	}
	cnt += tmp;
	tmp = di->digest_len;
	if (cnt > (SIZE_MAX - tmp)) {
		cnt = 0;
		goto out;
	}
	cnt += tmp;
	// check again since 1 byte is represented as 2 hex characters
	if (cnt > (SIZE_MAX - tmp)) {
		cnt = 0;
		goto out;
	}
	cnt += tmp;
out:
	return cnt;
}

char *jaln_digest_info_strcat(char *dst, const struct jaln_digest_info *di)
{
	// output for each line should be:
	// <dgst_as_hex>=<nonce>CRLF
	// start with cnt == 4 ('=' CR LF and NULL terminator)
	if (!dst || 0 == jaln_digest_info_strlen(di)) {
		return NULL;
	}
	char *orig = dst;
	dst = dst + strlen(dst);
	uint64_t i;
	for (i = 0; i < di->digest_len; i++) {
		sprintf(dst + (i * 2), "%02x", di->digest[i]);
	}
	sprintf(dst + (i * 2), "=%s" JALN_CRLF, di->nonce);
	return orig;
}

enum jal_status jaln_create_digest_msg(axlList *dgst_list, char **msg_out, uint64_t *msg_len)
{
#define DGST_MSG_HDRS JALN_MIME_PREAMBLE JALN_MSG_DIGEST JALN_CRLF \
		JALN_HDRS_COUNT JALN_COLON_SPACE "%d" JALN_CRLF JALN_CRLF
	if (!dgst_list || !msg_out || *msg_out || !msg_len) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = JAL_E_INVAL;
	int dgst_cnt = axl_list_length(dgst_list);
	uint64_t len = 1;
	uint64_t tmp = 0;
	char *msg = NULL;
	axlListCursor *iter = NULL;

	if (0 >= dgst_cnt) {
		goto err_out;
	}

	tmp = snprintf(NULL, 0, DGST_MSG_HDRS, dgst_cnt);
	if (len > (SIZE_MAX - tmp)) {
		goto err_out;
	}
	len += tmp;

	iter = axl_list_cursor_new(dgst_list);
	axl_list_cursor_first(iter);

	while(axl_list_cursor_has_item(iter)) {
		// major assumption that the list here contains valid
		// digest_info objects;
		struct jaln_digest_info *di = (struct jaln_digest_info *) axl_list_cursor_get(iter);
		tmp = jaln_digest_info_strlen(di);
		if (0 == tmp || len > (SIZE_MAX - tmp)) {
			goto err_out;
		}
		len += tmp;
		axl_list_cursor_next(iter);
	}

	msg = jal_malloc(len);
	sprintf(msg, DGST_MSG_HDRS, dgst_cnt);

	axl_list_cursor_first(iter);
	while(axl_list_cursor_has_item(iter)) {
		// major assumption that the list here contains valid
		// digest_info objects;
		struct jaln_digest_info *di = (struct jaln_digest_info *) axl_list_cursor_get(iter);
		jaln_digest_info_strcat(msg, di);
		axl_list_cursor_next(iter);
	}

	*msg_out = msg;
	*msg_len = len - 1;
	ret = JAL_OK;
	goto out;

err_out:
	free(msg);
out:
	if (iter) {
		axl_list_cursor_free(iter);
	}
	return ret;

}

axl_bool jaln_safe_add_size(uint64_t *base, uint64_t inc)
{
	if (!base || (*base > (SIZE_MAX - inc))) {
		return axl_false;
	}
	*base += inc;
	return axl_true;
}

enum jal_status jaln_create_init_msg(const char *pub_id, enum jaln_publish_mode mode, enum jaln_record_type type,
		axlList *dgst_list, axlList *enc_list, struct curl_slist **headers_out)
{
	if (!pub_id || !dgst_list || !enc_list ||
			!headers_out || *headers_out) {
		return JAL_E_INVAL;
	}
	// TODO: validate that pub_id is a uuid.

	struct curl_slist *headers = NULL;

	const char *preamble = JALN_MIME_PREAMBLE JALN_MSG_INIT;

	axlListCursor *cursor = NULL;
	enum jal_status ret = JAL_E_INVAL;

	const char *role_str;
	switch (mode) {
		case JALN_LIVE_MODE:
			role_str = JALN_HDRS_MODE JALN_COLON_SPACE JALN_MSG_PUBLISH_LIVE;
			break;
		case JALN_ARCHIVE_MODE:
			role_str = JALN_HDRS_MODE JALN_COLON_SPACE JALN_MSG_PUBLISH_ARCHIVE;
			break;
		default:
			return JAL_E_INVAL;
	}

	const char *type_str;
	switch (type) {
		case JALN_RTYPE_JOURNAL:
			type_str = JALN_HDRS_DATA_CLASS JALN_COLON_SPACE JALN_STR_JOURNAL;
			break;
		case JALN_RTYPE_AUDIT:
			type_str = JALN_HDRS_DATA_CLASS JALN_COLON_SPACE JALN_STR_AUDIT;
			break;
		case JALN_RTYPE_LOG:
			type_str = JALN_HDRS_DATA_CLASS JALN_COLON_SPACE JALN_STR_LOG;
			break;
		default:
			return JAL_E_INVAL;
	}

	const size_t prefix_len = strlen(JALN_HDRS_PUBLISHER_ID JALN_COLON_SPACE);
	const size_t pub_id_len = strlen(pub_id);
	char *pub_id_str = jal_malloc(prefix_len + pub_id_len + 1);
	memcpy(pub_id_str, JALN_HDRS_PUBLISHER_ID JALN_COLON_SPACE, prefix_len);
	memcpy(pub_id_str + prefix_len, pub_id, pub_id_len);
	pub_id_str[prefix_len + pub_id_len] = '\0';
	
	char *dgst_list_str = NULL;
	char *enc_list_str = NULL;

	if (!axl_list_is_empty(dgst_list)) {
		uint64_t dgst_list_size = 0;
		cursor = axl_list_cursor_new(dgst_list);
		axl_list_cursor_first(cursor);
		if (!jaln_safe_add_size(&dgst_list_size, strlen(JALN_HDRS_ACCEPT_DIGEST JALN_COLON_SPACE))) {
			goto out;
		}
		int dgst_cnt = 0;
		while(axl_list_cursor_has_item(cursor)) {
			struct jal_digest_ctx *dgst = (struct jal_digest_ctx *)axl_list_cursor_get(cursor);
			if (!jaln_safe_add_size(&dgst_list_size, strlen(dgst->algorithm_uri))) {
				goto out;
			}
			dgst_cnt += 1;
			axl_list_cursor_next(cursor);
		}
		// for each dgst in the list (except the last one), need to add
		// a ", ".
		if (!jaln_safe_add_size(&dgst_list_size, 2 * (dgst_cnt - 1))) {
			goto out;
		}

		dgst_list_str = malloc(dgst_list_size + 1);
		strcpy(dgst_list_str, JALN_HDRS_ACCEPT_DIGEST JALN_COLON_SPACE);
		axl_list_cursor_first(cursor);
		while(axl_list_cursor_has_item(cursor)) {
			struct jal_digest_ctx *dgst =
				(struct jal_digest_ctx *)axl_list_cursor_get(cursor);
			strcat(dgst_list_str, dgst->algorithm_uri);
			axl_list_cursor_next(cursor);
			if (axl_list_cursor_has_item(cursor)) {
				strcat(dgst_list_str, ", ");
			}
		}
		axl_list_cursor_free(cursor);
		cursor = NULL;
	}

	if (!axl_list_is_empty(enc_list)) {
		uint64_t enc_list_size = 0;
		cursor = axl_list_cursor_new(enc_list);
		axl_list_cursor_first(cursor);
		if (!jaln_safe_add_size(&enc_list_size, strlen(JALN_HDRS_ACCEPT_ENCODING JALN_COLON_SPACE))) {
			goto out;
		}
		int enc_cnt = 0;
		while (axl_list_cursor_has_item(cursor)) {
			char *enc = (char *)axl_list_cursor_get(cursor);
			if (!jaln_safe_add_size(&enc_list_size, strlen(enc))) {
				goto out;
			}
			enc_cnt += 1;
			axl_list_cursor_next(cursor);
		}
		// for each dgst in the list (except the last one), need to add
		// a ", ".
		if (!jaln_safe_add_size(&enc_list_size, 2 * (enc_cnt - 1))) {
			goto out;
		}

		enc_list_str = malloc(enc_list_size + 1);
		strcpy(enc_list_str, JALN_HDRS_ACCEPT_ENCODING JALN_COLON_SPACE);
		axl_list_cursor_first(cursor);
		while (axl_list_cursor_has_item(cursor)) {
			char *enc = (char *)axl_list_cursor_get(cursor);
			strcat(enc_list_str, enc);
			axl_list_cursor_next(cursor);
			if (axl_list_cursor_has_item(cursor)) {
				strcat(enc_list_str, ", ");
			}
		}
		axl_list_cursor_free(cursor);
		cursor = NULL;
	}


	if (!axl_list_is_empty(dgst_list)) {
		axl_list_cursor_free(cursor);
		cursor = NULL;
	}

	struct curl_slist *tmp;
	tmp = curl_slist_append(headers, preamble);
	if (!tmp) {
		curl_slist_free_all(headers);
		goto out;
	}
	headers = tmp;
	tmp = curl_slist_append(headers, pub_id_str);
	if (!tmp) {
		curl_slist_free_all(headers);
		goto out;
	}
	headers = tmp;
	tmp = curl_slist_append(headers, role_str);
	if (!tmp) {
		curl_slist_free_all(headers);
		goto out;
	}
	headers = tmp;
	if (!tmp) {
		curl_slist_free_all(headers);
		goto out;
	}
	headers = tmp;
	tmp = curl_slist_append(headers, type_str);
	if (!tmp) {
		curl_slist_free_all(headers);
		goto out;
	}
	headers = tmp;
	if (dgst_list_str) {
		tmp = curl_slist_append(headers, dgst_list_str);
		if (!tmp) {
			curl_slist_free_all(headers);
			goto out;
		}
		headers = tmp;
	}
	if (enc_list_str) {
		tmp = curl_slist_append(headers, enc_list_str);
		if (!tmp) {
			curl_slist_free_all(headers);
			goto out;
		}
		headers = tmp;
	}
	*headers_out = headers;

	ret = JAL_OK;

out:
	if (cursor) {
		axl_list_cursor_free(cursor);
	}
	free(dgst_list_str);
	free(enc_list_str);
	return ret;
}

enum jal_status jaln_create_record_ans_rpy_headers(struct jaln_record_info *rec_info, char **headers_out, uint64_t *headers_len_out)
{
	if (!rec_info || !headers_out || *headers_out || !headers_len_out) {
		return JAL_E_INVAL;;
	}
	if (!jaln_record_info_is_valid(rec_info)) {
		return JAL_E_INVAL;
	}

#define REC_FORMAT_STR JALN_MIME_PREAMBLE "%s" JALN_CRLF \
		JALN_HDRS_ID JALN_COLON_SPACE "%s" JALN_CRLF \
		JALN_HDRS_SYS_META_LEN JALN_COLON_SPACE "%" PRIu64 JALN_CRLF \
		JALN_HDRS_APP_META_LEN JALN_COLON_SPACE "%" PRIu64 JALN_CRLF \
		"%s" JALN_COLON_SPACE "%" PRIu64 JALN_CRLF JALN_CRLF

	const char *length_header = NULL;
	const char *msg = NULL;
	switch(rec_info->type) {
	case JALN_RTYPE_JOURNAL:
		length_header = JALN_HDRS_JOURNAL_LEN;
		msg = JALN_MSG_JOURNAL;
		break;
	case JALN_RTYPE_AUDIT:
		length_header = JALN_HDRS_AUDIT_LEN;
		msg = JALN_MSG_AUDIT;
		break;
	case JALN_RTYPE_LOG:
		length_header = JALN_HDRS_LOG_LEN;
		msg = JALN_MSG_LOG;
		break;
	default:
		return JAL_E_INVAL;
	}
	*headers_len_out = jal_asprintf(headers_out, REC_FORMAT_STR, msg, rec_info->nonce,
			rec_info->sys_meta_len, rec_info->app_meta_len,
			length_header, rec_info->payload_len);

	return JAL_OK;
}

uint64_t jaln_digest_resp_info_strlen(const struct jaln_digest_resp_info *di)
{
	// output for each line should be:
	// <dgst_as_hex>=<nonce>CRLF
	if (!di || !di->nonce) {
		return 0;
	}
	if (0 == strlen(di->nonce)) {
		return 0;
	}
	// start with cnt == 2 (CR LF)
	uint64_t cnt = 2;
	if (!jaln_safe_add_size(&cnt, strlen(di->nonce))) {
		cnt = 0;
		goto out;
	}
	const char *status_str = NULL;
	switch (di->status) {
	case (JALN_DIGEST_STATUS_CONFIRMED):
		status_str = JALN_STR_CONFIRMED_EQUALS;
		break;
	case (JALN_DIGEST_STATUS_INVALID):
		status_str = JALN_STR_INVALID_EQUALS;
		break;
	case (JALN_DIGEST_STATUS_UNKNOWN):
		status_str = JALN_STR_UNKNOWN_EQUALS;
		break;
	default:
		cnt = 0;
		goto out;
	}

	if (!jaln_safe_add_size(&cnt, strlen(status_str))) {
		cnt = 0;
		goto out;
	}
out:
	return cnt;
}

char *jaln_digest_resp_info_strcat(char *dst, const struct jaln_digest_resp_info *di)
{
	// output for each line should be:
	// <dgst_status>=<nonce>CRLF
	// start with cnt == 4 ('=' CR LF and NULL terminator)
	if (!dst || 0 == jaln_digest_resp_info_strlen(di)) {
		return NULL;
	}
	char *status_str = NULL;
	switch (di->status) {
	case (JALN_DIGEST_STATUS_CONFIRMED):
		status_str = JALN_STR_CONFIRMED_EQUALS;
		break;
	case (JALN_DIGEST_STATUS_INVALID):
		status_str = JALN_STR_INVALID_EQUALS;
		break;
	case (JALN_DIGEST_STATUS_UNKNOWN):
		status_str = JALN_STR_UNKNOWN_EQUALS;
		break;
	default:
		return NULL;
	}
	strcat(dst, status_str);
	strcat(dst, di->nonce);
	strcat(dst, JALN_CRLF);
	return dst;
}

enum jal_status jaln_create_digest_response_msg(axlList *dgst_resp_list, char **msg_out, uint64_t *msg_len)
{
#define DGST_RESP_MSG_HDRS JALN_MIME_PREAMBLE JALN_MSG_DIGEST_RESP JALN_CRLF \
		JALN_HDRS_COUNT JALN_COLON_SPACE "%d" JALN_CRLF JALN_CRLF
	if (!dgst_resp_list || !msg_out || *msg_out || !msg_len) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = JAL_E_INVAL;
	int dgst_cnt = axl_list_length(dgst_resp_list);
	uint64_t len = 1;
	uint64_t tmp = 0;
	char *msg = NULL;
	axlListCursor *iter = NULL;

	if (0 >= dgst_cnt) {
		goto err_out;
	}

	tmp = snprintf(NULL, 0, DGST_RESP_MSG_HDRS, dgst_cnt);
	if (len > (SIZE_MAX - tmp)) {
		goto err_out;
	}
	len += tmp;

	iter = axl_list_cursor_new(dgst_resp_list);
	axl_list_cursor_first(iter);

	while(axl_list_cursor_has_item(iter)) {
		// major assumption that the list here contains valid
		// digest_info objects;
		struct jaln_digest_resp_info *di = (struct jaln_digest_resp_info *) axl_list_cursor_get(iter);
		tmp = jaln_digest_resp_info_strlen(di);
		if (0 == tmp || len > (SIZE_MAX - tmp)) {
			goto err_out;
		}
		len += tmp;
		axl_list_cursor_next(iter);
	}

	msg = jal_malloc(len);
	sprintf(msg, DGST_RESP_MSG_HDRS, dgst_cnt);

	axl_list_cursor_first(iter);
	while(axl_list_cursor_has_item(iter)) {
		// major assumption that the list here contains valid
		// digest_info objects;
		struct jaln_digest_resp_info *di = (struct jaln_digest_resp_info *) axl_list_cursor_get(iter);
		jaln_digest_resp_info_strcat(msg, di);
		axl_list_cursor_next(iter);
	}

	*msg_out = msg;
	*msg_len = len - 1;
	ret = JAL_OK;
	goto out;

err_out:
	free(msg);
out:
	if (iter) {
		axl_list_cursor_free(iter);
	}
	return ret;
}

enum jal_status jaln_create_init_nack_msg(enum jaln_connect_error err_codes, char **msg_out, uint64_t *msg_len_out)
{
	if (err_codes == JALN_CE_ACCEPT || !msg_out || *msg_out || !msg_len_out) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = JAL_E_INVAL;
	const char *preamble = JALN_MIME_PREAMBLE JALN_MSG_INIT_NACK JALN_CRLF;
	uint64_t msg_size = strlen(preamble) + 1;
	char *msg = NULL;
	axl_bool errors_listed = axl_false;
	if (err_codes & JALN_CE_UNSUPPORTED_VERSION) {
		errors_listed = axl_true;
		if (!jaln_safe_add_size(&msg_size, strlen(JALN_HDRS_UNSUPPORTED_VERSION JALN_COLON_SPACE JALN_CRLF))) {
			goto err_out;
		}
	}
	if (err_codes & JALN_CE_UNSUPPORTED_ENCODING) {
		errors_listed = axl_true;
		if (!jaln_safe_add_size(&msg_size, strlen(JALN_HDRS_UNSUPPORTED_ENCODING JALN_COLON_SPACE JALN_CRLF))) {
			goto err_out;
		}
	}
	if (err_codes & JALN_CE_UNSUPPORTED_DIGEST) {
		errors_listed = axl_true;
		if (!jaln_safe_add_size(&msg_size, strlen(JALN_HDRS_UNSUPPORTED_DIGEST JALN_COLON_SPACE JALN_CRLF))) {
			goto err_out;
		}
	}
	if (err_codes & JALN_CE_UNSUPPORTED_MODE) {
		errors_listed = axl_true;
		if (!jaln_safe_add_size(&msg_size, strlen(JALN_HDRS_UNSUPPORTED_MODE JALN_COLON_SPACE JALN_CRLF))) {
			goto err_out;
		}
	}
	if (err_codes & JALN_CE_UNAUTHORIZED_MODE) {
		errors_listed = axl_true;
		if (!jaln_safe_add_size(&msg_size, strlen(JALN_HDRS_UNAUTHORIZED_MODE JALN_COLON_SPACE JALN_CRLF))) {
			goto err_out;
		}
	}
	if (!errors_listed) {
		goto err_out;
	}
	if (!jaln_safe_add_size(&msg_size, strlen(JALN_CRLF))) {
		goto err_out;
	}

	msg = jal_malloc(msg_size);
	msg[0] = '\0';
	strcat(msg, preamble);

	if (err_codes & JALN_CE_UNSUPPORTED_VERSION) {
		strcat(msg, JALN_HDRS_UNSUPPORTED_VERSION JALN_COLON_SPACE JALN_CRLF);
	}
	if (err_codes & JALN_CE_UNSUPPORTED_ENCODING) {
		strcat(msg, JALN_HDRS_UNSUPPORTED_ENCODING JALN_COLON_SPACE JALN_CRLF);
	}
	if (err_codes & JALN_CE_UNSUPPORTED_DIGEST) {
		strcat(msg, JALN_HDRS_UNSUPPORTED_DIGEST JALN_COLON_SPACE JALN_CRLF);
	}
	if (err_codes & JALN_CE_UNSUPPORTED_MODE) {
		strcat(msg, JALN_HDRS_UNSUPPORTED_MODE JALN_COLON_SPACE JALN_CRLF);
	}
	if (err_codes & JALN_CE_UNAUTHORIZED_MODE) {
		strcat(msg, JALN_HDRS_UNAUTHORIZED_MODE JALN_COLON_SPACE JALN_CRLF);
	}
	strcat(msg, JALN_CRLF);

	*msg_out = msg;
	*msg_len_out = msg_size - 1;
	ret = JAL_OK;
	goto out;
err_out:
	free(msg);
out:
	return ret;
}

enum jal_status jaln_create_init_ack_msg(const char *encoding, const char *digest, char **msg_out, uint64_t *msg_len_out)
{
	if (!encoding || !digest || !msg_out || *msg_out || !msg_len_out) {
		return JAL_E_INVAL;
	}
	*msg_len_out = jal_asprintf(msg_out, JALN_MIME_PREAMBLE JALN_MSG_INIT_ACK JALN_CRLF \
			  JALN_HDRS_ENCODING JALN_COLON_SPACE "%s" JALN_CRLF
			  JALN_HDRS_DIGEST JALN_COLON_SPACE "%s" JALN_CRLF JALN_CRLF,
			  encoding, digest);
	return JAL_OK;
}
