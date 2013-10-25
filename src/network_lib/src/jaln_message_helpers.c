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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#include "jaln_context.h"
#include "jaln_digest_info.h"
#include "jaln_digest_resp_info.h"
#include "jaln_message_helpers.h"
#include "jaln_record_info.h"
#include "jaln_strings.h"

enum jal_status jaln_create_journal_resume_msg(const char *serial_id,
		uint64_t offset, char **msg_out, uint64_t *msg_out_len)
{
	static const char * const preamble = JALN_MIME_PREAMBLE JALN_MSG_JOURNAL_RESUME JALN_CRLF \
		JALN_HDRS_SERIAL_ID JALN_COLON_SPACE;

	enum jal_status ret = JAL_E_INVAL;
	char *offset_str = NULL;
	if (!msg_out || *msg_out || !msg_out_len) {
		return JAL_E_INVAL;
	}
	if (!serial_id || (offset == 0)) {
		return JAL_E_INVAL;
	}
	jal_asprintf(&offset_str, "%"PRIu64, offset);
	uint64_t cnt = strlen(preamble) + 1;
	uint64_t tmp = strlen(serial_id) + strlen(JALN_CRLF);
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
	strcat(msg, serial_id);
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

enum jal_status jaln_create_sync_msg(const char *serial_id, char **msg_out, uint64_t *msg_len)
{
#define SYNC_MSG_HDRS JALN_MIME_PREAMBLE JALN_MSG_SYNC JALN_CRLF \
		JALN_HDRS_SERIAL_ID JALN_COLON_SPACE "%s" JALN_CRLF JALN_CRLF

	if (!serial_id || !msg_out || *msg_out || !msg_len) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = JAL_E_INVAL;
	char *msg = NULL;

	int len = jal_asprintf(&msg, SYNC_MSG_HDRS, serial_id);
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

uint64_t jaln_digest_info_strlen(const struct jaln_digest_info *di)
{
	// output for each line should be:
	// <dgst_as_hex>=<serial_id>CRLF
	if (!di || !di->serial_id || !di->digest || 0 == di->digest_len) {
		return 0;
	}
	if (0 == strlen(di->serial_id)) {
		return 0;
	}
	// start with cnt == 3 ('=' CR LF)
	uint64_t cnt = 3;
	uint64_t tmp = strlen(di->serial_id);
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
	// <dgst_as_hex>=<serial_id>CRLF
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
	sprintf(dst + (i * 2), "=%s" JALN_CRLF, di->serial_id);
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

enum jal_status jaln_create_init_msg(enum jaln_role role, enum jaln_publish_mode mode, enum jaln_record_type type,
		axlList *dgst_list, axlList *enc_list, char **msg_out, uint64_t *msg_len_out)
{
	if (!dgst_list || !enc_list ||
			!msg_out || *msg_out || !msg_len_out) {
		return JAL_E_INVAL;
	}
	const char *preamble = JALN_MIME_PREAMBLE JALN_MSG_INIT JALN_CRLF \
			       JALN_HDRS_MODE JALN_COLON_SPACE;
	axlListCursor *cursor = NULL;
	enum jal_status ret = JAL_E_INVAL;

	// +1 for the NULL terminator
	uint64_t char_cnt = strlen(preamble) + 1;
	char *role_str;
	switch (role) {
		case JALN_ROLE_SUBSCRIBER:
			switch (mode) {
				case JALN_LIVE_MODE:
					role_str = JALN_MSG_SUBSCRIBE_LIVE;
					break;
				case JALN_ARCHIVE_MODE:
					role_str = JALN_MSG_SUBSCRIBE_ARCHIVE;
					break;
				default:
					return JAL_E_INVAL;
			}
			break;
		case JALN_ROLE_PUBLISHER:
			switch (mode) {
				case JALN_LIVE_MODE:
					role_str = JALN_MSG_PUBLISH_LIVE;
					break;
				case JALN_ARCHIVE_MODE:
					role_str = JALN_MSG_PUBLISH_ARCHIVE;
					break;
				default:
					return JAL_E_INVAL;
			}
			break;
		default:
			return JAL_E_INVAL;
	}
	if (!jaln_safe_add_size(&char_cnt, strlen(role_str))) {
		goto out;
	}
	if (!jaln_safe_add_size(&char_cnt, strlen(JALN_CRLF))) {
		goto out;
	}
	if (!jaln_safe_add_size(&char_cnt, strlen(JALN_HDRS_DATA_CLASS JALN_COLON_SPACE))) {
		goto out;
	}

	char *type_str;
	switch (type) {
		case JALN_RTYPE_JOURNAL:
			type_str = JALN_STR_JOURNAL;
			break;
		case JALN_RTYPE_AUDIT:
			type_str = JALN_STR_AUDIT;
			break;
		case JALN_RTYPE_LOG:
			type_str = JALN_STR_LOG;
			break;
		default:
			return JAL_E_INVAL;
	}
	if (!jaln_safe_add_size(&char_cnt, strlen(type_str))) {
		goto out;
	}
	if (!jaln_safe_add_size(&char_cnt, strlen(JALN_CRLF))) {
		goto out;
	}

	if (!axl_list_is_empty(dgst_list)) {
		cursor = axl_list_cursor_new(dgst_list);
		axl_list_cursor_first(cursor);
		if (!jaln_safe_add_size(&char_cnt, strlen(JALN_HDRS_ACCEPT_DIGEST JALN_COLON_SPACE))) {
			goto out;
		}
		int dgst_cnt = 0;
		while(axl_list_cursor_has_item(cursor)) {
			struct jal_digest_ctx *dgst = (struct jal_digest_ctx *)axl_list_cursor_get(cursor);
			if (!jaln_safe_add_size(&char_cnt, strlen(dgst->algorithm_uri))) {
				goto out;
			}
			dgst_cnt += 1;
			axl_list_cursor_next(cursor);
		}
		// for each dgst in the list (except the last one), need to add
		// a ", ".
		if (!jaln_safe_add_size(&char_cnt, 2 * (dgst_cnt - 1) + strlen(JALN_CRLF))) {
			goto out;
		}
		axl_list_cursor_free(cursor);
		cursor = NULL;
	}

	if (!axl_list_is_empty(enc_list)) {
		cursor = axl_list_cursor_new(enc_list);
		axl_list_cursor_first(cursor);
		if (!jaln_safe_add_size(&char_cnt, strlen(JALN_HDRS_ACCEPT_ENCODING JALN_COLON_SPACE))) {
			goto out;
		}
		int enc_cnt = 0;
		while(axl_list_cursor_has_item(cursor)) {
			char *enc = (char *)axl_list_cursor_get(cursor);
			if (!jaln_safe_add_size(&char_cnt, strlen(enc))) {
				goto out;
			}
			enc_cnt += 1;
			axl_list_cursor_next(cursor);
		}
		// for each dgst in the list (except the last one), need to add
		// a ", ".
		if (!jaln_safe_add_size(&char_cnt, 2 * (enc_cnt - 1) + strlen(JALN_CRLF))) {
			goto out;
		}
		axl_list_cursor_free(cursor);
		cursor = NULL;
	}

	if (!jaln_safe_add_size(&char_cnt, strlen(JALN_CRLF))) {
		goto out;
	}

	char *init_msg = (char*) jal_malloc(char_cnt);
	init_msg[0] = '\0';
	strcat(init_msg, preamble);
	strcat(init_msg, role_str);
	strcat(init_msg, JALN_CRLF JALN_HDRS_DATA_CLASS JALN_COLON_SPACE);
	strcat(init_msg, type_str);
	strcat(init_msg, JALN_CRLF);

	if (!axl_list_is_empty(dgst_list)) {
		strcat(init_msg, JALN_HDRS_ACCEPT_DIGEST JALN_COLON_SPACE);
		cursor = axl_list_cursor_new(dgst_list);
		axl_list_cursor_first(cursor);
		while(axl_list_cursor_has_item(cursor)) {
			struct jal_digest_ctx *dgst =
				(struct jal_digest_ctx *)axl_list_cursor_get(cursor);
			strcat(init_msg, dgst->algorithm_uri);
			axl_list_cursor_next(cursor);
			if (axl_list_cursor_has_item(cursor)) {
				strcat(init_msg, ", ");
			}
		}
		strcat(init_msg, JALN_CRLF);
		axl_list_cursor_free(cursor);
		cursor = NULL;
	}

	if (!axl_list_is_empty(enc_list)) {
		strcat(init_msg, JALN_HDRS_ACCEPT_ENCODING JALN_COLON_SPACE);
		cursor = axl_list_cursor_new(enc_list);
		axl_list_cursor_first(cursor);
		while(axl_list_cursor_has_item(cursor)) {
			char *enc = (char *)axl_list_cursor_get(cursor);
			strcat(init_msg, enc);
			axl_list_cursor_next(cursor);
			if (axl_list_cursor_has_item(cursor)) {
				strcat(init_msg, ", ");
			}
		}
		strcat(init_msg, JALN_CRLF);
		axl_list_cursor_free(cursor);
		cursor = NULL;
	}
	strcat(init_msg, JALN_CRLF);
	*msg_out = init_msg;
	*msg_len_out = char_cnt - 1;
	ret = JAL_OK;
out:
	if (cursor) {
		axl_list_cursor_free(cursor);
	}
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
		JALN_HDRS_SERIAL_ID JALN_COLON_SPACE "%s" JALN_CRLF \
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
	// <dgst_as_hex>=<serial_id>CRLF
	if (!di || !di->serial_id) {
		return 0;
	}
	if (0 == strlen(di->serial_id)) {
		return 0;
	}
	// start with cnt == 2 (CR LF)
	uint64_t cnt = 2;
	if (!jaln_safe_add_size(&cnt, strlen(di->serial_id))) {
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
	// <dgst_status>=<serial_id>CRLF
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
	strcat(dst, di->serial_id);
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
