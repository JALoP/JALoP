/**
 * @file jaln_digest_resp_msg_handler.c This file contains the function
 * definitions for helper functions used to process a 'digest-response'
 * message.
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

#include "jaln_digest_resp_msg_handler.h"
#include "jaln_message_helpers.h"
#include "jal_alloc.h"
#include "jaln_digest_resp_info.h"
#include "jaln_string_utils.h"
#include "jaln_strings.h"

enum jal_status jaln_process_digest_resp(VortexFrame *frame, axlList **dgst_resp_list_out)
{
	if (!frame || !dgst_resp_list_out || *dgst_resp_list_out) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = JAL_E_PARSE;

	axlList *dgst_resp_list = NULL;
	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		goto err_out;
	}

	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (!msg) {
		goto err_out;
	}
	if (0 != strcasecmp(msg, JALN_MSG_DIGEST_RESP)) {
		goto err_out;
	}
	const char *cnt_str = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_COUNT);
	uint64_t expected_cnt;
	if (!cnt_str) {
		goto err_out;
	}
	if (!jaln_ascii_to_uint64(cnt_str, &expected_cnt)) {
		goto err_out;
	}
	if (0 == expected_cnt) {
		goto err_out;
	}
	dgst_resp_list = axl_list_new(jaln_axl_equals_func_digest_resp_info_nonce, jaln_axl_destroy_digest_resp_info);
	if (!dgst_resp_list) {
		goto err_out;
	}
	char *payload = (char*) vortex_frame_get_payload(frame);

	if (!payload) {
		goto err_out;
	}
	int payload_sz = vortex_frame_get_payload_size(frame);
	if (0 > payload_sz) {
		goto err_out;
	}
	char *status_str;
	int last_tok_idx = 0;
	int idx;
	for (idx = 0; idx < payload_sz; idx++) {
		axl_bool looking_for_nonce = axl_false;
		enum jaln_digest_status status = JALN_DIGEST_STATUS_UNKNOWN;
		if ('=' == payload[idx]) {
			uint64_t len = idx - last_tok_idx + 1;
			status_str = jal_malloc(len);
			memcpy(status_str, payload + last_tok_idx, len - 1);
			status_str[len-1] = '\0';

			axl_bool valid_status = axl_false;
			if (0 == strcasecmp(status_str, JALN_STR_CONFIRMED)) {
				valid_status = axl_true;
				status =  JALN_DIGEST_STATUS_CONFIRMED;
			} else if (0 == strcasecmp(status_str, JALN_STR_INVALID)) {
				valid_status = axl_true;
				status =  JALN_DIGEST_STATUS_INVALID;
			} else if (0 == strcasecmp(status_str, JALN_STR_UNKNOWN)) {
				valid_status = axl_true;
				status =  JALN_DIGEST_STATUS_UNKNOWN;
			}
			free(status_str);
			status_str = NULL;

			if (!valid_status) {
				goto err_out;
			}
			idx++;
			int nonce_start = idx;
			looking_for_nonce = axl_true;
			for (; (payload_sz - 1) >= idx; idx++) {
				if ('\r' != payload[idx]) {
					continue;
				}
				if ('\n' != payload[idx + 1]) {
					goto err_out;
				}
				len = idx - nonce_start + 1;
				if (1 >= len) {
					goto err_out;
				}
				char *nonce_str = jal_malloc(len);
				memcpy(nonce_str, payload + nonce_start, len - 1);
				nonce_str[len-1] = '\0';
				// extra ++ to skip the '\n'
				idx++;
				axl_list_append(dgst_resp_list, jaln_digest_resp_info_create(nonce_str, status));
				free(nonce_str);
				last_tok_idx = idx + 1;
				// need to break out of the inner loop...
				//bad_parse = axl_false;
				looking_for_nonce = axl_false;
				break;
			}
			if (looking_for_nonce) {
				goto err_out;
			}
		}
	}
	if (last_tok_idx != idx) {
		// trailing garbage after the last entry;
		goto err_out;
	}
	int rec_cnt = axl_list_length(dgst_resp_list);
	if ((0 >= rec_cnt) || ((uint64_t) rec_cnt != expected_cnt)) {
		goto err_out;
	}
	*dgst_resp_list_out = dgst_resp_list;
	ret = JAL_OK;
	goto out;
err_out:
	if (dgst_resp_list) {
		axl_list_free(dgst_resp_list);
	}
out:
	return ret;
}

