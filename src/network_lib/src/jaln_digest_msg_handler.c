/**
 * @file jaln_digest_msg_handler.c This file contains the function
 * definitions for helper functions used to process a 'digest'
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

#include "jaln_digest_msg_handler.h"
#include "jaln_message_helpers.h"
#include "jal_alloc.h"
#include "jaln_digest_info.h"
#include "jaln_string_utils.h"
#include "jaln_strings.h"

enum jal_status jaln_process_digest(VortexFrame *frame, axlList **dgst_list_out)
{
	if (!frame || !dgst_list_out || *dgst_list_out) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = JAL_E_PARSE;

	char *dgst_str = NULL;
	uint8_t *dgst_val = NULL;
	axlList *dgst_list = NULL;

	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		goto err_out;
	}

	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (!msg) {
		goto err_out;
	}
	if (0 != strcasecmp(msg, JALN_MSG_DIGEST)) {
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
	dgst_list = axl_list_new(jaln_axl_equals_func_digest_info_nonce, jaln_axl_destroy_digest_info);
	if (!dgst_list) {
		goto err_out;
	}
	char *payload = (char*) vortex_frame_get_payload(frame);

	if (!payload) {
		goto err_out;
	}
	int payload_sz = vortex_frame_get_payload_size(frame);
	if (0 >= payload_sz) {
		goto err_out;
	}
	int last_tok_idx = 0;
	int idx;
	for (idx = 0; idx < payload_sz; idx++) {
		axl_bool looking_for_nonce = axl_false;
		if ('=' == payload[idx]) {
			uint64_t len = idx - last_tok_idx;
			dgst_str = jal_malloc(len);
			memcpy(dgst_str, payload + last_tok_idx, len);

			uint64_t dgst_len = 0;
			if (JAL_OK != jaln_hex_str_to_bin_buf(dgst_str, len, &dgst_val, &dgst_len)) {
				goto err_out;
			}
			free(dgst_str);
			dgst_str = NULL;

			idx++;
			int nonce_start = idx;
			looking_for_nonce = axl_true;
			for (; idx <= payload_sz - 1; idx++) {
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
				axl_list_append(dgst_list, jaln_digest_info_create(nonce_str, dgst_val, dgst_len));
				free(dgst_val);
				dgst_val = NULL;
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
		goto err_out;
	}
	int rec_cnt = axl_list_length(dgst_list);
	if ((0 >= rec_cnt) || ((uint64_t) rec_cnt != expected_cnt)) {
		goto err_out;
	}
	*dgst_list_out = dgst_list;
	ret = JAL_OK;
	goto out;
err_out:
	free(dgst_str);
	free(dgst_val);
	if (dgst_list) {
		axl_list_free(dgst_list);
	}
out:
	return ret;
}

