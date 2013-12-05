/**
 * @file jaln_journal_resume_msg_handler.c This file contains the function
 * definitions for helper functions used to process an 'journal-resume'
 * message.
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

#include <jalop/jaln_network_types.h>

#include "jal_alloc.h"

#include "jaln_journal_resume_msg_handler.h"
#include "jaln_message_helpers.h"
#include "jaln_strings.h"
#include "jaln_string_utils.h"

enum jal_status jaln_process_journal_resume(VortexFrame *frame, char **nonce_out, uint64_t *offset_out)
{
	enum jal_status ret = JAL_E_INVAL;
	char *nonce = NULL;

	if (!frame || !nonce_out || *nonce_out || !offset_out) {
		goto err_out;
	}

	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		goto err_out;
	}

	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (!msg) {
		return JAL_E_INVAL;
	}
	if (0 != strcasecmp(msg, JALN_MSG_JOURNAL_RESUME)) {
		goto err_out;
	}

	const char *nonce_from_frame = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_NONCE);
	if (!nonce_from_frame) {
		goto err_out;
	}
	nonce = jal_strdup(nonce_from_frame);
	axl_stream_trim(nonce);
	if (0 == strlen(nonce)) {
		goto err_out;
	}

	const char *offset_str = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_JOURNAL_OFFSET);
	if (!offset_str) {
		goto err_out;
	}
	if (!jaln_ascii_to_uint64(offset_str, offset_out)) {
		goto err_out;
	}

	ret = JAL_OK;
	*nonce_out = nonce;

	goto out;

err_out:
	free(nonce);
out:
	return ret;
}

