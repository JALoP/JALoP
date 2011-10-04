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
#include <string.h>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#include "jaln_message_helpers.h"
#include "jaln_strings.h"

enum jal_status jaln_create_journal_resume_msg(const char *serial_id,
		uint64_t offset, char **msg_out, size_t *msg_out_len)
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
	size_t cnt = strlen(preamble) + 1;
	size_t tmp = strlen(serial_id) + strlen(JALN_CRLF);
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
	*msg_out_len = cnt;
	ret = JAL_OK;
	goto out;
out:
	free(offset_str);
	return ret;
}

