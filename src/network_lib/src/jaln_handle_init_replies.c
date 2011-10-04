/**
 * @file jaln_handl_init_replies.c This file contains function
 * definitions for internal library functions related to processing responses
 * to 'initialize' messages (init-ack/init-nack).
 *
 * @section LICENSE
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

#include "jaln_context.h"
#include "jaln_handle_init_replies.h"
#include "jaln_strings.h"

int jaln_handle_initialize_nack(struct jaln_session *sess,
		VortexFrame *frame)
{
	int err_cnt = 0;
	if (sess == NULL || frame == NULL || !sess->jaln_ctx ||
			!sess->jaln_ctx->conn_callbacks) {
		return axl_false;
	}
	char *err_strs[4];
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_UNAUTHORIZED_MODE)) {
		err_strs[err_cnt++] = JALN_HDRS_UNAUTHORIZED_MODE;
	}
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_UNSUPPORTED_MODE)) {
		err_strs[err_cnt++] = JALN_HDRS_UNSUPPORTED_MODE;
	}
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_UNSUPPORTED_ENCODING)) {
		err_strs[err_cnt++] = JALN_HDRS_UNSUPPORTED_ENCODING;
	}
	if (VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_UNSUPPORTED_DIGEST)) {
		err_strs[err_cnt++] = JALN_HDRS_UNSUPPORTED_DIGEST;
	}
	struct jaln_connect_nack nack;
	memset(&nack, 0, sizeof(nack));
	nack.ch_info = sess->ch_info;
	nack.error_list = err_strs;
	nack.error_cnt = err_cnt;
	sess->jaln_ctx->conn_callbacks->connect_nack(&nack, sess->jaln_ctx->user_data);
	return axl_true;
}
