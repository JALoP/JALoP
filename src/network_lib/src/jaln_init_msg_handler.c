/**
 * @file jaln_init_msg_handler.c This file contains the function
 * definitions for helper functions used to process an 'initialize'
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


#include "jaln_init_msg_handler.h"
#include "jaln_message_helpers.h"
#include "jaln_strings.h"
#include <jalop/jaln_network_types.h>

#include "jal_alloc.h"

enum jal_status jaln_process_init(VortexFrame *frame, struct jaln_init_info **info_out)
{
	if (!frame || !info_out || *info_out) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = JAL_E_INVAL;

	struct jaln_init_info *info = jaln_init_info_create();

	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		goto err_out;
	}

	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (!msg) {
		goto err_out;
	}

	if (0 != strcasecmp(msg, JALN_MSG_INIT)) {
		goto err_out;
	}

	const char *role = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MODE);
	if (!role) {
		goto err_out;
	}
	if (0 == strcasecmp(role, JALN_MSG_SUBSCRIBE_LIVE)) {
		info->role = JALN_ROLE_SUBSCRIBER;
		info->mode = JALN_LIVE_MODE;
	} else if (0 ==strcasecmp(role, JALN_MSG_SUBSCRIBE_ARCHIVE)) {
		info->role = JALN_ROLE_SUBSCRIBER;
		info->mode = JALN_ARCHIVE_MODE;
	} else if (0 == strcasecmp(role, JALN_MSG_PUBLISH_LIVE)) {
		info->role = JALN_ROLE_PUBLISHER;
		info->mode = JALN_LIVE_MODE;
	} else if (0 == strcasecmp(role, JALN_MSG_PUBLISH_ARCHIVE)) {
		info->role = JALN_ROLE_PUBLISHER;
		info->mode = JALN_ARCHIVE_MODE;
	} else {
		goto err_out;
	}
	const char *type = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_RECORD_TYPE);
	if (!type) {
		goto err_out;
	}
	if (0 == strcasecmp(type, JALN_STR_JOURNAL)) {
		info->type = JALN_RTYPE_JOURNAL;
	} else if (0 == strcasecmp(type, JALN_STR_AUDIT)) {
		info->type = JALN_RTYPE_AUDIT;
	} else if (0 == strcasecmp(type, JALN_STR_LOG)) {
		info->type = JALN_RTYPE_LOG;
	} else {
		goto err_out;
	}
	const char *agent = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_AGENT);
	if (agent) {
		info->peer_agent = jal_strdup(agent);
	}
	char *cpy = NULL;
	const char *accept_dgst = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_ACCEPT_DIGEST);
	if (accept_dgst) {
		cpy = jal_strdup(accept_dgst);
		char *cookie = NULL;
		char *token = NULL;
		for (token = strtok_r(cpy, ",", &cookie);
				token != NULL;
				token = strtok_r(NULL, ",", &cookie)) {
			axl_stream_trim(token);
			if (0 == strlen(token)) {
				free(cpy);
				cpy = NULL;
				goto err_out;
			}
			axl_list_append(info->digest_algs, jal_strdup(token));
		}
		free(cpy);
		cpy = NULL;
	} else {
		axl_list_append(info->digest_algs, jal_strdup(JALN_DGST_SHA256));
	}
	const char *accept_enc = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_ACCEPT_ENCODING);
	if (accept_enc) {
		cpy = jal_strdup(accept_enc);
		char *cookie = NULL;
		char *token = NULL;
		for (token = strtok_r(cpy, ",", &cookie);
				token != NULL;
				token = strtok_r(NULL, ",", &cookie)) {
			axl_stream_trim(token);
			if (0 == strlen(token)) {
				goto err_out;
			}
			axl_list_append(info->encodings, jal_strdup(token));
		}
		free(cpy);
		cpy = NULL;
	} else {
		axl_list_append(info->encodings, jal_strdup(JALN_ENC_XML));
	}
	ret = JAL_OK;
	*info_out = info;
	goto out;
err_out:
	jaln_init_info_destroy(&info);
out:
	return ret;
}

