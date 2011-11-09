/**
 * @file jaln_channel_info.c This file contains function
 * definitions for internal library functions related to a jaln_channel_info
 * structure.
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
#include <vortex.h>
#include <jalop/jaln_publisher_callbacks.h>

#include "jaln_context.h"
#include "jaln_digest_info.h"
#include "jaln_digest_resp_info.h"
#include "jaln_publisher.h"
#include "jaln_session.h"
#include "jaln_sync_msg_handler.h"

void jaln_pub_notify_digests_and_create_digest_response(
		struct jaln_session *sess,
		axlList *calc_dgsts,
		axlList *peer_dgsts,
		axlList **dgst_resp_infos)
{
	if (!sess || !sess->jaln_ctx || !sess->ch_info || !sess->jaln_ctx->pub_callbacks ||
			!sess->jaln_ctx->pub_callbacks->peer_digest ||
			!calc_dgsts || !peer_dgsts || !dgst_resp_infos ||
			*dgst_resp_infos) {
		return;
	}

	axlList *resps = jaln_digest_resp_list_create();

	axlListCursor *calc_cursor = axl_list_cursor_new(calc_dgsts);
	axlListCursor *peer_cursor = axl_list_cursor_new(peer_dgsts);

	axl_list_cursor_first(peer_cursor);
	while(axl_list_cursor_has_item(peer_cursor)) {
		struct jaln_digest_info *peer_di = (struct jaln_digest_info*) axl_list_cursor_get(peer_cursor);
		struct jaln_digest_info *calc_di = NULL;

		axl_list_cursor_first(calc_cursor);
		while(axl_list_cursor_has_item(calc_cursor)) {
			struct jaln_digest_info *tmp = (struct jaln_digest_info*) axl_list_cursor_get(calc_cursor);
			if (tmp && (0 == strcmp(peer_di->serial_id, tmp->serial_id))) {
				calc_di = tmp;
				axl_list_cursor_unlink(calc_cursor);
				break;
			}
			axl_list_cursor_next(calc_cursor);
		}

		struct jaln_digest_resp_info *resp_info = NULL;
		if (!calc_di) {
			sess->jaln_ctx->pub_callbacks->peer_digest(sess->ch_info,
					sess->ch_info->type,
					peer_di->serial_id,
					NULL, 0,
					peer_di->digest, peer_di->digest_len,
					sess->jaln_ctx->user_data);

			resp_info = jaln_digest_resp_info_create(peer_di->serial_id, JALN_DIGEST_STATUS_UNKNOWN);
		} else {
			if (jaln_digests_are_equal(peer_di, calc_di)) {
				resp_info = jaln_digest_resp_info_create(peer_di->serial_id, JALN_DIGEST_STATUS_CONFIRMED);
			} else {
				resp_info = jaln_digest_resp_info_create(peer_di->serial_id, JALN_DIGEST_STATUS_INVALID);
			}

			sess->jaln_ctx->pub_callbacks->peer_digest(sess->ch_info,
					sess->ch_info->type,
					peer_di->serial_id,
					calc_di->digest, calc_di->digest_len,
					peer_di->digest, peer_di->digest_len,
					sess->jaln_ctx->user_data);
		}
		axl_list_append(resps, resp_info);

		jaln_digest_info_destroy(&calc_di);

		axl_list_cursor_next(peer_cursor);
	}
	axl_list_cursor_free(peer_cursor);
	axl_list_cursor_free(calc_cursor);
	*dgst_resp_infos = resps;
}

enum jal_status jaln_publisher_handle_sync(struct jaln_session *sess,
		VortexChannel *chan,
		VortexFrame *frame,
		int msg_no)
{
	axl_bool ans_rpy_sent = vortex_channel_finalize_ans_rpy(chan, msg_no);
	char *serial_id = NULL;
	enum jal_status ret = JAL_E_INVAL;
	if (!sess || !sess->jaln_ctx || !sess->jaln_ctx->pub_callbacks || 
			!sess->jaln_ctx->pub_callbacks->sync || !sess->ch_info) {
		goto out;
	}
	ret = jaln_process_sync(frame, &serial_id);
	if (ret != JAL_OK) {
		goto out;
	}
	sess->jaln_ctx->pub_callbacks->sync(sess->ch_info, sess->ch_info->type, serial_id, NULL, sess->jaln_ctx->user_data);
	free(serial_id);
out:
	if (!ans_rpy_sent) {
		ret = JAL_E_COMM;
	}
	return ret;
}

