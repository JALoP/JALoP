/**
 * @file
 *
 * @brief This file contains function
* definitions related to the jal publisher.
*
* ### LICENSE
*
* Copyright (C) 2018-2026 Concurrent Technologies Corporation.
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

#include <jalop/jaln_network.h>

#include "jal_alloc.h"
#include "jaln_context.h"
#include "jaln_message_helpers.h"
#include "jaln_session.h"
#include "jaldb_segment.h"
#include "jaln_send_impl.h"

enum jal_status jaln_send(
			jaln_session *sess,
			struct jaldb_record* rec)
{
	if (NULL == sess
			|| NULL == sess->ch_info
			|| NULL == rec
			|| NULL == rec->network_nonce
			|| NULL == rec->app_meta
			|| NULL == rec->sys_meta
			|| NULL == rec->payload) {
		return JAL_E_INVAL_PARAM;
	}

	// NOTE - Free digestOut and peerDigestOut before returning
	uint8_t* digestOut = NULL;
	uint8_t* peerDigestOut = NULL;
	uint32_t digestLenOut = 0;
	uint32_t peerDigestLenOut = 0;

	// In the old implementation, a copy of the nonce was stashed in pub_data
	// Make a copy of the nonce for use in communication that will persist
	// after the on_complete callback destroys the record itself
	// Ensure this is freed before exiting
	char* nonce = strdup(rec->network_nonce);
	// Send the record
	enum jal_status status = jaln_send_record_impl(
		sess,
		rec,
		&digestOut,
		&digestLenOut,
		&peerDigestOut,
		&peerDigestLenOut);

	// If we calculated a digest, notify the digest callback
	// To preserve previous behavior, emit this callback even if a later step in
	// the sending process failed
	if(NULL != digestOut) {
		sess->jaln_ctx->pub_callbacks->notify_digest(
			sess,
			sess->ch_info,
			sess->ch_info->type,
			nonce,
			digestOut,
			sess->dgst->len,
			sess->jaln_ctx->user_data);
	}

	// If the send failed, early return with error
	if(JAL_OK != status) {
		free(digestOut);
		free(peerDigestOut);
		free(nonce);
		return status;
	}

	// The message was sent, emit the message complete callback
	sess->jaln_ctx->pub_callbacks->on_record_complete(
			sess,
			sess->ch_info,
			sess->ch_info->type,
			nonce,
			sess->jaln_ctx->user_data);

	// If we weren't expecting a digest-challenge, we received a sync and we're done
	// Emit the on_sync callback
	if(!sess->dgst_on) {
		sess->jaln_ctx->pub_callbacks->sync(
			sess,
			sess->ch_info,
			sess->ch_info->type,
			sess->mode,
			nonce,
			NULL,
			sess->jaln_ctx->user_data);
		free(digestOut);
		free(peerDigestOut);
		free(nonce);
		return JAL_OK;
	}

	// Otherwise, we received a digest-challenge and succesfully extracted the digest value
	// Notify the peer digest callback
	sess->jaln_ctx->pub_callbacks->peer_digest(
		sess,
		sess->ch_info,
		sess->ch_info->type,
		nonce,
		digestOut,
		digestLenOut,
		peerDigestOut,
		peerDigestLenOut,
		sess->jaln_ctx->user_data);

	// Send the digest-challenge-response
	status = jaln_send_digest_response_impl(
		sess,
		nonce,
		digestOut,
		digestLenOut,
		peerDigestOut,
		peerDigestLenOut);

	// We either get an error, record-failure, session-failure, sync-failure, or a sync
	// If we get an OK status back, notify the sync callback
	// otherwise just clean up the local digest storage 
	// and return the status
	if(JAL_OK == status) {
		sess->jaln_ctx->pub_callbacks->sync(
			sess,
			sess->ch_info,
			sess->ch_info->type,
			sess->mode,
			nonce,
			NULL,
			sess->jaln_ctx->user_data);
	}

	free(digestOut);
	free(peerDigestOut);
	free(nonce);
	return status;
}

enum jal_status jaln_finish(jaln_session *sess)
{
	if (NULL == sess || NULL == sess->pub_data) {
		return JAL_E_INVAL_PARAM;
	}
	// cancel queued records and wait for any running ones to complete
	jaln_send_close_session(sess);
	jaln_context *ctx = sess->jaln_ctx;
	pthread_mutex_lock(&ctx->lock);
	ctx->conn_callbacks->on_channel_close(sess->ch_info, ctx->user_data);
	if (0 >= --ctx->sess_cnt) {
		ctx->conn_callbacks->on_connection_close(ctx->conn, ctx->user_data);
	}
	pthread_mutex_unlock(&ctx->lock);

	return JAL_OK;
}
