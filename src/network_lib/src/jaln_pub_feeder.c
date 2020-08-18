/**
 * @file jaln_pub_feeder.c This file contains the functions related to the
 * implementation of VortexPayloadFeeder for sending records from a publisher
 * to a subscriber.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <limits.h>

#include "jal_alloc.h"
#include "jaln_pub_feeder.h"
#include "jaln_context.h"
#include "jaln_message_helpers.h"
#include "jaln_publisher.h"
#include "jaln_strings.h"
// This is for the 'copy_buffer' function, which should probably get re-factored
// to a different file.
#include "jaln_subscriber_state_machine.h"

axl_bool jaln_pub_feeder_get_size(jaln_session *sess, uint64_t *size)
{
	// expect that the pub_data is already filled out...
	*size = sess->pub_data->vortex_feeder_sz - sess->pub_data->payload_off;
	return axl_true;
}

size_t jaln_pub_feeder_fill_buffer(void *b, size_t size, size_t nmemb, void *userdata) {

	uint64_t dst_sz = size * nmemb;
	uint64_t dst_off = 0;
	struct jaln_readfunc_info *info = (struct jaln_readfunc_info *)userdata;
	jaln_session *sess = info->sess;
	struct jaln_pub_data *pd = sess->pub_data;
	struct jaln_publisher_callbacks *cbs = sess->jaln_ctx->pub_callbacks;
	struct jaln_channel_info *ch_info = sess->ch_info;
	void *ud = sess->jaln_ctx->user_data;
	uint8_t *buffer = (uint8_t*)b;
	enum jal_status ret = JAL_OK;
	size_t curl_ret = 0;

	if (pd->finished_payload_break) {
		// We're done sending
		curl_ret = 0;
		goto out;
	}

	if (sess->errored) {
		curl_ret = CURL_READFUNC_ABORT;
		goto out;
	}

	if (!pd->finished_sys_meta && (dst_sz > dst_off)) {
		jaln_copy_buffer(buffer, dst_sz, &dst_off, pd->sys_meta, pd->sys_meta_sz, &pd->sys_meta_off, axl_true);
		if (pd->sys_meta_sz == pd->sys_meta_off) {
			pd->finished_sys_meta = axl_true;
		}
	}

	if (!pd->finished_sys_meta_break && (dst_sz > dst_off)) {
		jaln_copy_buffer(buffer, dst_sz, &dst_off, (uint8_t*)JALN_STR_BREAK, strlen(JALN_STR_BREAK), &pd->break_off, axl_true);
		if (strlen(JALN_STR_BREAK) == pd->break_off) {
			pd->finished_sys_meta_break = axl_true;
			pd->break_off = 0;
		}
	}

	if (!pd->finished_app_meta && (dst_sz > dst_off)) {
		jaln_copy_buffer(buffer, dst_sz, &dst_off, pd->app_meta, pd->app_meta_sz, &pd->app_meta_off, axl_true);
		if (pd->app_meta_off == pd->app_meta_sz) {
			pd->finished_app_meta = axl_true;
			pd->sys_meta = NULL;
			pd->sys_meta_off = 0;
			pd->sys_meta_sz = 0;
			pd->app_meta = NULL;
			pd->app_meta_sz = 0;
			pd->app_meta_off = 0;
		}
	}

	if (!pd->finished_app_meta_break && (dst_sz > dst_off)) {
		jaln_copy_buffer(buffer, dst_sz, &dst_off, (uint8_t*)JALN_STR_BREAK, strlen(JALN_STR_BREAK), &pd->break_off, axl_true);
		if (strlen(JALN_STR_BREAK) == pd->break_off) {
			pd->finished_app_meta_break = axl_true;
			pd->break_off = 0;
		}
	}

	if (!pd->finished_payload && (dst_sz > dst_off)) {
		switch (ch_info->type) {
		case JALN_RTYPE_AUDIT:
		case JALN_RTYPE_LOG: {
			uint64_t tmp_offset = pd->payload_off;
			jaln_copy_buffer(buffer, dst_sz, &dst_off, pd->payload, pd->payload_sz, &tmp_offset, axl_true);
			pd->payload_off = tmp_offset;
			break;
		}
		case JALN_RTYPE_JOURNAL: {
			uint64_t left_in_buffer = dst_sz - dst_off;
			uint64_t bytes_acquired = left_in_buffer;

			ret = pd->journal_feeder.get_bytes(pd->payload_off,
							buffer + dst_off,
							&bytes_acquired,
							pd->journal_feeder.feeder_data);
			if (ret != JAL_OK || (bytes_acquired > left_in_buffer)) {
				curl_ret = CURL_READFUNC_ABORT;
				goto out;
			}

			ret = sess->dgst->update(pd->dgst_inst, buffer + dst_off, bytes_acquired);
			if (JAL_OK != ret) {
				curl_ret = CURL_READFUNC_ABORT;
				goto out;
			}

			dst_off += bytes_acquired;
			pd->payload_off += bytes_acquired;
			break;
		}
		default:
			curl_ret = CURL_READFUNC_ABORT;
			goto out;
		}
		if (pd->payload_sz == pd->payload_off) {
			pd->finished_payload = axl_true;
			size_t dgst_len = sess->dgst->len;
			if (JAL_OK != sess->dgst->final(pd->dgst_inst, pd->dgst, &dgst_len)) {
				curl_ret = CURL_READFUNC_ABORT;
				goto out;
			}

			jaln_session_add_to_dgst_list(sess, pd->nonce, pd->dgst, dgst_len);
			cbs->notify_digest(sess, ch_info, ch_info->type, pd->nonce, pd->dgst, dgst_len, ud);
			pd->payload = NULL;
		}
	}

	if (!pd->finished_payload_break && (dst_sz > dst_off)) {
		jaln_copy_buffer(buffer, dst_sz, &dst_off, (uint8_t*)JALN_STR_BREAK, strlen(JALN_STR_BREAK), &pd->break_off, axl_true);
		if (strlen(JALN_STR_BREAK) == pd->break_off) {
			pd->finished_payload_break = axl_true;
			pd->break_off = 0;
		}
	}
	curl_ret = dst_off;

out:
	if (curl_ret == CURL_READFUNC_ABORT || curl_ret == 0) {
		vortex_mutex_unlock(&sess->wait_lock);
		jaln_pub_feeder_on_finished(sess);
		info->complete = axl_true;
	}
	return curl_ret;
}

axl_bool jaln_pub_feeder_is_finished(jaln_session *sess, int *finished)
{
	*finished = sess->errored || sess->pub_data->finished_payload_break;
	return *finished;
}

static enum jal_status jaln_pub_verify_sync(jaln_session *sess, struct jaln_response_header_info *info)
{
	enum jal_status rc;
	if (!info->last_message) {
		rc = JAL_E_INVAL;
	}
	else if (!strcmp(info->last_message, JALN_MSG_SYNC)) {
		rc = jaln_verify_sync_headers(info);
		if (rc == JAL_OK && !sess->errored) {
			sess->jaln_ctx->pub_callbacks->sync(sess, sess->ch_info, sess->ch_info->type,\
					sess->mode, info->expected_nonce, NULL, sess->jaln_ctx->user_data);
		}
	} else if (!strcmp(info->last_message, JALN_MSG_SYNC_FAILURE)) {
		rc = jaln_verify_sync_failure_headers(info);
	} else if (!strcmp(info->last_message, JALN_MSG_RECORD_FAILURE)) {
		rc = jaln_verify_record_failure_headers(info);
	} else {
		rc = JAL_E_INVAL;
	}
	return rc;
}

void * APR_THREAD_FUNC jaln_pub_feeder_handler(
		__attribute__((unused)) apr_thread_t *thread,
		void *user_data)
{
	jaln_session *sess = (jaln_session*) user_data;

	vortex_mutex_lock(&sess->lock);
	CURL *ctx = curl_easy_duphandle(sess->curl_ctx);
	vortex_mutex_unlock(&sess->lock);
	if (!ctx) {
		// Error
		jaln_session_set_errored(sess);
		goto out;
	}

	struct jaln_response_header_info *info = jaln_response_header_info_create(sess);
	info->expected_nonce = jal_strdup(sess->pub_data->nonce);

	uint64_t size;
	jaln_pub_feeder_get_size(sess, &size);
	curl_easy_setopt(ctx, CURLOPT_POSTFIELDSIZE_LARGE, size);

	struct jaln_readfunc_info read_info = { sess, axl_false };
	curl_easy_setopt(ctx, CURLOPT_READFUNCTION, jaln_pub_feeder_fill_buffer);
	curl_easy_setopt(ctx, CURLOPT_READDATA, &read_info);

	if (sess->dgst_on) {
		curl_easy_setopt(ctx, CURLOPT_HEADERFUNCTION, jaln_publisher_digest_challenge_handler);
	} else {
		// if digest challenges are configured to be disabled, the protcol jumps straight to sync
		curl_easy_setopt(ctx, CURLOPT_HEADERFUNCTION, jaln_publisher_sync_handler);
	}

	curl_easy_setopt(ctx, CURLOPT_HEADERDATA, info);

	vortex_mutex_lock(&sess->wait_lock);

	curl_easy_setopt(ctx, CURLOPT_HTTPHEADER, sess->pub_data->headers);

	char buf[CURL_ERROR_SIZE];

	curl_easy_setopt(ctx, CURLOPT_ERRORBUFFER, &buf);

	CURLcode res = curl_easy_perform(ctx);

	if (res != CURLE_OK || sess->errored) {
		printf("Failed: %d: %s\n", res, buf); // TODO: Printfs in libraries are bad.  Remove me once the library is more stable
		jaln_session_set_errored(sess);
		if (!read_info.complete) {
			vortex_mutex_unlock(&sess->wait_lock);
			vortex_cond_signal(&sess->wait);
		}
		jaln_response_header_info_destroy(&info);
		goto out;
	}


	enum jal_status rc;

	if (!sess->dgst_on) {
		// if digest challenges are configured to be disabled, the sync has alreay ocurred
		rc = jaln_pub_verify_sync(sess, info);
		curl_easy_cleanup(ctx);
		if (JAL_OK != rc && JAL_OK != jaln_verify_sync_failure_headers(info)) {
			perror("Sync verification failed"); // TODO: Remove me once the library is more stable
			jaln_session_set_errored(sess);
		}
		jaln_response_header_info_destroy(&info);
		goto out;
	}

	if (JAL_OK != jaln_verify_digest_challenge_headers(info)) {
		if (JAL_OK != jaln_verify_record_failure_headers(info)) {
			perror("Digest challenge verification failed"); // TODO: Remove me once the library is more stable
			jaln_session_set_errored(sess);
		}
		jaln_response_header_info_destroy(&info);
		goto out;
	}

	// Send digest response

	struct jaln_digest_resp_info *resp_info = NULL;

	struct jaln_digest_info *peer_dgst = jaln_digest_info_create(info->expected_nonce, info->peer_dgst, info->peer_dgst_len);
	jaln_pub_notify_digests_and_create_digest_response(sess, sess->dgst_list, peer_dgst, &resp_info);

	char *resp_header = NULL;
	uint64_t resp_header_len = 0;
	jaln_create_digest_response_msg(sess->id, resp_info, &resp_header, &resp_header_len);

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, resp_header);
	free(resp_header);

	curl_easy_setopt(ctx, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(ctx, CURLOPT_POSTFIELDSIZE, 0L);

	if (JALN_DIGEST_STATUS_CONFIRMED == resp_info->status) {
		curl_easy_setopt(ctx, CURLOPT_HEADERFUNCTION, jaln_publisher_sync_handler);
	} else {
		curl_easy_setopt(ctx, CURLOPT_HEADERFUNCTION, jaln_publisher_failed_digest_handler);
	}
	curl_easy_setopt(ctx, CURLOPT_HEADERDATA, info);

	res = curl_easy_perform(ctx);

	if (JALN_DIGEST_STATUS_CONFIRMED == resp_info->status) {
		rc = jaln_pub_verify_sync(sess, info);
	} else {
		rc = jaln_verify_failed_digest_headers(info);
	}

	if (res != CURLE_OK || rc != JAL_OK) {
		printf("Failed digest resp: %d, %s\n", res? (int)res : rc, res? buf : "JAL_E_INVAL"); // TODO: Remove
		jaln_session_set_errored(sess);
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(ctx);
	jaln_digest_resp_info_destroy(&resp_info);
	jaln_digest_info_destroy(&peer_dgst);
	jaln_response_header_info_destroy(&info);

out:
	jaln_session_unref(sess);
	return NULL;
}

void jaln_pub_feeder_reset_state(jaln_session *sess)
{
	if (!sess || !sess->pub_data) {
		return;
	}

	struct jaln_pub_data *pd = sess->pub_data;

	free(pd->nonce);
	curl_slist_free_all(pd->headers);
	pd->headers = NULL;

	pd->nonce = NULL;
	pd->sys_meta = NULL;
	pd->app_meta = NULL;
	pd->payload = NULL;
	pd->vortex_feeder_sz = 0;
	pd->headers_off = 0;
	pd->sys_meta_off = 0;
	pd->app_meta_off = 0;
	pd->payload_off = 0;
	pd->break_off = 0;

	pd->finished_headers = axl_false;
	pd->finished_sys_meta = axl_false;
	pd->finished_sys_meta_break = axl_false;
	pd->finished_app_meta = axl_false;
	pd->finished_app_meta_break = axl_false;
	pd->finished_payload = axl_false;
	pd->finished_payload_break = axl_false;

	if (!pd->dgst_inst) {
		pd->dgst_inst = sess->dgst->create();
		if (!pd->dgst_inst) {
			goto err_out;
		}
	}

	if (JAL_OK != sess->dgst->init(pd->dgst_inst)) {
		goto err_out;
	}

	if (pd->dgst) {
		memset(pd->dgst, '\0', sess->dgst->len);
	} else {
		pd->dgst = (uint8_t*)jal_calloc(1, sess->dgst->len);
	}

	return;
err_out:
	jaln_session_set_errored(sess);
}

void jaln_pub_feeder_calculate_size_for_vortex(jaln_session *sess)
{
	if (!sess || !sess->pub_data) {
		return;
	}
	struct jaln_pub_data *pd = sess->pub_data;
	pd->vortex_feeder_sz = 0;
	if (!jaln_pub_feeder_safe_add_size(&pd->vortex_feeder_sz, pd->payload_sz)) {
		return;
	}
	if (!jaln_pub_feeder_safe_add_size(&pd->vortex_feeder_sz, pd->app_meta_sz)) {
		return;
	}
	if (!jaln_pub_feeder_safe_add_size(&pd->vortex_feeder_sz, pd->sys_meta_sz)) {
		return;
	}
	if (!jaln_pub_feeder_safe_add_size(&pd->vortex_feeder_sz, pd->headers_sz)) {
		return;
	}
	jaln_pub_feeder_safe_add_size(&pd->vortex_feeder_sz, 3 * strlen(JALN_STR_BREAK));
}

axl_bool jaln_pub_feeder_safe_add_size(int64_t *cnt, const uint64_t to_add)
{
	if (INT64_MAX < to_add) {
		*cnt = INT64_MAX;
		return axl_false;
	}
	if ((INT64_MAX - to_add) < (uint64_t) *cnt) {
		*cnt = INT64_MAX;
		return axl_false;
	}
	*cnt += to_add;
	return axl_true;
}

enum jal_status jaln_pub_begin_next_record_ans(jaln_session *sess,
						struct jaln_record_info *rec_info)
{
	if (!sess || !sess->pub_data) {
		return JAL_E_INVAL;
	}

	struct jaln_pub_data *pd = sess->pub_data;

	struct curl_slist *headers = jaln_create_record_ans_rpy_headers(rec_info, sess);
	if (!headers) {
		return JAL_E_INVAL;
	}

	pd->headers = headers;

	jaln_pub_feeder_calculate_size_for_vortex(sess);

	jaln_session_ref(sess);

	vortex_mutex_lock(&sess->wait_lock);

	if (APR_SUCCESS != apr_thread_pool_push(sess->jaln_ctx->threads,
	                                        jaln_pub_feeder_handler,
	                                        (void *) sess,
	                                        APR_THREAD_TASK_PRIORITY_NORMAL,
						(void *) sess)) { // use session as "owner" of the task
		jaln_session_unref(sess);
		vortex_mutex_unlock(&sess->wait_lock);
		return JAL_E_NO_MEM;
	}

	vortex_cond_wait(&sess->wait, &sess->wait_lock);
	vortex_mutex_unlock(&sess->wait_lock);
	return sess->errored? JAL_E_INVAL : JAL_OK;
}

void jaln_pub_feeder_on_finished(jaln_session *sess)
{
	struct jaln_channel_info *ch_info = sess->ch_info;
	enum jaln_record_type type = ch_info->type;
	struct jaln_pub_data *pd = sess->pub_data;
	struct jaln_publisher_callbacks *pub_cbs = sess->jaln_ctx->pub_callbacks;

	pub_cbs->on_record_complete(sess, ch_info, type, pd->nonce, sess->jaln_ctx->user_data);
	pd->payload_off = 0;

	vortex_mutex_lock(&sess->wait_lock);
	vortex_mutex_unlock(&sess->wait_lock);
	vortex_cond_signal(&sess->wait);
	return;
}
