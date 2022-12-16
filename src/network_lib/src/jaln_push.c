/**
* @file jaln_push.c  This file contains function
* definitions related to the jal publisher.
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

#include <jalop/jaln_network.h>

#include "jal_alloc.h"
#include "jaln_context.h"
#include "jaln_message_helpers.h"
#include "jaln_session.h"
#include "jaln_pub_feeder.h"
#include "jaln_push.h"

/*
 * Helper method used to initialize the record information
 * that is to be sent to the subscriber.
 */
enum jal_status jaln_send_record_init(
			jaln_session *sess,
			void *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len, 
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			struct jaln_record_info *rec_info)
{
	enum jal_status ret = JAL_E_INVAL;
	struct jaln_pub_data *pub_data = NULL;

	jaln_pub_feeder_reset_state(sess);

	pub_data = sess->pub_data;

	pub_data->nonce = jal_strdup(nonce);
	pub_data->sys_meta = sys_meta_buf;
	pub_data->sys_meta_sz = sys_meta_len;
	pub_data->app_meta = app_meta_buf;
	pub_data->app_meta_sz = app_meta_len;

	memset(rec_info, 0, sizeof(*rec_info));
	rec_info->type = sess->ch_info->type;
	rec_info->nonce = nonce;
	rec_info->sys_meta_len = sys_meta_len;
	rec_info->app_meta_len = app_meta_len;

	ret = sess->dgst->update(pub_data->dgst_inst,
				pub_data->sys_meta,
				pub_data->sys_meta_sz);
	if (JAL_OK != ret) {
		goto out;
	}

	ret = sess->dgst->update(pub_data->dgst_inst,
				pub_data->app_meta,
				pub_data->app_meta_sz);
out:
	return ret;
}

/*
 * Helper method used to send the record, in the form of buffers,
 * to the subscriber.
 *
 * This method initializes the record information to be sent and
 * subsequently initiates the process of sending the record to the
 * subscriber.
 */
enum jal_status jaln_send_record(
			jaln_session *sess,
			char *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len, 
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			uint8_t *payload_buf,
			uint64_t payload_len)
{
	if (!sess || !nonce || !sys_meta_buf || ((payload_len != 0) && !payload_buf)) {
		return JAL_E_INVAL;
	}

	if (SIZE_MAX < app_meta_len || SIZE_MAX < sys_meta_len) {
		return JAL_E_INVAL;
	}

	if (strlen(nonce) > JALN_MAX_NONCE_LENGTH) {
		return JAL_E_INVAL_NONCE;
	}

	enum jal_status ret = jaln_session_is_ok(sess);
	if (JAL_E_INTERNAL_ERROR == ret) {
		jaln_finish(sess);
	}
	if (JAL_OK != ret) {
		return JAL_E_NOT_CONNECTED;
	}

	struct jaln_pub_data *pub_data = NULL;
	struct jaln_record_info rec_info;

	ret = jaln_send_record_init(sess,
				nonce,
				sys_meta_buf,
				sys_meta_len,
				app_meta_buf,
				app_meta_len,
				&rec_info);
	if (JAL_OK != ret) {
		goto out;
	}

	pub_data = sess->pub_data;
	pub_data->payload = payload_buf;
	pub_data->payload_sz = payload_len;

	rec_info.payload_len = payload_len;

	ret = sess->dgst->update(pub_data->dgst_inst,
				pub_data->payload,
				pub_data->payload_sz);
	if (JAL_OK != ret) {
		goto out;
	}

	ret = jaln_pub_begin_next_record_ans(sess, &rec_info);
out:
	// The library does not assume ownership of the buffers.
	// Make sure there are no lingering pointers to them.
	if (pub_data)
	{
		pub_data->sys_meta = NULL;
		pub_data->app_meta = NULL;
		pub_data->payload = NULL;
		pub_data->sys_meta_sz = 0;
		pub_data->app_meta_sz = 0;
		pub_data->payload_sz = 0;
	}
	if (JAL_OK != ret) {
		jaln_finish(sess);
	}
	return ret;
}

/*
 * Helper method used to send a record, via a feeder, to the
 * subscriber.
 * 
 * This method initializes the record information to be sent,
 * reads the payload data from the feeder, and subsequently
 * initiates the process of sending the record to the subscriber.
 *
 * TODO: Convert audit and log handling to feeders.
 */
enum jal_status jaln_send_record_feeder(
			jaln_session *sess,
			char *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len, 
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			uint64_t payload_len,
			uint64_t offset,
			struct jaln_payload_feeder *feeder)
{
	if (!sess || !nonce || !sys_meta_buf || ((app_meta_len != 0) && !app_meta_buf) || !feeder) {
		return JAL_E_INVAL_PARAM;
	}

	if (SIZE_MAX < app_meta_len || SIZE_MAX < sys_meta_len) {
		return JAL_E_INVAL_PARAM;
	}

	if (strlen(nonce) > JALN_MAX_NONCE_LENGTH) {
		return JAL_E_INVAL_NONCE;
	}

	enum jal_status ret = jaln_session_is_ok(sess);
	if (JAL_E_INTERNAL_ERROR == ret) {
		jaln_finish(sess);
	}
	if (JAL_OK != ret) {
		return JAL_E_NOT_CONNECTED;
	}

	struct jaln_pub_data *pub_data = NULL;
	struct jaln_record_info rec_info;

	ret = jaln_send_record_init(sess,
				nonce,
				sys_meta_buf,
				sys_meta_len,
				app_meta_buf,
				app_meta_len,
				&rec_info);

	if (JAL_OK != ret) {
		goto out;
	}
	rec_info.payload_len = payload_len - offset;

	pub_data = sess->pub_data;

#define BUF_SIZE (4*1024)
	uint8_t buf[BUF_SIZE];
	uint64_t left_to_process = (offset < payload_len) ? offset : 0;
	offset = 0;

	while (left_to_process != 0) {
		uint64_t to_copy = (uint64_t) (BUF_SIZE < left_to_process) ? 
			BUF_SIZE : left_to_process;
		uint64_t tmp = to_copy;
		ret = feeder->get_bytes(offset, buf, &tmp,
				feeder->feeder_data);
		if ((JAL_OK != ret) || (0 == tmp) || (tmp > to_copy)) {
			ret = JAL_E_INVAL;
			goto out;
		}

		ret = sess->dgst->update(pub_data->dgst_inst, buf, tmp);
		if (JAL_OK != ret) {
			goto out;
		}
		left_to_process -= tmp;
		offset += tmp;
	}
	pub_data->payload_off = offset;
	pub_data->payload_sz = payload_len;
	pub_data->journal_feeder = *feeder;

	ret = jaln_pub_begin_next_record_ans(sess, &rec_info); 
out:
	// The library does not assume ownership of the buffers.
	// Make sure there are no lingering pointers to them.
	if (pub_data)
	{
		pub_data->sys_meta = NULL;
		pub_data->app_meta = NULL;
		pub_data->sys_meta_sz = 0;
		pub_data->app_meta_sz = 0;
	}
	if (JAL_OK != ret) {
		jaln_finish(sess);
	}
	return ret;
}

enum jal_status jaln_send_journal(
			jaln_session *sess,
			char *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len,
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			uint64_t payload_len,
			struct jaln_payload_feeder *feeder)
{
	if (NULL == sess || NULL == sess->ch_info || JALN_RTYPE_JOURNAL != sess->ch_info->type) {
		return JAL_E_INVAL_PARAM;
	}

	return jaln_send_record_feeder(sess,
					nonce,
					sys_meta_buf,
					sys_meta_len, 
					app_meta_buf,
					app_meta_len,
					payload_len,
					sess->pub_data->payload_off,
					feeder);

}

enum jal_status jaln_send_audit(
			jaln_session *sess,
			char *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len,
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			uint8_t *payload_buf,
			uint64_t payload_len)
{
	if (NULL == sess || NULL == sess->ch_info || JALN_RTYPE_AUDIT != sess->ch_info->type) {
		return JAL_E_INVAL_PARAM;
	}

	return jaln_send_record(sess,
				nonce,
				sys_meta_buf,
				sys_meta_len,
				app_meta_buf,
				app_meta_len,
				payload_buf,
				payload_len);
}

enum jal_status jaln_send_log(
			jaln_session *sess,
			char *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len,
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			uint8_t *payload_buf,
			uint64_t payload_len)
{
	if (NULL == sess || NULL == sess->ch_info || JALN_RTYPE_LOG != sess->ch_info->type) {
		return JAL_E_INVAL_PARAM;
	}

	return jaln_send_record(sess,
				nonce,
				sys_meta_buf,
				sys_meta_len,
				app_meta_buf,
				app_meta_len,
				payload_buf,
				payload_len);
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
