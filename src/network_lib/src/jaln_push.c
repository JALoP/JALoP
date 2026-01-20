/**
 * @file
 *
 * @brief This file contains function
* definitions related to the jal publisher.
*
* ### LICENSE
*
* Copyright (C) 2018-2025 Concurrent Technologies Corporation.
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
#include "jaldb_segment.h"

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
	// Validate inputs
	if (
			!sess
			|| !nonce
			|| !sys_meta_buf
			// application meatadata may be NULL(empty)
			// payload may be NULL(empty), but only if the len is 0
			|| ((payload_len != 0) && !payload_buf)
			|| !sess->pub_data
			|| !sess->pub_data->feeder.get_bytes) {
		return JAL_E_INVAL;
	}

	if (SIZE_MAX < app_meta_len || SIZE_MAX < sys_meta_len) {
		return JAL_E_INVAL;
	}

	if (strlen(nonce) > JALN_MAX_NONCE_LENGTH) {
		return JAL_E_INVAL_NONCE;
	}

	enum jal_status ret = jaln_session_is_ok(sess);
	if (JAL_OK != ret) {
		return JAL_E_NOT_CONNECTED;
	}

	struct jaln_pub_data *pub_data = sess->pub_data;
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
	pub_data->feeder = *feeder;

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
	return ret;
}

// Read up to "size" bytes from payload->fd into "buffer"
static enum jal_status pub_get_bytes_on_disk(
		const uint64_t offset,
		uint8_t * const buffer,
		uint64_t *size,
		struct jaldb_segment* payload)
{
	off64_t err = lseek64(payload->fd, offset, SEEK_SET);
	if (-1 == err) {
		return JAL_E_INVAL;
	}
	size_t to_read = *size;
	ssize_t bytes_read = read(payload->fd, buffer, to_read);
	if (bytes_read < 0) {
		return JAL_E_INVAL;
	}
	*size = bytes_read;
	return JAL_OK;
}

// copy up to "size" bytes from payload->payload to buffer
static enum jal_status pub_get_bytes_in_memory(
		const uint64_t offset,
		uint8_t * const buffer,
		uint64_t *size,
		struct jaldb_segment* payload)
{
	// starting from &payload[offset], copy the remaining bytes to buffer
	uint64_t to_copy = (payload->length - offset);
	// if there are more bytes remaining than "size", only copy "size" bytes
	if(to_copy > *size) {
		to_copy = *size;
	}
	memcpy(buffer, payload->payload + offset, to_copy);
	// set "size" to the amount of bytes copied
	*size = to_copy;
	return JAL_OK;
}

// Provide bytes for the payload portion of a record, in chunks of <= size,
// setting size to the amount of bytes provided, and copying the bytes to buffer.
// Offset indicates how far in to the payload to start copying from
static enum jal_status default_get_bytes(
		const uint64_t offset,
		uint8_t* buffer,
		uint64_t* size,
		void *feeder_data) {
	struct jaldb_segment* payload = (struct jaldb_segment*)feeder_data;
	if(payload->on_disk) {
		return pub_get_bytes_on_disk(offset, buffer, size, payload);
	} else {
		return pub_get_bytes_in_memory(offset, buffer, size, payload);
	}
}

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

	struct jaln_payload_feeder feeder;
	feeder.get_bytes = default_get_bytes;
	feeder.feeder_data = rec->payload;

	return jaln_send_record_feeder(sess,
					rec->network_nonce,
					rec->sys_meta->payload,
					rec->sys_meta->length,
					rec->app_meta->payload,
					rec->app_meta->length,
					rec->payload->length,
					sess->pub_data->payload_off,
					&feeder);
}

enum jal_status jaln_send_feeder(
			jaln_session *sess,
			struct jaldb_record* rec,
			struct jaln_payload_feeder *feeder)
{
	if (NULL == sess
			|| NULL == sess->ch_info
			|| NULL == rec
			|| NULL == rec->network_nonce
			|| NULL == rec->app_meta
			|| NULL == rec->sys_meta
			|| NULL == rec->payload
			|| NULL == feeder) {
		return JAL_E_INVAL_PARAM;
	}

	return jaln_send_record_feeder(sess,
					rec->network_nonce,
					rec->sys_meta->payload,
					rec->sys_meta->length,
					rec->app_meta->payload,
					rec->app_meta->length,
					rec->payload->length,
					sess->pub_data->payload_off,
					feeder);

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
