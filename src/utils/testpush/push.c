/**
 * @file push.c Dummy server as the start to 'real' jalp_push tool. Shows
 * sample use of the network library.
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
#include <inttypes.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_publisher_callbacks.h>
#include <jalop/jaln_connection_callbacks.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "jal_base64_internal.h"

#define DEBUG_LOG(args...) \
	do { \
		fprintf(stderr, "(push) %s[%d] \n", __FUNCTION__, __LINE__); \
		fprintf(stderr, ##args); \
		fprintf(stderr, "\n"); \
	} while(0)

enum jaln_connect_error on_connect_request(const struct jaln_connect_request *req,
		int *selected_encoding, int *selected_digest, void *user_data)
{
	user_data = user_data;
	DEBUG_LOG("request: %p", req);
	*selected_encoding = 0;
	*selected_digest = 0;
	return JALN_CE_ACCEPT;
}
void on_channel_close(const struct jaln_channel_info *channel_info, void *user_data)
{
	user_data = user_data;
	DEBUG_LOG("channel_info: %p", channel_info);
}
void on_connection_close(const struct jaln_connection *jal_conn, void *user_data)
{
	user_data = user_data;
	DEBUG_LOG("conn_info: %p", jal_conn);
}
void on_connect_ack(const struct jaln_connect_ack *ack, void *user_data)
{
	user_data = user_data;
	DEBUG_LOG("ack: %p", ack);
}
void on_connect_nack(const struct jaln_connect_nack *nack, void *user_data)
{
	user_data = user_data;
	DEBUG_LOG("nack: %p", nack);
}
enum jal_status on_journal_resume(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) struct jaln_record_info *record_info,
		__attribute__((unused)) uint64_t offset,
		__attribute__((unused)) uint8_t **system_metadata_buffer,
		__attribute__((unused)) uint8_t **application_metadata_buffer,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	// remote is trying to resume start resuming a journal record
	// look up journal base on offset
	// TODO: dump the channel info, etc
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("rec_info: %p", record_info);
	DEBUG_LOG("headers: %p", headers);
	return JAL_E_INVAL;
}
int on_subscribe(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *serial_id,
		struct jaln_mime_header *headers,
		void *user_data)
{
	// remote is sending a subscribe message for the particular type
	// indicate they wish to begin receiving records at serial_id
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("record_type: %d", type);
	DEBUG_LOG("sid: %p", serial_id);
	DEBUG_LOG("headers: %p", headers);
	return JAL_OK;
}
int get_next_record_info_and_metadata(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *last_serial_id,
		struct jaln_record_info *record_info,
		uint8_t **system_metadata_buffer,
		uint8_t **application_metadata_buffer,
		void *user_data)
{
	// obtain the record that comes after 'last_serial_id'
	// the sys metadata and application metadata buffers
	// are set to address that are (possibly) allocated 
	// in this function
	user_data = user_data;
	DEBUG_LOG("ch_info: %p, rec_type: %d, sid: %p rec_info: %p, sys_meta: %p, app_meta %p",
			ch_info, type, last_serial_id, record_info, system_metadata_buffer,
			application_metadata_buffer);

	sleep(1);
	static uint64_t sid = 1;
	DEBUG_LOG("last sid: %s", last_serial_id);

	size_t sz = snprintf(NULL, 0, "%"PRIu64, sid);
	record_info->serial_id = calloc(1, sz + 1);
	snprintf(record_info->serial_id, sz + 1, "%"PRIu64, sid);
	DEBUG_LOG("next: %s", record_info->serial_id);

	sid++;
	record_info->sys_meta_len = strlen("sys_meta_buffer");
	record_info->app_meta_len = strlen("app_meta_buffer");
	record_info->payload_len = strlen("payload_buffer");

	*system_metadata_buffer = (uint8_t*) strdup("sys_meta_buffer");
	*application_metadata_buffer = (uint8_t*) strdup("app_meta_buffer");
	return JAL_OK;
}
int release_metadata_buffers(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		uint8_t *system_metadata_buffer,
		uint8_t *application_metadata_buffer,
		void *user_data)
{
	// release the sys/app buffers
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("serial_id: %p", serial_id);
	DEBUG_LOG("sys_meta: %p", system_metadata_buffer);
	DEBUG_LOG("app_meta: %p", application_metadata_buffer);
	free(system_metadata_buffer);
	free(application_metadata_buffer);
	return JAL_OK;
}

int acquire_log_data(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		uint8_t **buffer,
		void *user_data)
{
	// acquire the actual log data for a record
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("sid: %p", serial_id);
	DEBUG_LOG("buffer: %p", buffer);
	*buffer = (uint8_t*) strdup("payload_buffer");
	return JAL_OK;
}

int release_log_data(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		uint8_t *buffer,
		void *user_data)
{
	// release the actual log data for a record
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("sid: %p", serial_id);
	DEBUG_LOG("buffer: %p", buffer);
	free(buffer);
	return JAL_OK;
}

int acquire_audit_data(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		uint8_t **buffer,
		void *user_data)
{
	// acquire the actual audit data for a record
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("sid: %p", serial_id);
	DEBUG_LOG("buffer: %p", buffer);
	*buffer = (uint8_t*) strdup("payload_buffer");
	return JAL_OK;
}

int release_audit_data(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		uint8_t *buffer,
		void *user_data)
{
	// release the actual audit data for a record
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("sid: %p", serial_id);
	DEBUG_LOG("buffer: %p", buffer);
	free(buffer);
	return JAL_OK;
}
int acquire_journal_feeder(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		struct jaln_payload_feeder *feeder,
		void *user_data)
{
	// acquire a journal feeder for the record
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("sid: %p", serial_id);
	DEBUG_LOG("feeder: %p", feeder);
	return JAL_E_INVAL;
}

enum jal_status release_journal_feeder(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		struct jaln_payload_feeder *feeder,
		void *user_data)
{
	// relase a journal feeder for the record
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("sid: %p", serial_id);
	DEBUG_LOG("feeder: %p", feeder);
	return JAL_OK;
}
enum jal_status on_record_complete(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		char *serial_id,
		void *user_data)
{
	// notification that the record was sent
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("record_type: %d", type);
	DEBUG_LOG("sid: %p", serial_id);
	return JAL_OK;
}
void on_sync(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *serial_id,
		struct jaln_mime_header *headers,
		void *user_data)
{
	// notification of a sync message from a remote
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("record_type: %d", type);
	DEBUG_LOG("sid: %p", serial_id);
	DEBUG_LOG("headers: %p", headers);
}
void notify_digest(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *serial_id,
		const uint8_t *digest,
		const uint32_t size,
		void *user_data)
{
	// notification of the digest calculated by the network library
	DEBUG_LOG("ch info:%p type:%d serial_id:%s dgst:%p, len:%d, ud:%p\n",
		ch_info, type, serial_id, digest, size, user_data);
	char *b64 = jal_base64_enc(digest, size);
	DEBUG_LOG("dgst: %s\n", b64);

}
void notify_peer_digest(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *serial_id,
		const uint8_t *local_digest,
		const uint32_t local_size,
		const uint8_t *peer_digest,
		const uint32_t peer_size,
		void *user_data)
{
	// notification of the digest calculated by the remote network store
	DEBUG_LOG("ch info:%p type:%d serial_id:%s ldgst:%p, llen:%d, pdgst:%p, plen:%d, ud:%p\n",
		ch_info, type, serial_id, local_digest, local_size, peer_digest, peer_size, user_data);
	char *b64 = jal_base64_enc(local_digest, local_size);
	DEBUG_LOG("dgst: %s\n", b64);
	free(b64);
	b64 = jal_base64_enc(peer_digest, peer_size);
	DEBUG_LOG("dgst: %s\n", b64);
	free(b64);
}
int main() {
	jaln_context *net_ctx = jaln_context_create();
	//struct jaln_connection_handlers *connect_handlers = jaln_connection_handlers_create();
	struct jaln_connection_callbacks ch;
	struct jaln_connection_callbacks *connect_handlers = &ch;

	connect_handlers->connect_request_handler = on_connect_request;
	connect_handlers->on_channel_close = on_channel_close;
	connect_handlers->on_connection_close = on_connection_close;
	connect_handlers->connect_ack = on_connect_ack;
	connect_handlers->connect_nack = on_connect_nack;

	//struct jaln_publisher_callbacks *pub_callbacks = jaln_publisher_callbacks_create();
	struct jaln_publisher_callbacks pc;
	struct jaln_publisher_callbacks *pub_callbacks = &pc;
	pub_callbacks->on_journal_resume = on_journal_resume;
	pub_callbacks->on_subscribe = on_subscribe;
	pub_callbacks->get_next_record_info_and_metadata = get_next_record_info_and_metadata;
	pub_callbacks->release_metadata_buffers = release_metadata_buffers;
	pub_callbacks->acquire_log_data = acquire_log_data;
	pub_callbacks->release_log_data = release_log_data;
	pub_callbacks->acquire_audit_data = acquire_audit_data;
	pub_callbacks->release_audit_data = release_audit_data;
	pub_callbacks->acquire_journal_feeder = acquire_journal_feeder;
	pub_callbacks->release_journal_feeder = release_journal_feeder;
	pub_callbacks->on_record_complete = on_record_complete;
	pub_callbacks->sync = on_sync;
	pub_callbacks->notify_digest = notify_digest;
	pub_callbacks->peer_digest = notify_peer_digest;

	enum jal_status err;
	struct jal_digest_ctx *dc1 = jal_sha256_ctx_create();
	jaln_register_digest_algorithm(net_ctx, dc1);
	err = jaln_register_encoding(net_ctx, "xml");

	//err = jan_register_tls(net_ctx, "priv_key", "pub_cert", "path/to/peer/certs");
	//err = jan_register_encoding(net_ctx, "some_other_encoding");
	err = jaln_register_connection_callbacks(net_ctx, connect_handlers);
	DEBUG_LOG("register conn cbs: %d\n", err);
	err = jaln_register_publisher_callbacks(net_ctx, pub_callbacks);
	DEBUG_LOG("register pub cbs: %d\n", err);
	struct jaln_connection *conn = jaln_publish(net_ctx, "127.0.0.1", "55555", JALN_RTYPE_LOG, NULL);
	DEBUG_LOG("got jal con %p\n", conn);
	sleep(9999);
	//err = jaln_shutdown(conn);
	//jaln_context_destroy(&net_ctx);
	return 0;
}
