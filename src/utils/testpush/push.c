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
#include <pthread.h>
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

struct thread_data {
	jaln_session *sess;
	char *sid;
};

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
enum jal_status __send_record(jaln_session *sess, char *sid, 
			enum jal_status (*send)(jaln_session *, void *, char *,
						uint8_t *, uint64_t, uint8_t *,
						uint64_t, uint8_t *, uint64_t))
{
	uint8_t *sys_meta_buf = NULL;
	uint64_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	uint64_t app_meta_len = 0;
	uint8_t *payload_buf = NULL;
	uint64_t payload_len = 0;

	sys_meta_buf = (uint8_t*) strdup("sys_meta_buffer");
	sys_meta_len = strlen("sys_meta_buffer");
	app_meta_buf = (uint8_t*) strdup("app_meta_buffer");
	app_meta_len = strlen("app_meta_buffer");
	payload_buf = (uint8_t*) strdup("payload_buffer");
	payload_len = strlen("payload_buffer");

	enum jal_status ret = send(sess, NULL, sid, sys_meta_buf, sys_meta_len,
				app_meta_buf, app_meta_len, payload_buf, payload_len);

	free(sys_meta_buf);
	free(app_meta_buf);
	free(payload_buf);

	return ret;
}
__attribute__((noreturn))
void *send_journal(__attribute__((unused)) void *args) {
	pthread_exit(NULL);
}
__attribute__((noreturn))
void *send_record(void *args) {
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	char *sid = data->sid;
	enum jal_status ret = JAL_E_INVAL;

	while (1) {
		ret = __send_record(sess, sid, &jaln_send_audit);\
		if (JAL_OK != ret) {
			DEBUG_LOG("Failed to send audit record");
			goto out;
		}
		sleep(1);
	}

out:
	pthread_exit(&ret);
}

enum jal_status on_subscribe(
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

	pthread_t journal_thread;
	pthread_t audit_thread;
	pthread_t log_thread;
	pthread_attr_t attr;
	struct thread_data data;
	enum jal_status ret = JAL_E_INVAL;
	void *status = NULL;
	int rc = 0;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	data.sess = sess;
	data.sid = (char *)serial_id;

	switch (type) {
	case JALN_RTYPE_JOURNAL:
		pthread_create(&journal_thread, &attr, send_journal, &data);

		pthread_attr_destroy(&attr);

		rc = pthread_join(journal_thread, &status);
		if (rc) {
			DEBUG_LOG("ERROR: return code from pthread_create() is %d\n", rc);
			return JAL_E_INVAL;
		}
		break;
	case JALN_RTYPE_AUDIT:
		pthread_create(&audit_thread, &attr, send_record, &data);

		pthread_attr_destroy(&attr);

		rc = pthread_join(audit_thread, &status);
		if (rc) {
			DEBUG_LOG("Error while joining thread (%d)\n", rc);
			return JAL_E_INVAL;
		}
		DEBUG_LOG("AUDIT THREAD JOINED");
		break;
	case JALN_RTYPE_LOG:
		pthread_create(&log_thread, &attr, send_record, &data);

		pthread_attr_destroy(&attr);

		rc = pthread_join(log_thread, &status);
		if (rc) {
			DEBUG_LOG("Error while joining thread (%d)\n", rc);
			return JAL_E_INVAL;
		}
		DEBUG_LOG("LOG THREAD JOINED");
		break;
	default:
		DEBUG_LOG("Illegal Record Type");
		return JAL_E_INVAL;
	}

	ret = *((enum jal_status *) status);
	if (JAL_OK != ret) {
		DEBUG_LOG("Failed to send records to subscriber");
	}

	return ret;

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
