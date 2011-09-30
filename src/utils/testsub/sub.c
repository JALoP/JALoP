/**
 * @file main.c Dummy server as the start to 'real' jalp_push tool. Shows
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
#include <jalop/jaln_network.h>
#include <jalop/jaln_subscriber_callbacks.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "jal_base64_internal.h"
#define DEBUG_LOG(args...) \
	do { \
		fprintf(stderr, "(sub) %s[%d] ", __FILE__, __LINE__); \
		fprintf(stderr, ##args); \
		fprintf(stderr, "\n"); \
	} while(0)

int sub_get_subscribe_request(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		char **serial_id,
		__attribute__((unused)) uint64_t *offset)
{
	DEBUG_LOG(" ");
	*serial_id = strdup("0");
	return JAL_OK;
}

int sub_on_record_info(const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const struct jaln_record_info *record_info,
		const struct jaln_mime_header *headers,
		const uint8_t *system_metadata_buffer,
		const uint32_t system_metadata_size,
		const uint8_t *application_metadata_buffer,
		const uint32_t application_metadata_size,
		void *user_data)
{
	DEBUG_LOG("ch info:%p type:%d rec_info: %p headers: %p smb: %p sms:%d amb:%p ams:%d ud:%p\n",
		ch_info, type, record_info, headers, system_metadata_buffer, system_metadata_size,
		application_metadata_buffer, application_metadata_size, user_data);
	DEBUG_LOG("(%s)sys_meta[%lu/%lu] '%s'", record_info->serial_id,
			record_info->sys_meta_len,
			strlen((char*) system_metadata_buffer),
			(char *) system_metadata_buffer);
	DEBUG_LOG("(%s)app_meta[%lu/%lu] '%s'", record_info->serial_id,
			record_info->app_meta_len,
			strlen((char*) application_metadata_buffer),
			(char*) application_metadata_buffer);
	DEBUG_LOG("(%s)payload_sz[%lu]", record_info->serial_id, 
			record_info->payload_len);


	return 0;
}

int sub_on_audit(const struct jaln_channel_info *ch_info,
		const char *serial_id,
		const uint8_t *buffer,
		const uint32_t cnt,
		void *user_data)
{
	DEBUG_LOG("ch info:%p serial_id:%s buf: %p cnt:%d ud:%p\n",
		ch_info, serial_id, buffer, cnt, user_data);
	return 0;
}

int sub_on_log(const struct jaln_channel_info *ch_info,
		const char *serial_id,
		const uint8_t *buffer,
		const uint32_t cnt,
		void *user_data)
{
	DEBUG_LOG("ch info:%p serial_id:%s buf: %p cnt:%d ud:%p\n",
		ch_info, serial_id, buffer, cnt, user_data);

	DEBUG_LOG("(%s)app_meta[%u/%lu] '%s'", serial_id,
			cnt,
			strlen((char*) buffer),
			(char*) buffer);
	return 0;
}

int sub_on_journal(const struct jaln_channel_info *ch_info,
		const char *serial_id,
		const uint8_t *buffer,
		const uint32_t cnt,
		const uint64_t offset,
		const int more,
		void *user_data)
{
	DEBUG_LOG("ch info:%p serial_id:%s buf: %p cnt:%u offset:%lu, more:%d, ud:%p\n",
		ch_info, serial_id, buffer, cnt, offset, more, user_data);
	return 0;
}

int sub_notify_digest(const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		char *serial_id,
		const uint8_t *digest,
		const uint32_t len,
		const void *user_data)
{
	DEBUG_LOG("ch info:%p type:%d serial_id:%s dgst:%p, len:%d, ud:%p\n",
		ch_info, type, serial_id, digest, len, user_data);
	char *b64 = jal_base64_enc(digest, len);
	DEBUG_LOG("dgst: %s\n", b64);
	return 0;
}

int sub_on_digest_response(const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *serial_id,
		const enum jaln_digest_status status,
		const void *user_data)
{
	const char *status_str;
	switch (status) {
	case JALN_DIGEST_STATUS_CONFIRMED:
		status_str = "Confirmed";
		break;
	case JALN_DIGEST_STATUS_INVALID:
		status_str = "Invalid";
		break;
	case JALN_DIGEST_STATUS_UNKNOWN:
		status_str = "Unknown";
		break;
	default:
		status_str = "illegal";
	}

	DEBUG_LOG("ch info:%p type:%d serial_id:%s status: %s, ds:%d, ud:%p\n",
		ch_info, type, serial_id, status_str, status, user_data);
	return 0;
}

void sub_message_complete(const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		void *user_data)
{
	DEBUG_LOG("ch info:%p type:%d ud:%p\n",
		ch_info, type, user_data);
}

int sub_acquire_journal_feeder(const struct jaln_channel_info *ch_info,
		const char *serial_id,
		struct jaln_payload_feeder *feeder,
		void *user_data)
{
	user_data = user_data;
	DEBUG_LOG("ch_info: %p, sid:%s, feeder:%p\n", ch_info, serial_id, feeder);
	return 0;
}

void sub_release_journal_feeder(const struct jaln_channel_info *ch_info,
		const char *serial_id,
		struct jaln_payload_feeder *feeder,
		void *user_data)
{
	user_data = user_data;
	DEBUG_LOG("ch_info: %p, sid:%s, feeder:%p\n", ch_info, serial_id, feeder);
}

enum jaln_connect_error on_connect_request(const struct jaln_connect_request *req,
		int *selected_encoding,
		int *selected_digest,
		void *user_data)
{
	user_data = user_data;
	DEBUG_LOG("req: %p, enc:%p, dgst:%p", req, selected_encoding, selected_digest);
	return JALN_CE_ACCEPT;
}
void on_channel_close(const struct jaln_channel_info *channel_info, void *user_data)
{
	user_data = user_data;
	// a channel is being closed.
	// TODO: dump the channel info
	DEBUG_LOG("channel_info: %p", channel_info);
}
void on_connection_close(const struct jaln_connection *jal_conn, void *user_data)
{
	user_data = user_data;
	// a connection is being closed.
	// TODO: dump the connection
	DEBUG_LOG("conn_info: %p", jal_conn);
}
void on_connect_ack(const struct jaln_connect_ack *ack, void *user_data)
{
	DEBUG_LOG("hostname: %s", ack->hostname);
	DEBUG_LOG("addr: %s", ack->addr);
	DEBUG_LOG("version: %d", ack->jaln_version);
	DEBUG_LOG("agent: %s", ack->jaln_agent);
	DEBUG_LOG("role: %s", ack->mode == JALN_ROLE_SUBSCRIBER ? "subscriber" : "publisher");
	user_data = user_data;
}
void on_connect_nack(const struct jaln_connect_nack *nack, void *user_data)
{
	user_data = user_data;
	// connection was rejected by the remote
	// TODO: dump the nack
	DEBUG_LOG("ack: %p", nack);
}

int main() {
	jaln_context *net_ctx = jaln_context_create();
	//struct jaln_connection_handlers *conn_cbs = jaln_connection_handlers_create();
	struct jaln_connection_callbacks ch;
	struct jaln_connection_callbacks *conn_cbs = &ch;

	conn_cbs->connect_request_handler = on_connect_request;
	conn_cbs->on_channel_close = on_channel_close;
	conn_cbs->on_connection_close = on_connection_close;
	conn_cbs->connect_ack = on_connect_ack;
	conn_cbs->connect_nack = on_connect_nack;

	struct jaln_subscriber_callbacks *sub_cbs = jaln_subscriber_callbacks_create();
	sub_cbs->get_subscribe_request = sub_get_subscribe_request;
	sub_cbs->on_record_info = sub_on_record_info;
	sub_cbs->on_audit = sub_on_audit;
	sub_cbs->on_log = sub_on_log;
	sub_cbs->on_journal = sub_on_journal;
	sub_cbs->notify_digest = sub_notify_digest;
	sub_cbs->on_digest_response = sub_on_digest_response;
	sub_cbs->message_complete = sub_message_complete;
	sub_cbs->acquire_journal_feeder = sub_acquire_journal_feeder;
	sub_cbs->release_journal_feeder = sub_release_journal_feeder;

	enum jal_status err;
	struct jal_digest_ctx *dc1 = jal_sha256_ctx_create();
	struct jal_digest_ctx *dc2 = jal_sha256_ctx_create();
	dc1->algorithm_uri = strdup("sha512");
	dc2->algorithm_uri = strdup("sha384");
	jaln_register_digest_algorithm(net_ctx, dc1);
	jaln_register_digest_algorithm(net_ctx, dc2);
	//err = jan_register_tls(net_ctx, "priv_key", "pub_cert", "path/to/peer/certs");
	err = jaln_register_encoding(net_ctx, "exi");
	err = jaln_register_encoding(net_ctx, "deflate");
	err = jaln_register_connection_callbacks(net_ctx, conn_cbs);
	err = jaln_register_subscriber_callbacks(net_ctx, sub_cbs);
	//struct jaln_connection *conn = jaln_subscribe(net_ctx, "192.168.246.156", "55555", JALN_RTYPE_LOG, NULL);
	struct jaln_connection *conn = jaln_subscribe(net_ctx, "localhost", "55555", JALN_RTYPE_LOG, NULL);
	DEBUG_LOG("got jal con %p\n", conn);
	//sleep(120);
	//err = jaln_disconnect(conn);
	sleep(600);
	//err = jaln_shutdown(conn);
	//jaln_context_destroy(&net_ctx);
	return 0;
}
