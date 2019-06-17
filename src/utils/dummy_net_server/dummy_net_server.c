/**
 * @file dummy_net_server.c This file contains dummy net server functions
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
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_publisher_callbacks.h>
#include <string.h>
#include <unistd.h>
#include "jal_base64_internal.h"

#define DEBUG_LOG(args...) \
	do { \
		fprintf(stderr, "(server) %s[%d] ", __FUNCTION__, __LINE__); \
		fprintf(stderr, ##args); \
		fprintf(stderr, "\n"); \
	} while(0)

#define TEST_INPUT_PATH "test-input/"
#define AUDIT_PAYLOAD_XML "good_audit_input.xml"
#define JOURNAL_PAYLOAD_TXT "big_payload.txt"
#define SYS_META_XML "system-metadata.xml"
#define APP_META_XML "good_app_meta_input.xml"

struct thread_data {
	jaln_session *sess;
	char *nonce;
};

uint8_t *m_sys_meta_buf = NULL;
uint8_t *m_app_meta_buf = NULL;
uint8_t *m_audit_buf = NULL;
uint8_t *m_journal_buf = NULL;
uint64_t m_sys_meta_buf_len = 0;
uint64_t m_app_meta_buf_len = 0;
uint64_t m_audit_buf_len = 0;
uint64_t m_journal_buf_len = 0;

int read_file(const char *file_name, uint8_t **buffer, uint64_t *buff_len);
void load_test_data();

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

enum jal_status pub_on_journal_resume(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) struct jaln_record_info *record_info,
		__attribute__((unused)) uint64_t offset,
		__attribute__((unused)) uint8_t **system_metadata_buffer,
		__attribute__((unused)) uint8_t **application_metadata_buffer,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("Journal Resume NOT IMPLEMENTED");
	return JAL_E_INVAL;
}

enum jal_status __send_record(jaln_session *sess, char *nonce, uint8_t *buf, uint64_t buf_len, 
			enum jal_status (*send)(jaln_session *, char *, uint8_t *,
						uint64_t, uint8_t *, uint64_t,
						uint8_t *, uint64_t))
{
	enum jal_status ret = send(sess, nonce, m_sys_meta_buf, m_sys_meta_buf_len,
				m_app_meta_buf, m_app_meta_buf_len, buf, buf_len);

	return ret;
}

__attribute__((noreturn))
void *send_journal(__attribute__((unused)) void *args) {
	DEBUG_LOG("not impl");
	pthread_exit(NULL);
}

__attribute__((noreturn))
void *send_audit(void *args) {
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	char *nonce = data->nonce;
	enum jal_status ret = JAL_E_INVAL;

	while (1) {
		ret = __send_record(sess, nonce, m_audit_buf, m_audit_buf_len, &jaln_send_audit);
		if (JAL_OK != ret) {
			DEBUG_LOG("Failed to send audit record");
			goto out;
		}
		sleep(1);
	}

out:
	pthread_exit(&ret);
}

__attribute__((noreturn))
void *send_log(void *args) {
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	char *nonce = data->nonce;
	enum jal_status ret = JAL_E_INVAL;

	while (1) {
		ret = __send_record(sess, nonce, m_journal_buf, m_journal_buf_len, &jaln_send_audit);
		if (JAL_OK != ret) {
			DEBUG_LOG("Failed to send audit record");
			goto out;
		}
		sleep(1);
	}

out:
	pthread_exit(&ret);
}

enum jal_status pub_on_subscribe(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		__attribute__((unused)) enum jaln_publish_mode mode,
		struct jaln_mime_header *headers,
		void *user_data)
{
	// remote is sending a subscribe message for the particular type
	// indicate they wish to begin receiving records at nonce
	user_data = user_data;
	DEBUG_LOG("ch_info: %p", ch_info);
	DEBUG_LOG("record_type: %d", type);
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
		pthread_create(&audit_thread, &attr, send_audit, &data);

		pthread_attr_destroy(&attr);

		rc = pthread_join(audit_thread, &status);
		if (rc) {
			DEBUG_LOG("Error while joining thread (%d)\n", rc);
			return JAL_E_INVAL;
		}
		break;
	case JALN_RTYPE_LOG:
		pthread_create(&log_thread, &attr, send_log, &data);

		pthread_attr_destroy(&attr);

		rc = pthread_join(log_thread, &status);
		if (rc) {
			DEBUG_LOG("Error while joining thread (%d)\n", rc);
			return JAL_E_INVAL;
		}
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

enum jal_status pub_on_record_complete(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) char *nonce,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("nonce: %s", nonce);
	return JAL_OK;
}

void pub_sync(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) enum jaln_publish_mode mode,
		__attribute__((unused)) const char *nonce,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("nonce: %s", nonce);
}

void pub_notify_digest(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *nonce,
		__attribute__((unused)) const uint8_t *digest,
		__attribute__((unused)) const uint32_t size,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("ch info:%p type:%d nonce:%s dgst:%p, len:%d, ud:%p\n",
		ch_info, type, nonce, digest, size, user_data);
	char *b64 = jal_base64_enc(digest, size);
	DEBUG_LOG("dgst: %s\n", b64);
	free(b64);
}

void pub_peer_digest(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *nonce,
		__attribute__((unused)) const uint8_t *local_digest,
		__attribute__((unused)) const uint32_t local_size,
		__attribute__((unused)) const uint8_t *peer_digest,
		__attribute__((unused)) const uint32_t peer_size,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("ch info:%p type:%d nonce:%s ldgst:%p, llen:%d, pdgst:%p, plen:%d, ud:%p\n",
		ch_info, type, nonce, local_digest, local_size, peer_digest, peer_size, user_data);
	char *b64 = jal_base64_enc(local_digest, local_size);
	DEBUG_LOG("dgst: %s\n", b64);
	free(b64);
	b64 = jal_base64_enc(peer_digest, peer_size);
	DEBUG_LOG("dgst: %s\n", b64);
	free(b64);
}

int sub_get_subscribe_request(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		char **nonce,
		__attribute__((unused)) uint64_t *offset)
{
	DEBUG_LOG(" ");
	*nonce = strdup("0");
	return JAL_OK;
}

int sub_on_record_info(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
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
	DEBUG_LOG("(%s)sys_meta[%"PRIu64"/%zu] '%s'", record_info->nonce,
			record_info->sys_meta_len,
			strlen((char*) system_metadata_buffer),
			(char *) system_metadata_buffer);
	DEBUG_LOG("(%s)app_meta[%"PRIu64"/%zu] '%s'", record_info->nonce,
			record_info->app_meta_len,
			strlen((char*) application_metadata_buffer),
			(char*) application_metadata_buffer);
	DEBUG_LOG("(%s)payload_sz[%"PRIu64"]", record_info->nonce,
			record_info->payload_len);


	return 0;
}

int sub_on_audit(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *nonce,
		const uint8_t *buffer,
		const uint32_t cnt,
		void *user_data)
{
	DEBUG_LOG("ch info:%p nonce:%s buf: %p cnt:%d ud:%p\n",
		ch_info, nonce, buffer, cnt, user_data);
	return 0;
}

int sub_on_log(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *nonce,
		const uint8_t *buffer,
		const uint32_t cnt,
		void *user_data)
{
	DEBUG_LOG("ch info:%p nonce:%s buf: %p cnt:%d ud:%p\n",
		ch_info, nonce, buffer, cnt, user_data);

	DEBUG_LOG("(%s)app_meta[%"PRIu32"/%zu] '%s'", nonce,
			cnt,
			strlen((char*) buffer),
			(char*) buffer);
	return 0;
}

int sub_on_journal(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *nonce,
		const uint8_t *buffer,
		const uint32_t cnt,
		const uint64_t offset,
		const int more,
		void *user_data)
{
	DEBUG_LOG("ch info:%p nonce:%s buf: %p cnt:%"PRIu32" offset:%"PRIu64", more:%d, ud:%p\n",
		ch_info, nonce, buffer, cnt, offset, more, user_data);
	return 0;
}

int sub_notify_digest(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		char *nonce,
		const uint8_t *digest,
		const uint32_t len,
		const void *user_data)
{
	DEBUG_LOG("ch info:%p type:%d nonce:%s dgst:%p, len:%d, ud:%p\n",
		ch_info, type, nonce, digest, len, user_data);
	char *b64 = jal_base64_enc(digest, len);
	DEBUG_LOG("dgst: %s\n", b64);
	return 0;
}

int sub_on_digest_response(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *nonce,
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

	DEBUG_LOG("ch info:%p type:%d nonce:%s status: %s, ds:%d, ud:%p\n",
		ch_info, type, nonce, status_str, status, user_data);
	return 0;
}

void sub_message_complete(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		void *user_data)
{
	DEBUG_LOG("ch info:%p type:%d ud:%p\n",
		ch_info, type, user_data);
}

int sub_acquire_journal_feeder(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *nonce,
		struct jaln_payload_feeder *feeder,
		void *user_data)
{
       user_data = user_data;
       DEBUG_LOG("ch_info: %p, nonce:%s, feeder:%p\n", ch_info, nonce, feeder);
       return 0;
}

void sub_release_journal_feeder(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *nonce,
		struct jaln_payload_feeder *feeder,
		void *user_data)
{
       user_data = user_data;
       DEBUG_LOG("ch_info: %p, nonce:%s, feeder:%p\n", ch_info, nonce, feeder);
}

int main()
{
	load_test_data();

	jaln_context *net_ctx = jaln_context_create();
	//struct jaln_connection_handlers *conn_cbs = jaln_connection_handlers_create();
	struct jaln_connection_callbacks ch;
	struct jaln_connection_callbacks *conn_cbs = &ch;

	conn_cbs->connect_request_handler = on_connect_request;
	conn_cbs->on_channel_close = on_channel_close;
	conn_cbs->on_connection_close = on_connection_close;
	conn_cbs->connect_ack = on_connect_ack;
	conn_cbs->connect_nack = on_connect_nack;

	struct jaln_publisher_callbacks *pub_cbs = jaln_publisher_callbacks_create();
	pub_cbs->on_journal_resume = pub_on_journal_resume;
	pub_cbs->on_subscribe = pub_on_subscribe;
	pub_cbs->on_record_complete = pub_on_record_complete;
	pub_cbs->sync = pub_sync;
	pub_cbs->notify_digest = pub_notify_digest;
	pub_cbs->peer_digest = pub_peer_digest;

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

	jaln_register_digest_algorithm(net_ctx, dc1);
	err = jaln_register_encoding(net_ctx, "xml");

	//err = jan_register_tls(net_ctx, "priv_key", "pub_cert", "path/to/peer/certs");
	err = jaln_register_subscriber_callbacks(net_ctx, sub_cbs);
	DEBUG_LOG("register sub cbs: %d\n", err);
	err = jaln_register_connection_callbacks(net_ctx, conn_cbs);
	DEBUG_LOG("register conn cbs: %d\n", err);
	err = jaln_register_publisher_callbacks(net_ctx, pub_cbs);
	DEBUG_LOG("register pub cbs: %d\n", err);
	err = jaln_listen(net_ctx, "0.0.0.0", "55555", NULL);
	err = jaln_listener_wait(net_ctx);
	jaln_context_destroy(&net_ctx);
	return 0;
}

int read_file(const char *file_name, uint8_t **buffer, uint64_t *buff_len)
{
	int ret = 0;
	FILE *f = NULL;
	f = fopen(file_name, "rb");

	ret = fseek(f, 0, SEEK_END);
	*buff_len = ftell(f);
	ret = fseek(f, 0, SEEK_SET);

	// Allocate enough for buffer + null terminator
	*buffer = (uint8_t *)malloc(*buff_len + 1);
	ret = fread(*buffer, *buff_len, 1, f);
	*buff_len += 1; // For Null Terminator
	(*buffer)[*buff_len-1] = (uint8_t)'\0';

	fclose(f);
	return ret;
}

void load_test_data()
{
	read_file(TEST_INPUT_PATH APP_META_XML,
			&m_app_meta_buf,
			&m_app_meta_buf_len);
	read_file(TEST_INPUT_PATH SYS_META_XML,
			&m_sys_meta_buf,
			&m_sys_meta_buf_len);
	read_file(TEST_INPUT_PATH AUDIT_PAYLOAD_XML,
			&m_audit_buf,
			&m_audit_buf_len);
	read_file(TEST_INPUT_PATH JOURNAL_PAYLOAD_TXT,
			&m_journal_buf,
			&m_journal_buf_len);
}
