#include <inttypes.h>
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

enum jal_status pub_on_subscribe(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("sid: %s", serial_id);
	return JAL_OK;

}

enum jal_status pub_get_next_record_info_and_metadata(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *last_serial_id,
		__attribute__((unused)) struct jaln_record_info *record_info,
		__attribute__((unused)) uint8_t **system_metadata_buffer,
		__attribute__((unused)) uint8_t **application_metadata_buffer,
		__attribute__((unused)) void *user_data)
{
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

enum jal_status pub_release_metadata_buffers(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) uint8_t *system_metadata_buffer,
		__attribute__((unused)) uint8_t *application_metadata_buffer,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("sid: %s", serial_id);
	free(system_metadata_buffer);
	free(application_metadata_buffer);
	return JAL_OK;
}

enum jal_status pub_acquire_log_data(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) uint8_t **buffer,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("sid: %s", serial_id);
	*buffer = (uint8_t*) strdup("payload_buffer");
	return JAL_OK;
}

enum jal_status pub_release_log_data(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) uint8_t *buffer,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("sid: %s", serial_id);
	free(buffer);
	return JAL_OK;
}

enum jal_status pub_acquire_audit_data(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) uint8_t **buffer,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("sid: %s", serial_id);
	*buffer = (uint8_t*) strdup("payload_buffer");
	return JAL_OK;
}

enum jal_status pub_release_audit_data(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) uint8_t *buffer,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("sid: %s", serial_id);
	free(buffer);
	return JAL_OK;
}

enum jal_status pub_acquire_journal_feeder(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("sid: %s", serial_id);
	DEBUG_LOG("not impl");
	return JAL_E_INVAL;
}

enum jal_status pub_release_journal_feeder(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("sid: %s", serial_id);
	DEBUG_LOG("not impl");
	return JAL_E_INVAL;
}

enum jal_status pub_on_record_complete(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) char *serial_id,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("sid: %s", serial_id);
	return JAL_OK;
}

void pub_sync(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("sid: %s", serial_id);
}

void pub_notify_digest(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) const uint8_t *digest,
		__attribute__((unused)) const uint32_t size,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("ch info:%p type:%d serial_id:%s dgst:%p, len:%d, ud:%p\n",
		ch_info, type, serial_id, digest, size, user_data);
	char *b64 = jal_base64_enc(digest, size);
	DEBUG_LOG("dgst: %s\n", b64);
}

void pub_peer_digest(
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) const uint8_t *local_digest,
		__attribute__((unused)) const uint32_t local_size,
		__attribute__((unused)) const uint8_t *peer_digest,
		__attribute__((unused)) const uint32_t peer_size,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("ch info:%p type:%d serial_id:%s ldgst:%p, llen:%d, pdgst:%p, plen:%d, ud:%p\n",
		ch_info, type, serial_id, local_digest, local_size, peer_digest, peer_size, user_data);
	char *b64 = jal_base64_enc(local_digest, local_size);
	DEBUG_LOG("dgst: %s\n", b64);
	free(b64);
	b64 = jal_base64_enc(peer_digest, peer_size);
	DEBUG_LOG("dgst: %s\n", b64);
	free(b64);
}

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
	DEBUG_LOG("(%s)sys_meta[%"PRIu64"/%zu] '%s'", record_info->serial_id,
			record_info->sys_meta_len,
			strlen((char*) system_metadata_buffer),
			(char *) system_metadata_buffer);
	DEBUG_LOG("(%s)app_meta[%"PRIu64"/%zu] '%s'", record_info->serial_id,
			record_info->app_meta_len,
			strlen((char*) application_metadata_buffer),
			(char*) application_metadata_buffer);
	DEBUG_LOG("(%s)payload_sz[%"PRIu64"]", record_info->serial_id, 
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

	DEBUG_LOG("(%s)app_meta[%"PRIu32"/%zu] '%s'", serial_id,
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
	DEBUG_LOG("ch info:%p serial_id:%s buf: %p cnt:%"PRIu32" offset:%"PRIu64", more:%d, ud:%p\n",
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



int main()
{
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
	pub_cbs->get_next_record_info_and_metadata = pub_get_next_record_info_and_metadata;
	pub_cbs->release_metadata_buffers = pub_release_metadata_buffers;
	pub_cbs->acquire_log_data = pub_acquire_log_data;
	pub_cbs->release_log_data = pub_release_log_data;
	pub_cbs->acquire_audit_data = pub_acquire_audit_data;
	pub_cbs->release_audit_data = pub_release_audit_data;
	pub_cbs->acquire_journal_feeder = pub_acquire_journal_feeder;
	pub_cbs->release_journal_feeder = pub_release_journal_feeder;
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
	struct jal_digest_ctx *dc2 = jal_sha256_ctx_create();
	dc1->algorithm_uri = strdup("sha512");
	dc2->algorithm_uri = strdup("sha384");
	jaln_register_digest_algorithm(net_ctx, dc1);
	jaln_register_digest_algorithm(net_ctx, dc2);

	err = jaln_register_encoding(net_ctx, "exi");
	err = jaln_register_encoding(net_ctx, "deflate");

	//err = jan_register_tls(net_ctx, "priv_key", "pub_cert", "path/to/peer/certs");
	err = jaln_register_subscriber_callbacks(net_ctx, sub_cbs);
	DEBUG_LOG("register sub cbs: %d\n", err);
	err = jaln_register_connection_callbacks(net_ctx, conn_cbs);
	DEBUG_LOG("register conn cbs: %d\n", err);
	err = jaln_register_publisher_callbacks(net_ctx, pub_cbs);
	DEBUG_LOG("register pub cbs: %d\n", err);
	err = jaln_listen(net_ctx, "0.0.0.0", "55555", NULL);
	err = jaln_listener_wait(net_ctx);
	return 0;
}

