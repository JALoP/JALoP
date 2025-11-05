/**
 * @file
 *
 * @brief This file contains handlers for the
 * Network Library subscriber callbacks.
 *
 * ### LICENSE
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
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <jalop/jaln_network_types.h>
#include "jsub_callbacks.hpp"
#include "jsub_db_layer.hpp"
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jal_base64_internal.h"

#define DEBUG_LOG(args...) \
	do { \
		time_t rawtime; \
		time(&rawtime); \
		char timestr[26]; \
		strftime(timestr, 26, "%Y-%m-%dT%H:%M:%S", gmtime(&rawtime)); \
		fprintf(stderr, "(jal_subscribe) %s[%d](%s) ", __FUNCTION__, __LINE__, timestr); \
		fprintf(stderr, ##args); \
		fprintf(stderr, "\n"); \
	} while(0)

#define JSUB_INITIAL_NONCE "0"

volatile bool jsub_is_conn_closed = true;
volatile int jsub_debug = 0;
static struct jaln_subscriber_callbacks *sub_cbs =  NULL;
static struct jaln_connection_callbacks *cb = NULL;

// Journal buffers
static uint8_t *journal_sys_meta_buf = NULL;
static uint32_t journal_sys_meta_size = 0;
static uint8_t *journal_app_meta_buf = NULL;
static uint32_t journal_app_meta_size = 0;
static uint64_t journal_payload_size = 0;

// Audit buffers
static uint8_t *audit_sys_meta_buf = NULL;
static uint32_t audit_sys_meta_size = 0;
static uint8_t *audit_app_meta_buf = NULL;
static uint32_t audit_app_meta_size = 0;

// Log buffers
static uint8_t *log_sys_meta_buf = NULL;
static uint32_t log_sys_meta_size = 0;
static uint8_t *log_app_meta_buf = NULL;
static uint32_t log_app_meta_size = 0;

// Journal path and fd
static char *db_payload_path = NULL;
static int db_payload_fd = -1;

enum jaln_connect_error jsub_connect_request_handler(
		const struct jaln_connect_request *req,
		int *selected_encoding,
		int *selected_digest,
		__attribute__((unused)) void *user_data)
{
	// Nothing to do here
	if (jsub_debug) {
		DEBUG_LOG("CONNECT_REQUEST_HANDLER");
		DEBUG_LOG("req: %p, enc:%p, dgst:%p", req, selected_encoding, selected_digest);
	}
	return JALN_CE_ACCEPT;
}

void jsub_on_channel_close(
		const struct jaln_channel_info *channel_info,
		__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("ON_CHANNEL_CLOSED");
		DEBUG_LOG("channel_info: %p", channel_info);
	}
}

void jsub_on_connection_close(
		const struct jaln_connection *jal_conn,
		__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("ON_CONNECTION_CLOSED");
		DEBUG_LOG("conn_info: %p", jal_conn);
	}
	jsub_is_conn_closed = true;
}

void jsub_connect_ack(
	const struct jaln_connect_ack *ack,
	__attribute__((unused)) void *user_data)
{
	// Nothing to do here
	if (jsub_debug) {
		DEBUG_LOG("CONNECT_ACK");
		DEBUG_LOG("hostname: %s", ack->hostname);
		DEBUG_LOG("addr: %s", ack->addr);
		DEBUG_LOG("version: %d", ack->jaln_version);
		if (ack->jaln_agent) {
			DEBUG_LOG("agent: %s", ack->jaln_agent);
		}
		DEBUG_LOG("role: %s", ack->mode == JALN_ROLE_SUBSCRIBER ? "subscriber" : "publisher");
		DEBUG_LOG("digest_algorithm: %s", ack->digest_algorithm);
		DEBUG_LOG("encoding: %s", ack->encoding);
	}
}

void jsub_connect_nack(
	const struct jaln_connect_nack *nack,
	__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("CONNECT_NACK");
		DEBUG_LOG("ack: %p", nack);
	}
	jsub_is_conn_closed = true;
}

int jsub_get_subscribe_request(
		jaln_session *session,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		char **nonce,
		uint64_t *offset)
{
	int ret = 0;
	// enum jaldb_rec_type rec_type = JALDB_RTYPE_UNKNOWN;
	if (jsub_debug) {
		DEBUG_LOG("GET_SUBSCRIBE_REQUEST");
		DEBUG_LOG("host_name: %s", ch_info->hostname);
	}

	std::string nonce_out;
	if (type == JALN_RTYPE_JOURNAL) {
		// Check configuration for journal resume threshold
		long long threshold = jaln_session_get_resume_threshold(session);
		// Retrieve offset if it exists
		char *full_payload_path = NULL;
		ret = jsub_get_journal_resume(jsub_db_ctx,
					ch_info->hostname,
					nonce,
					&db_payload_path, *offset);
		// In a degenerate case, the received data (range of size_t) could theoretically be
		// larger than the range of a long long, which is going to cause comparison problems.
		// The use of long long (at least 64 bits, signed) here is a restriction of libconfig.
		// We have no way to indicate larger thresholds than this in the config file
		// If resume isn't disabled (negative), or already 0 (always resume) go ahead and
		// assume we want to resume in that case, which we'll indicate by locally
		// setting threshold to 0 (always resume)
		if(threshold > 0 && *offset > LLONG_MAX) {
			threshold = 0;
		}
		// Skip the attempt to resume if
		// a) no resume entry exists in the db
		// b) the threshold was negative (journal_resume disabled), or could not be fetched
		// c) the amount of previously received data is below the configured threshold
		// Note: We can only safely do the size_t cast because we first check that threshold is positive
		if (0 != ret || 0 > threshold || (*offset) < (size_t)threshold) {
			if(0 == ret && 0 > threshold) {
				DEBUG_LOG("Journal resume available but ignored. Resume configuration was disabled "
					"or not accessible in associated jaln_context.");
			} else if(0 == ret && *offset < (size_t)threshold) {
				DEBUG_LOG("Journal resume avilable but ignored because cached data of size: %zu "
					"is less than configured threshold: %lld", *offset, threshold);
			}
			// Default
			*offset = 0;
			db_payload_path = NULL;
		} else {
			jal_asprintf(&full_payload_path, "%s/%s", jsub_db_ctx->journal_root, db_payload_path);
			nonce_out = *nonce;
			db_payload_fd = open(full_payload_path, O_RDWR | O_APPEND);
			if (0 > db_payload_fd) {
				DEBUG_LOG("Failed to open journal payload for resume: %s", strerror(errno));
			}
			DEBUG_LOG("Opened payload resume file: %d\n", db_payload_fd);
			free(full_payload_path);
		}
		if ((0 != ret) && jsub_debug) {
			DEBUG_LOG("No resume found for host: %s",
				  ch_info->hostname);
		}
		if ((0 == ret) && jsub_debug) {
			DEBUG_LOG("retrieved a journal resume for host: %s",
				  ch_info->hostname);
		}
		ret = 0;
	}

	if (jsub_debug) {
		DEBUG_LOG("record_type: %d nonce: %s",
			  type, nonce_out.c_str());
	}

	// In all cases, purge the stored journal resume data for this host
	// either we're consuming it, or there was an error retrieving it
	// In the worst case, this will result in a full retransmission on the next
	// connection attempt
	jsub_clear_journal_resume(jsub_db_ctx, ch_info->hostname);

	return ret;
}

int jsub_on_record_info(
		__attribute__((unused)) jaln_session *session,
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
	if (jsub_debug) {
		DEBUG_LOG("ON_RECORD INFO");
		DEBUG_LOG("ch info:%p type:%d rec_info: %p headers: %p smb: %p sms:%d amb:%p ams:%d ud:%p\n",
			ch_info, type, record_info, headers,
			system_metadata_buffer,
			system_metadata_size,
			application_metadata_buffer,
			application_metadata_size, user_data);
	}

	switch (type) {
	case JALN_RTYPE_JOURNAL:
		journal_sys_meta_size = system_metadata_size;
		journal_sys_meta_buf = (uint8_t *) jal_memdup((char *)system_metadata_buffer, system_metadata_size);
		journal_app_meta_size = application_metadata_size;
		journal_app_meta_buf = (uint8_t *) jal_memdup((char *)application_metadata_buffer, application_metadata_size);
		break;
	case JALN_RTYPE_AUDIT:
		audit_sys_meta_size = system_metadata_size;
		audit_sys_meta_buf = (uint8_t *) jal_memdup((char *)system_metadata_buffer, system_metadata_size);
		audit_app_meta_size = application_metadata_size;
		audit_app_meta_buf = (uint8_t *) jal_memdup((char *)application_metadata_buffer, application_metadata_size);
		break;
	case JALN_RTYPE_LOG:
		log_sys_meta_size = system_metadata_size;
		log_sys_meta_buf = (uint8_t *) jal_memdup((char *)system_metadata_buffer, system_metadata_size);
		log_app_meta_size = application_metadata_size;
		log_app_meta_buf = (uint8_t *) jal_memdup((char *)application_metadata_buffer, application_metadata_size);
		break;
	default:
		break;
	}

	return JAL_OK;
}

int jsub_on_audit(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *nonce,
		const uint8_t *buffer,
		const uint32_t cnt,
		void *user_data)
{
	// If the session is closing, skip writing. The sync message isn't going
	// to make it back to the publisher, and we'll end up with duplicates when
	// the connection is resumed
	if(jaln_session_is_closing(session)) {
		return JAL_OK;
	}

	if (jsub_debug) {
		DEBUG_LOG("ON_AUDIT");
		DEBUG_LOG("ch info:%p nonce:%s buf: %p cnt:%d ud:%p\n",
			ch_info, nonce, buffer, cnt, user_data);
	}
	// Insert audit into temp container
	return jsub_insert_audit(jsub_db_ctx, ch_info->hostname, audit_sys_meta_buf,
				 audit_sys_meta_size, audit_app_meta_buf,
				 audit_app_meta_size, (uint8_t *)buffer, cnt,
				 (char *)nonce, jsub_debug);
}

int jsub_on_log(
		jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *nonce,
		const uint8_t *buffer,
		const uint32_t cnt,
		void *user_data)
{
	// If the session is closing, skip writing. The sync message isn't going
	// to make it back to the publisher, and we'll end up with duplicates when
	// the connection is resumed
	if(jaln_session_is_closing(session)) {
		return JAL_OK;
	}

	if (jsub_debug) {
		DEBUG_LOG("ON_LOG");
		DEBUG_LOG("ch info:%p nonce:%s buf: %p cnt:%d ud:%p\n",
			ch_info, nonce, buffer, cnt, user_data);
	}

	// Insert log into temp container
	return jsub_insert_log(jsub_db_ctx, ch_info->hostname, log_sys_meta_buf,
				log_sys_meta_size, log_app_meta_buf,
				log_app_meta_size, (uint8_t *)buffer, cnt,
				(char *)nonce, jsub_debug);
}

int jsub_on_journal(
		jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *nonce,
		const uint8_t *buffer,
		const uint32_t cnt,
		__attribute__((unused)) const uint64_t offset,
		const int more,
		void *user_data)
{
	// If the session is closing, skip writing. The sync message isn't going
	// to make it back to the publisher, and we'll end up with duplicates when
	// the connection is resumed
	if(jaln_session_is_closing(session)) {
		return JAL_OK;
	}

	if (jsub_debug) {
		DEBUG_LOG("ON_JOURNAL");
		DEBUG_LOG("more: %d", more);
		DEBUG_LOG("ch info:%p nonce:%s buf: %p cnt:%d ud:%p\n",
			  ch_info, nonce, buffer, cnt, user_data);
	}

	// Write data to disk until there is no more data to write.
	// Then write the system/application metadata to DB.
	if (0 == more) {
		// No more data
		if (buffer) {
			int ret = jsub_write_journal(
					jsub_db_ctx,
					&db_payload_path,
					&db_payload_fd,
					(uint8_t *)buffer,
					cnt,
					0,
					ch_info->hostname,
					nonce,
					jsub_debug);
			if (0 != ret) {
				return ret;
			}
		} else {
			jsub_clear_journal_resume(jsub_db_ctx, ch_info->hostname);
		}
		int ret = jsub_insert_journal_metadata(
					jsub_db_ctx,
					ch_info->hostname,
					journal_sys_meta_buf,
					journal_sys_meta_size,
					journal_app_meta_buf,
					journal_app_meta_size,
					db_payload_path,
					journal_payload_size,
					(char *)nonce,
					jsub_debug);
		journal_payload_size = 0;
		return ret;
	} else {
		// There will be more data, append what we've
		//	received to file on disk.
		journal_payload_size += cnt;
		return jsub_write_journal(
					jsub_db_ctx,
					&db_payload_path,
					&db_payload_fd,
					(uint8_t *)buffer,
					cnt,
					journal_payload_size,
					ch_info->hostname,
					nonce,
					jsub_debug);
	}
	return JAL_OK;
}

int jsub_notify_digest(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		 enum jaln_record_type type,
		char *nonce,
		const uint8_t *digest,
		const uint32_t len,
		const void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("NOTIFY_DIGEST");
		DEBUG_LOG("ch info:%p type:%d nonce:%s dgst:%p, len:%d, ud:%p\n",
			ch_info, type, nonce, digest, len,
			user_data);
		char *b64 = jal_base64_enc(digest, len);
		DEBUG_LOG("dgst: %s\n", b64);
		free(b64);
	}
	return JAL_OK;
}

int jsub_on_digest_response(
		__attribute__((unused)) jaln_session *session,
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
			return -1;
	}
	if (jsub_debug) {
		DEBUG_LOG("ON_DIGEST_RESPONSE");
		DEBUG_LOG("ch info:%p type:%d nonce:%s status: %s, ds:%d, ud:%p\n",
				ch_info, type, nonce, status_str, status, user_data);
	}
	// If the status was CONFIRMED, we should mark it as such.
	// In any other case, we just return, and it will be removed at the next startup.
	if (status != JALN_DIGEST_STATUS_CONFIRMED) {
		return JAL_OK;
	}
	enum jaldb_status db_err;
	int ret = -1;
	enum jaldb_rec_type jaldb_type = JALDB_RTYPE_UNKNOWN;
	std::string nonce_out = "";
	std::string source = ch_info->hostname;
	std::string nonce_str = nonce;
	std::string rec_type = "";
	bool willXfer = false;
	char *rec_nonce = NULL;
	switch (type)
	{
		case JALN_RTYPE_JOURNAL:
			// xfer journal
			willXfer = true;
			ret = JAL_OK;
			rec_type = "JOURNAL";
			jaldb_type = JALDB_RTYPE_JOURNAL;
			break;
		case JALN_RTYPE_AUDIT:
			// xfer audit
			willXfer = true;
			ret = JAL_OK;
			rec_type = "AUDIT";
			jaldb_type = JALDB_RTYPE_AUDIT;
			break;
		case JALN_RTYPE_LOG:
			// xfer log
			willXfer = true;
			ret = JAL_OK;
			rec_type = "LOG";
			jaldb_type = JALDB_RTYPE_LOG;
			break;
		default:
			// Nothing
			ret = JAL_OK;
			rec_type = "UNKNOWN RECORD TYPE";
			break;
	}
	if (willXfer) {
		db_err = jaldb_mark_confirmed(jsub_db_ctx, jaldb_type, nonce_str.c_str(), &rec_nonce);
		if(JALDB_OK != db_err) {
			DEBUG_LOG("Failed to confirm record! %s nonce: %s error: %d\n",
				rec_type.c_str(), nonce_str.c_str(), db_err);
				ret = -1;
		}
	}
	free(rec_nonce);
	return ret;
}

void jsub_message_complete(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		void *user_data)
{
	int rc = 0;
	if (jsub_debug) {
		DEBUG_LOG("MESSAGE_COMPLETE");
		DEBUG_LOG("ch info:%p type:%d ud:%p\n",
			ch_info, type, user_data);
	}

	switch (type) {
	case JALN_RTYPE_JOURNAL:
		// Perform some cleanup?
		if (-1 != db_payload_fd) {
			rc = fsync(db_payload_fd);
			if ((-1 == rc) && jsub_debug) {
				DEBUG_LOG("payload file sync failed for %s\n",
					  ch_info->hostname);
			}
			rc = close(db_payload_fd);
			if ((-1 == rc) && jsub_debug) {
				DEBUG_LOG("payload file close failed for %s\n",
					  ch_info->hostname);
			}
			db_payload_fd = -1;
		}

		free(journal_sys_meta_buf);
		free(journal_app_meta_buf);
		free(db_payload_path);
		journal_sys_meta_buf = NULL;
		journal_app_meta_buf = NULL;
		journal_sys_meta_size = 0;
		journal_app_meta_size = 0;
		db_payload_path = NULL;
		break;
	case JALN_RTYPE_AUDIT:
		free(audit_sys_meta_buf);
		free(audit_app_meta_buf);
		audit_sys_meta_buf = NULL;
		audit_app_meta_buf = NULL;
		audit_sys_meta_size = 0;
		audit_app_meta_size = 0;
		break;
	case JALN_RTYPE_LOG:
		free(log_sys_meta_buf);
		free(log_app_meta_buf);
		log_sys_meta_buf = NULL;
		log_app_meta_buf = NULL;
		log_sys_meta_size = 0;
		log_app_meta_size = 0;
		break;
	default:
		break;
	}
}

enum jal_status jsub_get_bytes(
		const uint64_t offset,
		uint8_t *const buffer,
		uint64_t *size,
		__attribute__((unused))void *feeder_data)
{
	if (-1 == db_payload_fd){
		if (jsub_debug) {
			DEBUG_LOG("get_bytes: bad file descriptor!\n");
		}
		return JAL_E_BAD_FD;
	}
	int rc = lseek64(db_payload_fd, offset, SEEK_SET);
	if (-1 == rc ) {
		if (jsub_debug) {
			DEBUG_LOG("get_bytes: seek failed!\n");
		}
		return JAL_E_FILE_IO;
	}
	ssize_t bytes_read = read(db_payload_fd, buffer, *size);
	*size = bytes_read;
	if (-1 == bytes_read) {
		if (jsub_debug) {
			DEBUG_LOG("get_bytes: read failed!\n");
		}
		return JAL_E_FILE_IO;
	}
	return JAL_OK;
}

int jsub_acquire_journal_feeder(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *nonce,
		struct jaln_payload_feeder *feeder,
		void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("ACQUIRE_JOURNAL_FEEDER");
		DEBUG_LOG("ch_info: %p, nonce:%s, feeder:%p\n",
			  ch_info, nonce, feeder);
	}
	feeder->feeder_data = user_data;
	feeder->get_bytes = jsub_get_bytes;
	return JAL_OK;
}

void jsub_release_journal_feeder(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *nonce,
		struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("RELEASE_JOURNAL_FEEDER");
		DEBUG_LOG("ch_info: %p, nonce:%s, feeder:%p\n",
			  ch_info, nonce, feeder);
	}
	// Unclear what to do here
}

enum jal_status jsub_init_subscriber_callbacks(jaln_context *context)
{
	sub_cbs = jaln_subscriber_callbacks_create();
	sub_cbs->get_subscribe_request = jsub_get_subscribe_request;
	sub_cbs->on_record_info = jsub_on_record_info;
	sub_cbs->on_audit = jsub_on_audit;
	sub_cbs->on_log = jsub_on_log;
	sub_cbs->on_journal = jsub_on_journal;
	sub_cbs->notify_digest = jsub_notify_digest;
	sub_cbs->on_digest_response = jsub_on_digest_response;
	sub_cbs->message_complete = jsub_message_complete;
	sub_cbs->acquire_journal_feeder = jsub_acquire_journal_feeder;
	sub_cbs->release_journal_feeder = jsub_release_journal_feeder;
	enum jal_status ret = jaln_register_subscriber_callbacks(context, sub_cbs);

	jaln_subscriber_callbacks_destroy(&sub_cbs);
	return ret;
}

enum jal_status jsub_init_connection_callbacks(jaln_context *context)
{
	cb = jaln_connection_callbacks_create();
	cb->connect_request_handler = jsub_connect_request_handler;
	cb->on_channel_close = jsub_on_channel_close;
	cb->on_connection_close = jsub_on_connection_close;
	cb->connect_ack = jsub_connect_ack;
	cb->connect_nack = jsub_connect_nack;
	return jaln_register_connection_callbacks(context, cb);
}

enum jal_status jsub_callbacks_init(jaln_context *context)
{
	enum jal_status ret;
	ret = jsub_init_connection_callbacks(context);

	if (JAL_OK != ret) {
		if (jsub_debug) {
			DEBUG_LOG("connection_callback_init_failed\n");
		}
		return ret;
	}
	ret = jsub_init_subscriber_callbacks(context);
	if (JAL_OK != ret) {
		if (jsub_debug) {
			DEBUG_LOG("subscriber_callback_init_failed\n");
		}
		return ret;
	}
	return ret;
}
