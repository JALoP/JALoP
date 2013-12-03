/**
* @file jsub_callbacks.cpp This file contains handlers for the
* Network Library subscriber callbacks.
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

#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "jsub_callbacks.hpp"
#include "jsub_db_layer.hpp"
#include "jal_alloc.h"
#include "jal_base64_internal.h"

#define DEBUG_LOG(args...) \
	do { \
		fprintf(stdout, "(jal_subscribe) %s[%d] ", __FILE__, __LINE__); \
		fprintf(stdout, ##args); \
		fprintf(stdout, "\n"); \
	} while(0)

#define JSUB_INITIAL_SID "0"

volatile bool jsub_is_conn_closed = false;
volatile int jsub_debug = 0;
static struct jaln_subscriber_callbacks *sub_cbs =  NULL;
static struct jaln_connection_callbacks *cb = NULL;

// Journal buffers
static uint8_t *journal_sys_meta_buf = NULL;
static uint32_t journal_sys_meta_size = 0;
static uint8_t *journal_app_meta_buf = NULL;
static uint32_t journal_app_meta_size = 0;

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
		__attribute__((unused)) const struct jaln_connect_request *req,
		__attribute__((unused)) int *selected_encoding,
		__attribute__((unused)) int *selected_digest,
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
	if ((-1 != db_payload_fd) &&
		(JALN_RTYPE_JOURNAL == channel_info->type)) {
		// Valid file descriptor
		uint64_t offset = jsub_get_offset(db_payload_fd);
		int rc = jsub_store_journal_resume(
					jsub_db_ctx,
					channel_info->hostname,
					db_payload_path, offset);
		if ((0 != rc)  && jsub_debug) {
			DEBUG_LOG("store journal resume failed for host: %s",
				  channel_info->hostname);
		}
		if ((0 == rc)  && jsub_debug) {
			DEBUG_LOG("store journal resume succeeded for host: %s",
				  channel_info->hostname);
		}
	}
}

void jsub_on_connection_close(
		__attribute__((unused)) const struct jaln_connection *jal_conn,
		__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("ON_CONNECTION_CLOSED");
		DEBUG_LOG("conn_info: %p", jal_conn);
	}
	jsub_is_conn_closed = true;
}

void jsub_connect_ack(
	__attribute__((unused)) const struct jaln_connect_ack *ack,
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
	}
}

void jsub_connect_nack(
	__attribute__((unused)) const struct jaln_connect_nack *nack,
	__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("CONNECT_NACK");
		DEBUG_LOG("ack: %p", nack);
	}
	jsub_is_conn_closed = true;
}

int jsub_get_subscribe_request(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		char **serial_id,
		uint64_t *offset)
{
	int ret = 0;
	enum jaldb_status db_err;
	enum jaldb_rec_type rec_type;
	if (jsub_debug) {
		DEBUG_LOG("GET_SUBSCRIBE_REQUEST");
		DEBUG_LOG("host_name: %s", ch_info->hostname);
	}

	switch (type)
	{
		case JALN_RTYPE_JOURNAL:
			rec_type = JALDB_RTYPE_JOURNAL;
			break;
		case JALN_RTYPE_AUDIT:
			rec_type = JALDB_RTYPE_AUDIT;
			break;
		case JALN_RTYPE_LOG:
			rec_type = JALDB_RTYPE_LOG;
			break;
		default:
			rec_type = JALDB_RTYPE_UNKNOWN;
			break;
	}
	// Going to need to store the last confed sid to the
	// 	temp container so that it can be retrieved here.
	std::string sid_out;

	db_err = jaldb_get_last_confed_sid_temp(jsub_db_ctx, rec_type, ch_info->hostname, serial_id);
	if (JALDB_OK != db_err) {
		if (jsub_debug) {
			DEBUG_LOG("last confed sid not found, defaulting to 0.");
		}
		sid_out = JSUB_INITIAL_SID;
		*serial_id = jal_strdup((char *)JSUB_INITIAL_SID);
	}
	if (jsub_debug) {
		DEBUG_LOG("record_type: %d ser_id: %s",
			  type, sid_out.c_str());
	}
	ret = JAL_OK;

	if (type == JALN_RTYPE_JOURNAL) {
		// Retrieve offset if it exists
		ret = jsub_get_journal_resume(jsub_db_ctx,
					ch_info->hostname,
					&db_payload_path, *offset);
		if (0 != ret) {
			// Default
			*offset = 0;
			db_payload_path = NULL;
		}
		if ((0 != ret) && jsub_debug) {
			DEBUG_LOG("failed to retrieve a journal resume for host: %s",
				  ch_info->hostname);
		}
		if ((0 == ret) && jsub_debug) {
			DEBUG_LOG("retrieved a journal resume for host: %s",
				  ch_info->hostname);
		}
		ret = 0;
	}
	return ret;
}

int jsub_on_record_info(
		__attribute__((unused)) jaln_session *session,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		__attribute__((unused)) const struct jaln_record_info *record_info,
		__attribute__((unused)) const struct jaln_mime_header *headers,
		const uint8_t *system_metadata_buffer,
		const uint32_t system_metadata_size,
		const uint8_t *application_metadata_buffer,
		const uint32_t application_metadata_size,
		__attribute__((unused)) void *user_data)
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
		journal_sys_meta_buf = (uint8_t *) jal_strndup((char *)system_metadata_buffer, system_metadata_size);
		journal_app_meta_size = application_metadata_size;
		journal_app_meta_buf = (uint8_t *) jal_strndup((char *)application_metadata_buffer, application_metadata_size);
		break;
	case JALN_RTYPE_AUDIT:
		audit_sys_meta_size = system_metadata_size;
		audit_sys_meta_buf = (uint8_t *) jal_strndup((char *)system_metadata_buffer, system_metadata_size);
		audit_app_meta_size = application_metadata_size;
		audit_app_meta_buf = (uint8_t *) jal_strndup((char *)application_metadata_buffer, application_metadata_size);
		break;
	case JALN_RTYPE_LOG:
		log_sys_meta_size = system_metadata_size;
		log_sys_meta_buf = (uint8_t *) jal_strndup((char *)system_metadata_buffer, system_metadata_size);
		log_app_meta_size = application_metadata_size;
		log_app_meta_buf = (uint8_t *) jal_strndup((char *)application_metadata_buffer, application_metadata_size);
		break;
	default:
		break;
	}

	return JAL_OK;
}

int jsub_on_audit(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		const uint8_t *buffer,
		const uint32_t cnt,
		__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("ON_AUDIT");
		DEBUG_LOG("ch info:%p serial_id:%s buf: %p cnt:%d ud:%p\n",
			ch_info, serial_id, buffer, cnt, user_data);
	}
	// Insert audit into temp container
	return jsub_insert_audit(jsub_db_ctx, ch_info->hostname, audit_sys_meta_buf,
				 audit_sys_meta_size, audit_app_meta_buf,
				 audit_app_meta_size, (uint8_t *)buffer, cnt,
				 (char *)serial_id, jsub_debug);
}

int jsub_on_log(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		const uint8_t *buffer,
		const uint32_t cnt,
		__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("ON_LOG");
		DEBUG_LOG("ch info:%p serial_id:%s buf: %p cnt:%d ud:%p\n",
			ch_info, serial_id, buffer, cnt, user_data);
	}

	// Insert log into temp container
	return jsub_insert_log(jsub_db_ctx, ch_info->hostname, log_sys_meta_buf,
				log_sys_meta_size, log_app_meta_buf,
				log_app_meta_size, (uint8_t *)buffer, cnt,
				(char *)serial_id, jsub_debug);
}

int jsub_on_journal(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		const uint8_t *buffer,
		const uint32_t cnt,
		__attribute__((unused)) const uint64_t offset,
		const int more,
		__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("ON_JOURNAL");
		DEBUG_LOG("more: %d", more);
		DEBUG_LOG("ch info:%p serial_id:%s buf: %p cnt:%d ud:%p\n",
			  ch_info, serial_id, buffer, cnt, user_data);
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
					jsub_debug);
			if (0 != ret) {
				return ret;
			}
		}
		return jsub_insert_journal_metadata(
					jsub_db_ctx,
					ch_info->hostname,
					journal_sys_meta_buf,
					journal_sys_meta_size,
					journal_app_meta_buf,
					journal_app_meta_size,
					db_payload_path,
					(char *)serial_id,
					jsub_debug);
	} else {
		// There will be more data, append what we've
		//	received to file on disk.
		return jsub_write_journal(
					jsub_db_ctx,
					&db_payload_path,
					&db_payload_fd,
					(uint8_t *)buffer,
					cnt,
					jsub_debug);
	}
	return JAL_OK;
}

int jsub_notify_digest(
		__attribute__((unused)) jaln_session *session,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) char *serial_id,
		__attribute__((unused)) const uint8_t *digest,
		__attribute__((unused)) const uint32_t len,
		__attribute__((unused)) const void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("NOTIFY_DIGEST");
		DEBUG_LOG("ch info:%p type:%d serial_id:%s dgst:%p, len:%d, ud:%p\n",
			ch_info, type, serial_id, digest, len,
			user_data);
		char *b64 = jal_base64_enc(digest, len);
		DEBUG_LOG("dgst: %s\n", b64);
	}
	return JAL_OK;
}

int jsub_on_digest_response(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *serial_id,
		__attribute__((unused)) const enum jaln_digest_status status,
		__attribute__((unused)) const void *user_data)
{
	char *nonce = NULL;
	// Once received, perform transfer operation
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
	if (jsub_debug) {
		DEBUG_LOG("ON_DIGEST_RESPONSE");
		DEBUG_LOG("ch info:%p type:%d serial_id:%s status: %s, ds:%d, ud:%p\n",
				ch_info, type, serial_id, status_str, status, user_data);
	}
	enum jaldb_status db_err;
	int ret = -1;
	enum jaldb_rec_type jaldb_type = JALDB_RTYPE_UNKNOWN;
	std::string sid_out = "";
	std::string source = ch_info->hostname;
	std::string ser_id = serial_id;
	std::string rec_type = "";
	bool willXfer = false;
	switch (type)
	{
		case JALN_RTYPE_JOURNAL:
			// xfer journal
			willXfer = true;
			rec_type = "JOURNAL";
			jaldb_type = JALDB_RTYPE_JOURNAL;
			break;
		case JALN_RTYPE_AUDIT:
			// xfer audit
			willXfer = true;
			rec_type = "AUDIT";
			jaldb_type = JALDB_RTYPE_AUDIT;
			break;
		case JALN_RTYPE_LOG:
			// xfer log
			willXfer = true;
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
		db_err = jaldb_xfer(jsub_db_ctx, jaldb_type, jal_strdup(source.c_str()), jal_strdup(ser_id.c_str()), &nonce);
		if(JALDB_OK == db_err) {
			db_err = jaldb_store_confed_sid_temp(jsub_db_ctx, jaldb_type, jal_strdup(source.c_str()), jal_strdup(ser_id.c_str()));
			if (jsub_debug) {
				if (JALDB_OK == db_err) {
					ret = JAL_OK;
					DEBUG_LOG("Store confed sid success! %s sid: %s\n",
						rec_type.c_str(), ser_id.c_str());
				}
				else {
					DEBUG_LOG("Store confed sid fail! %s sid: %s\n",
						  rec_type.c_str(), ser_id.c_str());
				}
			}
		} else {
			DEBUG_LOG("Failed to transfer record! %s sid: %s\n",
				rec_type.c_str(), ser_id.c_str());
		}
	}
	free(nonce);
	return ret;
}

void jsub_message_complete(
		__attribute__((unused)) jaln_session *session,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		__attribute__((unused)) void *user_data)
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
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("ACQUIRE_JOURNAL_FEEDER");
		DEBUG_LOG("ch_info: %p, sid:%s, feeder:%p\n",
			  ch_info, serial_id, feeder);
	}
	feeder->feeder_data = user_data;
	feeder->get_bytes = jsub_get_bytes;
	return JAL_OK;
}

void jsub_release_journal_feeder(
		__attribute__((unused)) jaln_session *session,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
	if (jsub_debug) {
		DEBUG_LOG("RELEASE_JOURNAL_FEEDER");
		DEBUG_LOG("ch_info: %p, sid:%s, feeder:%p\n",
			  ch_info, serial_id, feeder);
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
	return jaln_register_subscriber_callbacks(context, sub_cbs);
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
