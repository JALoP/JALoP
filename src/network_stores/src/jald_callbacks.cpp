/**
 * @file
 *
 * @brief This file contains the implementation of function callbacks invoked by
 * the jaln network_lib to pass information to jald.
 *
 * ### LICENSE
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <pthread.h>
#include <jalop/jaln_network.h>

#include "jal_ts_utils.h"
#include "jal_alloc.h"
#include "jald_common_definitions.hpp"
#include "jald_callbacks.hpp"
#include "jald_filter_extension.hpp"
#include "jal_base64_internal.h"
#include "jald_config.hpp"


// Global values shared from jald.cpp
extern global_args_t global_args;
extern uint16_t next_subscriber_token;
extern int threads_to_exit;
extern pthread_mutex_t exit_count_lock;
extern UDSSendSocket requestSocket;
extern pthread_mutex_t request_socket_lock;

void on_channel_close(
		const struct jaln_channel_info *ch_info,
		void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Session is closing");

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(ch_info->type);

	// Close db_handle for this channel
	std::shared_ptr<struct session_ctx_t> ctxPtr = nullptr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(ch_info->hostname);

		// (currently only used by the receive thread)
		// indicate that this session is closing
		ctxPtr->shutting_down = true;

		// Note that erasing the item from our maps doesn't actually destroy the session_ctx_t
		// until all shared_ptrs pointing to it go out of scope, so we can keep using ctxPtr
		sessionHostMap.erase(ctxPtr->hostname);
		sessionTokenMap.erase(ctxPtr->subscriber_token);
		// mapLock is per record type, not per session, so we don't remove that ever

		// Destroy in progress record, if any
		if(ctxPtr->rec) {
			jaldb_destroy_record(&ctxPtr->rec);
		}

		// If we're using the db, close the handle
		if(!global_args.use_filter) {
			jaldb_context_destroy(&ctxPtr->db_ctx);
		} 
		// If we're using the sockets, signal the pthread_cond associated with this thread so the 
		// record_receive_thread will wake, just in case it's already blocked waiting on us
		else {
			pthread_cond_signal(&(ctxPtr->socket_thread_signal));
		}

		pthread_mutex_unlock(mapLock.get());
	} catch(std::out_of_range& e) {
		pthread_mutex_unlock(mapLock.get());
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: No context or DB context associated with closing channel");
	}


	DEBUG_LOG_SUB_SESSION(ch_info, "Closing other sessions");
	PeerConfig *peer = (PeerConfig *)user_data;
	if (peer) {
		std::lock_guard<std::mutex> guard(peer->peer_lock);
		jaln_disconnect(peer->conn); //session->closing=true, for each session.
		DEBUG_LOG_SUB_SESSION(ch_info, "Closed other sessions");
	}
}

void on_connection_close(
		__attribute__((unused)) const struct jaln_connection *jal_conn,
		void *user_data)
{
	PeerConfig *peer = (PeerConfig*)user_data;
	if (!peer) {
		DEBUG_LOG("User data not set for connection_close callback");
		return;
	}
	if (JAL_OK != jaln_shutdown(peer->conn)) {
		DEBUG_LOG("Failed to shutdown connection to %s:%llu", peer->host.c_str(), peer->port);
	} else {
		DEBUG_LOG("Closed connection to %s:%llu", peer->host.c_str(), peer->port);
	}
	jaln_disconnect(peer->conn); // marks session->closing = true, for each session.
	peer->connected = false;
}

#define LOG_STR_FIELD(_s, _f) DEBUG_LOG(#_f": %s", _s->_f? _s->_f : "(nil)")
#define LOG_INT_FIELD(_s, _f) DEBUG_LOG(#_f": %d", _s->_f)
#define LOG_PTR_FIELD(_s, _f) DEBUG_LOG(#_f": %p", _s->_f)
void on_connect_ack(
		const struct jaln_connect_ack *ack,
		__attribute__((unused))void *user_data)
{
	DEBUG_LOG("initialize-ack received:");
	DEBUG_LOG("ack: %p", ack);
	LOG_STR_FIELD(ack, hostname);
	LOG_STR_FIELD(ack, addr);
	LOG_INT_FIELD(ack, jaln_version);
	LOG_STR_FIELD(ack, jaln_agent);
	LOG_INT_FIELD(ack, mode);
	LOG_PTR_FIELD(ack, headers);
}

void on_connect_nack(
		const struct jaln_connect_nack *nack,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("initialize-nack received:");
	DEBUG_LOG("nack: %p", nack);
	DEBUG_LOG("user_data: %p", user_data);
	LOG_STR_FIELD(nack->ch_info, hostname);
	LOG_STR_FIELD(nack->ch_info, addr);
	LOG_STR_FIELD(nack->ch_info, compression);
	LOG_STR_FIELD(nack->ch_info, digest_method);
	LOG_INT_FIELD(nack->ch_info, type);
	LOG_PTR_FIELD(nack, error_list);
	LOG_INT_FIELD(nack, error_cnt);
	for (int i = 0; i < nack->error_cnt; ++i) {
		DEBUG_LOG("error[%d]: %s", i, nack->error_list[i]);
	}
}
#undef LOG_STR_FIELD
#undef LOG_INT_FIELD
#undef LOG_PTR_FIELD

// If a resume is requested, pub_on_journal_resume is called prior to (and in addition to)
// pub_on_subscribe. In this case, pub_on_journal_resume creates the session context and inserts
// it to the hash map. pub_on_subscribe detects this by finding ctx != NULL
// "offset" is unused here because it is set in session->pub_data->payload_off
// by the jaln_nextwork layer, and that value is used internally by jaln_send_payload_feeder anyway
enum jal_status pub_on_journal_resume(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		struct jaln_record_info *record_info,
		__attribute__((unused)) uint64_t offset,
		uint8_t **system_metadata_buffer,
		uint8_t **application_metadata_buffer,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Journal Resume");

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(JALN_RTYPE_JOURNAL);

	pthread_mutex_lock(mapLock.get());

	// A resume should create a new session context, ensure a session with this hostname does not
	// already exist
	if(0 != sessionHostMap.count(std::string(ch_info->hostname))) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Subscriber already exists");
		pthread_mutex_unlock(mapLock.get());
		return JAL_E_INVAL;
	}

	// The session does not alreaady exist. Create it
	// This is a shared pointer to allow both maps to point at the same context safely and ensures
	// the context object can't be destroyed while in use, even if it is removed from the maps
	std::shared_ptr<struct session_ctx_t> ctxPtr = std::make_shared<struct session_ctx_t>(
		std::string(ch_info->hostname),
		next_subscriber_token);

	// Insert this session by hostname and token to our maps
	sessionHostMap.insert({std::string(ch_info->hostname), ctxPtr});
	sessionTokenMap.insert({next_subscriber_token, ctxPtr});
	pthread_mutex_unlock(mapLock.get());

	ctxPtr->rec = NULL;
	// When not using the filter, immediately retrieve the record identified by record_info->nonce
	// from the DB
	if (!global_args.use_filter){
		ctxPtr->db_ctx = setup_db_layer();
		if(NULL == ctxPtr->db_ctx) {
			return JAL_E_INVAL;
		}

		enum jaldb_status db_ret = JALDB_E_INVAL;

		db_ret = jaldb_get_record(ctxPtr->db_ctx, JALDB_RTYPE_JOURNAL, record_info->nonce, &(ctxPtr->rec));
		if (JALDB_OK != db_ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to retrieve journal from db");
			return JALDB_E_NOT_FOUND == db_ret? JAL_E_JOURNAL_MISSING : JAL_E_INVAL;
		}

		*system_metadata_buffer = ctxPtr->rec->sys_meta->payload;
		if (ctxPtr->rec->app_meta) {
			*application_metadata_buffer = ctxPtr->rec->app_meta->payload;
		} else {
			*application_metadata_buffer = NULL;
		}
	}
	// When using the filter, store the nonce for later retrieval
	// sess->pub_data->payload_off is already set for later use
	else {
		ctxPtr->resume_nonce = strdup(record_info->nonce);
	}
	return JAL_OK;
}

// If a resume is requested, pub_on_journal_resume is called prior to (and in addition to)
// pub_on_subscribe. In this case, pub_on_journal_resume creates the session context and inserts
// it to the hash map. pub_on_subscribe detects this by finding ctxPtr != NULL
enum jal_status pub_on_subscribe(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		enum jaln_publish_mode mode,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	pthread_attr_t attr;
	if (0 != pthread_attr_init(&attr)) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR in pthread_attr_init()");
		return JAL_E_INVAL;
	}

	enum jal_status ret = JAL_E_INVAL;
	// Ensure main doesn't try to exit before the thread we're about to create does
	// Note - pub_on_subscribe is called in the chain from jaln_publish, so there isn't actually
	// a risk of main trying to exit during this function
	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit += 1;
	pthread_mutex_unlock(&exit_count_lock);

	pthread_t journal_thread;
	pthread_t audit_thread;
	pthread_t log_thread;

	struct thread_data *data = (struct thread_data *) jal_malloc(sizeof(struct thread_data));
	data->sess = sess;
	data->ch_info = ch_info;
	data->timestamp = NULL;
	// pub_on_subscriber is called directly on the main thread via jaln_publish
	// we can trust that the global value next_subscriber_token will not be concurrently accessed.
	// This is incremented in the main loop, after all corresponding threads have been started
	// Unused when not using the filter
	data->subscriber_token = next_subscriber_token;

	if (0 != pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR in pthread_attr_setdetachstate()");
		ret = JAL_E_INVAL;
		goto err_out;
	}

	if (JALN_LIVE_MODE == mode) {
		data->timestamp = jal_gen_timestamp_usec();
		if (!data->timestamp) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Error: Error generating timestamp");
			ret = JAL_E_INVAL_TIMESTAMP;
			goto err_out;
		}
	} else if (JALN_ARCHIVE_MODE != mode) {
		// Bad mode
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: Bad mode");
		ret = JAL_E_INVAL;
		goto err_out;
	}

	pthread_t* thread;
	switch (type) {
	case JALN_RTYPE_JOURNAL:
		DEBUG_LOG_SUB_SESSION(ch_info, "Starting journal thread.");
		thread = &journal_thread;
		break;

	case JALN_RTYPE_AUDIT:
		DEBUG_LOG_SUB_SESSION(ch_info, "Starting audit thread.");
		thread = &audit_thread;
		break;

	case JALN_RTYPE_LOG:
		DEBUG_LOG_SUB_SESSION(ch_info, "Starting log thread.");
		thread = &log_thread;
		break;

	default:
		DEBUG_LOG_SUB_SESSION(ch_info, "Illegal Record Type");
		ret = JAL_E_INVAL;
		goto err_out;
	}

	if(0 != pthread_create(thread, &attr, pub_send, data)) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
		ret = JAL_E_INVAL;
		goto err_out;
	}
	pthread_attr_destroy(&attr);

	return JAL_OK;
	// There are a number of cleanup steps that we need to do in error cases
err_out:
	pthread_attr_destroy(&attr);
	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit -= 1;
	pthread_mutex_unlock(&exit_count_lock);
	return ret;
}

enum jal_status pub_on_record_complete(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		char *nonce,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "On record complete: %s", nonce);

	enum jaldb_rec_type db_type = JALDB_RTYPE_UNKNOWN;
	switch(type) {
	case JALN_RTYPE_JOURNAL:
		db_type = JALDB_RTYPE_JOURNAL;
		break;
	case JALN_RTYPE_AUDIT:
		db_type = JALDB_RTYPE_AUDIT;
		break;
	case JALN_RTYPE_LOG:
		db_type = JALDB_RTYPE_LOG;
		break;
	default:
		DEBUG_LOG_SUB_SESSION(ch_info, "Invalid record type");
		return JAL_E_INVAL;
	}

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);

	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	pthread_mutex_lock(mapLock.get());

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		pthread_mutex_unlock(mapLock.get());
		return JAL_E_INVAL;
	}

	enum jaln_publish_mode mode = jaln_session_get_publish_mode(sess);
	// Only mark the records as sent in archive mode
	if (mode == JALN_ARCHIVE_MODE && !global_args.use_filter) {
		pthread_mutex_lock(mapLock.get());
		enum jaldb_status jaldb_ret = jaldb_mark_sent(ctxPtr->db_ctx, db_type, nonce, 1);
		pthread_mutex_unlock(mapLock.get());
		if (JALDB_OK != jaldb_ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to mark %s as sent: %d", nonce, jaldb_ret);
		} else {
			DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as sent %i", nonce, db_type);
		}
	}
	jaldb_destroy_record(&ctxPtr->rec);
	return JAL_OK;
}

void pub_sync(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		enum jaln_publish_mode mode,
		const char *nonce,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "sync: %s", nonce);

	enum jaldb_status jaldb_ret = JALDB_E_INVAL;
	enum jaldb_rec_type db_type = JALDB_RTYPE_UNKNOWN;

	switch(type) {
	case JALN_RTYPE_JOURNAL:
		db_type = JALDB_RTYPE_JOURNAL;
		break;
	case JALN_RTYPE_AUDIT:
		db_type = JALDB_RTYPE_AUDIT;
		break;
	case JALN_RTYPE_LOG:
		db_type = JALDB_RTYPE_LOG;
		break;
	default:
		// shouldn't happen.
		return;
	}

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);
	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	pthread_mutex_lock(mapLock.get());

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		pthread_mutex_unlock(mapLock.get());
		return;
	}

	// If using the filter, signal the filter that the record was handled completely
	// with success.
	if (global_args.use_filter){
		RecordResponseArgs args;
		args.mType = FilterMessageType::RecordSuccess;
		args.subscriberToken = ctxPtr->subscriber_token;
		args.type = db_type;
		args.recordNonce = nonce;

		// Create and send the message
		pthread_mutex_lock(&request_socket_lock);
		requestSocket.sendMsg(JalFilterRecordResponse(args));
		pthread_mutex_unlock(&request_socket_lock);
	} 
	else {
		// Only sync the record in the DB in archive mode with digest challenges
		if (mode == JALN_ARCHIVE_MODE && ch_info->digest_method) {
			pthread_mutex_lock(mapLock.get());
			jaldb_ret = jaldb_mark_synced(ctxPtr->db_ctx, db_type, nonce);
			pthread_mutex_unlock(mapLock.get());
			if (JALDB_OK != jaldb_ret) {
				DEBUG_LOG_SUB_SESSION(ch_info, "Failed to mark %s as synced: %d", nonce, jaldb_ret);
			} else {
				DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as synced", nonce);
			}
		}
	}

}

void pub_notify_digest(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		const char *nonce,
		const uint8_t *digest,
		const uint32_t size,
		__attribute__((unused)) void *user_data)
{
	char *b64 = jal_base64_enc(digest, size);
	DEBUG_LOG_SUB_SESSION(ch_info, "Digest for %s: %s", nonce, b64);
	free(b64);
}

void pub_peer_digest(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *nonce,
		const uint8_t *local_digest,
		const uint32_t local_size,
		const uint8_t *peer_digest,
		const uint32_t peer_size,
		__attribute__((unused)) void *user_data)
{
	enum jaldb_rec_type db_type = JALDB_RTYPE_UNKNOWN;
	enum jaldb_status db_ret = JALDB_E_INVAL;
	switch (type) {
	case JALN_RTYPE_JOURNAL:
		db_type = JALDB_RTYPE_JOURNAL;
		break;
	case JALN_RTYPE_AUDIT:
		db_type = JALDB_RTYPE_AUDIT;
		break;
	case JALN_RTYPE_LOG:
		db_type = JALDB_RTYPE_LOG;
		break;
	default:
		// shouldn't happen.
		db_type = JALDB_RTYPE_UNKNOWN;
		return;
	}

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);
	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	pthread_mutex_lock(mapLock.get());
	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		pthread_mutex_unlock(mapLock.get());
		return;
	}

	// Check for error conditions
	if (!local_digest || !peer_digest) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Error: Missing peer or local digest.");
		goto error;
	}
	if ((0 == local_size) || (0 == peer_size) || (local_size != peer_size)) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Error: Digests have different lengths for %s. Local[%u] Peer[%u]", nonce, local_size, peer_size);
		goto error;
	}
	if (0 != memcmp(local_digest, peer_digest, local_size)) {
		char *local_b64 = jal_base64_enc(local_digest, local_size);
		char *peer_b64 = jal_base64_enc(peer_digest, peer_size);
		DEBUG_LOG_SUB_SESSION(ch_info, "Error: Digests do not match for %s. Local[%s] Peer[%s]",nonce, local_b64, peer_b64);
		free(local_b64);
		free(peer_b64);
		goto error;
	}
	// Digest match
	DEBUG_LOG_SUB_SESSION(ch_info, "Digest match for %s", nonce);
	goto out;

error:
	// The digests do not match. We need to mark the record as unsent so it can be sent again by the publisher.


	if(ctxPtr)
	{
		if (global_args.use_filter){
			RecordResponseArgs args;
			args.mType = FilterMessageType::RecordError;
			args.subscriberToken = ctxPtr->subscriber_token;
			args.type = db_type;
			args.recordNonce = nonce;

			// Create and send the message
			pthread_mutex_lock(&request_socket_lock);
			requestSocket.sendMsg(JalFilterRecordResponse(args));
			pthread_mutex_unlock(&request_socket_lock);
			db_ret = JALDB_OK;
		}
		else
		{
			db_ret = jaldb_mark_sent(ctxPtr->db_ctx, db_type, nonce, 0);
		}
	}

	if (JALDB_OK != db_ret) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Error: Failed to update record as unsent %s. Return code: %d", nonce, db_ret);
		goto out;
	} else {
		DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as unsent", nonce);
	}

out:
	// No status returned by callback function
	return;
}
