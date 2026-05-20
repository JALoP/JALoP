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
#include <string>
#include <jalop/jaln_network.h>

#include "jal_ts_utils.h"
#include "jal_alloc.h"
#include "jald_common_definitions.hpp"
#include "jald_callbacks.hpp"
#include "jald_filter_extension.hpp"
#include "jal_base64_internal.h"
#include "jald_config.hpp"

// Global values shared from jald.cpp
extern JaldConfig global_config;
extern global_args_t global_args;
extern int threads_to_exit;
extern pthread_mutex_t exit_count_lock;
extern UDSSendSocket requestSocket;
extern pthread_mutex_t request_socket_lock;
extern int exiting;

#define LOG_STR_FIELD(_s, _f) DEBUG_LOG(#_f": %s", _s->_f? _s->_f : "(nil)")
#define LOG_INT_FIELD(_s, _f) DEBUG_LOG(#_f": %d", _s->_f)
#define LOG_ARR_FIELD(_s, _f, _i, _c) DEBUG_LOG(#_f": %s", _i < _s->_c? _s->_f? _s->_f[_i] : "(nil)" : "(bad index)")

// short hand for long map type names
using SessionHostMap = std::map<std::string, std::shared_ptr<session_ctx_t>>;
using SessionTokenMap = std::map<uint16_t, std::shared_ptr<session_ctx_t>>;

//Map to store subscriber token per subscriber hostname key
static std::map<std::string, uint16_t> subscriberTokenMap;
static uint16_t next_subscriber_token = 1;
static std::mutex subscriberTokenMapMutex;

static void removeSubscriberToken(const std::string& hostname)
{
	std::lock_guard<std::mutex> lock(subscriberTokenMapMutex);  //Locks the mutex for the scope
	subscriberTokenMap.erase(hostname);
}

static uint16_t getSubscriberToken(const std::string& hostname)
{
	std::lock_guard<std::mutex> lock(subscriberTokenMapMutex);  //Locks the mutex for the scope
	uint16_t currSubscriberToken = next_subscriber_token;

	//If hostname exist in map, then return corresponding subscriber token
	auto it = subscriberTokenMap.find(hostname);
	if (it != subscriberTokenMap.end())
	{
		return it->second;
	}
	else //If host name doesn't exist in map, add new entry and increment the subscriber token
	{
		subscriberTokenMap.insert({hostname, next_subscriber_token});
		next_subscriber_token ++;
	}

	return currSubscriberToken;
}

enum jaln_connect_error on_connect_request(
		const struct jaln_connect_request *req,
		__attribute__((unused)) int *selected_encoding,
		__attribute__((unused)) int *selected_digest,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("initialize received:");
	DEBUG_LOG("ack/nack response fields: ");
	LOG_STR_FIELD(req, hostname);
	LOG_STR_FIELD(req, addr);
	LOG_INT_FIELD(req, jaln_version);
	LOG_STR_FIELD(req, jaln_agent);
	LOG_INT_FIELD(req, mode);

	// If these fields are -1, then we are about to send a nack.
	// In that case, don't print anything for these as -1 is an invalid index.
	if (-1 != *selected_encoding) {
		LOG_ARR_FIELD(req, encodings, *selected_encoding, enc_cnt);
	}

	if (-1 != *selected_digest) {
		LOG_ARR_FIELD(req, digests, *selected_digest, dgst_cnt);
	}

	auto it = global_config.peers.find(std::string(req->hostname));
	if (global_config.peers.end() == it) {
		it = global_config.peers.find(std::string(req->addr));
	}
	if (global_config.peers.end() == it) {
		return JALN_CE_UNAUTHORIZED_MODE;
	}

	const PeerConfig& peer_cfg = it->second;

	if (req->role == JALN_ROLE_PUBLISHER) {
		// TODO: add support for jald to act as a subscriber.
		return JALN_CE_UNSUPPORTED_MODE;
	}
	enum jaln_record_type mask = (enum jaln_record_type)0;
	switch (req->role) {
	case JALN_ROLE_SUBSCRIBER:
		mask = peer_cfg.sub_allow;
		break;
	case JALN_ROLE_PUBLISHER:
		mask = peer_cfg.pub_allow;
		break;
	default:
		// Shouldn't happen.
		DEBUG_LOG("[%s] Invalid role in connection request?", req->ch_info->hostname);
	}
	if (mask & req->type) {
		return JALN_CE_ACCEPT;
	}
	return JALN_CE_UNAUTHORIZED_MODE;
}

void on_channel_close(
		const struct jaln_channel_info *ch_info,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Session is closing");

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(ch_info->type);
	std::shared_ptr<struct session_ctx_t> ctxPtr = nullptr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(ch_info->hostname);

		// Note that erasing the item from our maps doesn't actually destroy the session_ctx_t
		// until all shared_ptrs pointing to it go out of scope, so we can keep using ctxPtr
		sessionHostMap.erase(ctxPtr->hostname);
		sessionTokenMap.erase(ctxPtr->subscriber_token);
		// mapLock is per record type, not per session, so we don't remove that ever

		//Removes subscriber token for this connection from map, so that when this subscriber reconnects
		//a new subscriber token is generated.
		//NOTE: This will remove the token for all 3 record types when one record type disconnects.
		//Assumption is on_channel_close only occurs when the subscriber is closing, which will close all 3 channels.
		//The reference to the subscriber token still exists in sessionHostMap per channel until each channel is closed.
		removeSubscriberToken(ctxPtr->hostname);

		// (currently only used by the receive thread)
		// indicate that this session is closing
		ctxPtr->shutting_down = true;
		ctxPtr->channel_closed = true;
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
}

void on_connection_close(
		__attribute__((unused)) const struct jaln_connection *jal_conn,
		__attribute__((unused)) void *user_data)
{
	// don't need to to anything here.
}
void on_connect_ack(
		__attribute__((unused)) const struct jaln_connect_ack *ack,
		__attribute__((unused)) void *user_data)
{
	// Not applicable for our context since we only act as a listener, and
	// do not initiate any connections.
}

void on_connect_nack(
		__attribute__((unused)) const struct jaln_connect_nack *nack,
		__attribute__((unused)) void *user_data)
{
	// Not applicable for our context since we only act as a listener, and
	// do not initiate any connections.
}

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
	uint16_t nextSubcriberToken = getSubscriberToken(ch_info->hostname);
	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(JALN_RTYPE_JOURNAL);

	pthread_mutex_lock(mapLock.get());

	// A resume should create a new session context, ensure a session with this hostname does not
	// already exist
	if(0 != sessionHostMap.count(std::string(ch_info->hostname))) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Subscriber already exists");
		pthread_mutex_unlock(mapLock.get());
		return JAL_E_INVAL;
	}

	// The session does not already exist. Create it
	// This is a shared pointer to allow both maps to point at the same context safely and ensures
	// the context object can't be destroyed while in use, even if it is removed from the maps
	std::shared_ptr<struct session_ctx_t> ctxPtr = std::make_shared<struct session_ctx_t>(
		std::string(ch_info->hostname),
		nextSubcriberToken);

	// Insert this session by hostname and token to our maps
	sessionHostMap.insert({std::string(ch_info->hostname), ctxPtr});
	sessionTokenMap.insert({nextSubcriberToken, ctxPtr});
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
			return JAL_E_INVAL;
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

	//Sets journal resume to true
	ctxPtr->is_resume = true;
	return JAL_OK;
}

// If a resume is requested, pub_on_journal_resume is called prior to (and in addition to)
// pub_on_subscribe. In this case, pub_on_journal_resume creates the session context and inserts
// it to the hash map. pub_on_subscribe detects this by finding ctxPtr != NULL
enum jal_status pub_on_subscribe(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info_param,
		enum jaln_record_type type,
		enum jaln_publish_mode mode,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	// Under some exit conditions (for instance if the subscriber and publisher
	// both receive a ctrl-C very close to the same time) the jaln_network
	// closes down very quickly and rips the ch_info data out from under us.
	// Save a copy and use that, using a C++ destructor to guarantee the
	// copy is freed
	// Also use this object to ensure we increment and decrement our thread count
	// no matter how we leave this function
	struct ChInfo {
		struct jaln_channel_info ch_info = {NULL, NULL, NULL, NULL, JALN_RTYPE_JOURNAL};
		ChInfo(const struct jaln_channel_info* param) {
			if(param->hostname) ch_info.hostname = strdup(param->hostname);
			if(param->addr) ch_info.addr = strdup(param->addr);
			if(param->encoding) ch_info.encoding = strdup(param->encoding);
			if(param->digest_method) ch_info.digest_method = strdup(param->digest_method);
			ch_info.type = param->type;

			pthread_mutex_lock(&exit_count_lock);
			threads_to_exit += 1;
			pthread_mutex_unlock(&exit_count_lock);
		}
		~ChInfo() {
			free(ch_info.hostname);
			free(ch_info.addr);
			free(ch_info.encoding);
			free(ch_info.digest_method);
			pthread_mutex_lock(&exit_count_lock);
			threads_to_exit -= 1;
			pthread_mutex_unlock(&exit_count_lock);
		}
	} ch_info_container(ch_info_param);
	const struct jaln_channel_info* ch_info = &(ch_info_container.ch_info);
	uint16_t nextSubcriberToken = getSubscriberToken(ch_info->hostname);
	// Get the appropriate hash/lock and ensure this subscription doesn't already exist
	// This can happen if the subscriber is restarted very quickly before we finish
	// tearing down this thread
	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);

	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	pthread_mutex_lock(mapLock.get());

	// In the case of a journal resume, the session will already exist
	std::shared_ptr<struct session_ctx_t> ctxPtr;
	if (0 == sessionHostMap.count(std::string(ch_info->hostname))) {
		// The session does not already exist. Create it
		// This is a shared pointer to allow both maps to point at the same context safely and ensures
		// the context object can't be destroyed while in use, even if it is removed from the maps
		ctxPtr = std::make_shared<struct session_ctx_t>(
			std::string(ch_info->hostname),
			nextSubcriberToken);

		if (!global_args.use_filter){
			ctxPtr->db_ctx = setup_db_layer();
			if(NULL == ctxPtr->db_ctx) {
				pthread_mutex_unlock(mapLock.get());
				return JAL_E_INVAL;
			}
		}

		// Insert this session by hostname and token to our maps
		std::string type_str = stringify_type(ch_info->type);
		DEBUG_LOG_SUB_SESSION(ch_info, "Inserting session with hostname: %s, token: %d, type: %s\n", ch_info->hostname, nextSubcriberToken, type_str.c_str());
		sessionHostMap.insert({std::string(ch_info->hostname), ctxPtr});
		sessionTokenMap.insert({nextSubcriberToken, ctxPtr});
	}
	else {
		// We just did a .count() with this value, so we know .at will not throw
		ctxPtr = sessionHostMap.at(ch_info->hostname);
		// If this is a resume, it is valid (and expected) for the session to already exist
		// in our hash map
		if(!ctxPtr->is_resume) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: Subscription to host: %s already in use", ch_info->hostname);
			pthread_mutex_unlock(mapLock.get());
			return JAL_E_INVAL;
		}
	}


	// Once we have handled the resume once, we don't want to allow any additional sessions
	// of this type to this host, so mark is_resume false
	// Waiting to unlock the mapLock until we've set this final bit of state that will
	// prevent duplicate sessions from being created
	ctxPtr->is_resume = false;

	pthread_mutex_unlock(mapLock.get());

	struct thread_data data;
	data.sess = sess;
	data.ch_info = ch_info;
	data.timestamp = NULL;
	// Unused when not using the filter
	data.subscriber_token = nextSubcriberToken;

	if (JALN_LIVE_MODE == mode) {
		data.timestamp = jal_gen_timestamp_usec();
		if (!data.timestamp) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Error: Error generating timestamp");
			return JAL_E_INVAL_TIMESTAMP;
		}
	} else if (JALN_ARCHIVE_MODE != mode) {
		// Bad mode
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: Bad mode");
		return JAL_E_INVAL;
	}

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	pthread_t thread;
	int create_status = pthread_create(&thread, &attr, pub_send, &data);
	pthread_attr_destroy(&attr);

	if(0 != create_status) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
		return JAL_E_INVAL;
	}

	void* thread_status = NULL;

	// Wait for thread to terminate
	int join_status = pthread_join(thread, &thread_status);
	if (join_status) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: return code from pthread_join() is %d\n",
			join_status);
		free(thread_status);
		return JAL_E_INVAL;
	}

	// Once every second until either the session vanishes (shouldn't be possible)
	// or the channel_closed value is set, refresh our handle to the session ctx
	// and check again
	while(true) {

		// If the session handle has gone bad, fail out, there's nothing more we can do
		if(!ctxPtr || (!global_args.use_filter && !ctxPtr->db_ctx)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "No context or DB context associated with closing channel");
			return JAL_E_INVAL;
		}
		// If the session has closed by the remote host break out of the loop and move on
		// We will receive no more incoming messages
		else if(ctxPtr->channel_closed) {
			break;
		}
		// If we're closing from our side, wait for up to 5 seconds to collect any outstanding
		// record responses
		else if(exiting) {
			const int SLEEP_MAX = 5;
			for(int i = 0; i < SLEEP_MAX; i++) {
				if(ctxPtr->num_outstanding_syncs > 0) {
					DEBUG_LOG_SUB_SESSION(ch_info, "Waiting for channel to quiesce: %d.", i);
					sleep(1);
				} else {
					break;
				}
			}

			if(ctxPtr->num_outstanding_syncs > 0 ) {
				// After 5 seconds, break out even if we didn't get all the syncs we expected,
				// but display a warning
				DEBUG_LOG_SUB_SESSION(ch_info,
					"Didn't receive all expected syncs. Num oustanding: %d.",
					ctxPtr->num_outstanding_syncs);
			}
			break;
		}
		// Otherwise wait 1 second
		else {
			sleep(1);
		}
	}

	if(!global_args.use_filter) {
		jaldb_context_destroy(&ctxPtr->db_ctx);
	}

	enum jal_status ret = *((enum jal_status *) thread_status);
	free(thread_status);
	if (JAL_OK != ret && JAL_E_NOT_CONNECTED != ret) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed while sending records to subscriber");
	}

	return ret;
}

enum jal_status pub_on_record_complete(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		char *nonce,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "On record complete: %s", nonce);

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);

	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		pthread_mutex_unlock(mapLock.get());
		return JAL_E_INVAL;
	}

	if (ctxPtr->archive_mode && !global_args.use_filter) {

		pthread_mutex_lock(mapLock.get());
		enum jaldb_status jaldb_ret = jaldb_mark_sent(ctxPtr->db_ctx, ctxPtr->rec->type, nonce, 1);
		pthread_mutex_unlock(mapLock.get());

		if (JALDB_OK != jaldb_ret) {
			fprintf(stderr, "Failed to mark %s as sent: %d", nonce, jaldb_ret);
			return JAL_E_INVAL;
		} else {
			DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as sent", nonce);
		}
	}

	jaldb_destroy_record(&ctxPtr->rec);
	ctxPtr->num_outstanding_syncs++;
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

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);
	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		pthread_mutex_unlock(mapLock.get());
		return;
	}

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
		if (mode == JALN_ARCHIVE_MODE) {
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

	if(ctxPtr->num_outstanding_syncs > 0) {
		ctxPtr->num_outstanding_syncs--;
	} else {
		DEBUG_LOG_SUB_SESSION(ch_info, "Unexpected sync with ID: %s", nonce);
	}
}

void pub_notify_digest(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
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

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		pthread_mutex_lock(mapLock.get());
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
	return;
}
