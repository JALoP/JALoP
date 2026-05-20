/**
 * @file
 *
 * @brief This file contains the extensions necessary for jald to interact
 * jald to interact with the in-line Rust filter process.
 *
 * ### LICENSE
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
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
#include "jald_filter_extension.hpp"
#include "jal_socket.hpp"

// lifetime globals from jald.cpp
extern int threads_to_exit;
extern pthread_mutex_t exit_count_lock;
extern int exiting;
extern pthread_mutex_t request_socket_lock;
extern UDSSendSocket requestSocket;

// short hand for long map type names
using SessionHostMap = std::map<std::string, std::shared_ptr<session_ctx_t>>;
using SessionTokenMap = std::map<uint16_t, std::shared_ptr<session_ctx_t>>;

// These maps are lifetime globals in jald.cpp
extern std::map<enum jaln_record_type, SessionHostMap> sessionHostMaps;
extern std::map<enum jaln_record_type, std::shared_ptr<pthread_mutex_t>> mapLocks;
extern std::map<enum jaln_record_type, SessionTokenMap> sessionTokenMaps;

RecvRecordMessage::RecvRecordMessage() {
	// Capture the "id" of each field as it is added so we know how to refer to them later
	messageTypeId = addField(sizeof(uint16_t));
	subscriberTokenId = addField(sizeof(uint16_t));
	payloadLengthId = addField(sizeof(uint64_t));
	appMetaLengthId = addField(sizeof(uint64_t));
	sysMetaLengthId = addField(sizeof(uint16_t));
	nonceLengthId = addField(sizeof(uint16_t));
	timestampLengthId = addField(sizeof(uint16_t));
	payloadOnDiskId = addField(sizeof(uint16_t));
	payloadId = addOptionalDependentField(payloadOnDiskId, 0, payloadLengthId);
	// NOTE - we do not send the NULL terminator with the BREAK strings
	// subtract one from the expected size
	break1Id = addOptionalField(payloadOnDiskId, 0, sizeof("BREAK")-1);
	appMetaId = addDependentField(appMetaLengthId);
	break2Id = addField(sizeof("BREAK")-1);
	sysMetaId = addDependentField(sysMetaLengthId);
	break3Id = addField(sizeof("BREAK")-1);
	nonceId = addDependentField(nonceLengthId);
	break4Id = addField(sizeof("BREAK")-1);
	timestampId = addDependentField(timestampLengthId);
	break5Id = addField(sizeof("BREAK")-1);
}

RecvRecordMessage::~RecvRecordMessage() {
	// If, at the time of destruction, the data owned by raw pointers has not been
	// stolen, free it
	free(payloadData);
	free(appMeta);
	free(sysMeta);
}

int RecvRecordMessage::process() {
	try {
		// Sanity check on the break fields first to help guard against data alignment errors
		//
		// The first BREAK is only present if payloadOnDisk is false so we'll parse that field
		// out early
		uint16_t onDisk = getField<uint16_t>(payloadOnDiskId);
		payloadOnDisk = (0 != onDisk ? true : false);

		if(!payloadOnDisk) {
			if(std::string("BREAK") != getString(break1Id, strlen("BREAK"))) {
				fprintf(stderr, "First BREAK segment does not contain BREAK\n");
				return -1;
			}
		}
		if(std::string("BREAK") != getString(break2Id, strlen("BREAK"))) {
			fprintf(stderr, "Second BREAK segment does not contain BREAK\n");
			return -1;
		}
		if(std::string("BREAK") != getString(break3Id, strlen("BREAK"))) {
			fprintf(stderr, "Third BREAK segment does not contain BREAK\n");
			return -1;
		}
		if(std::string("BREAK") != getString(break4Id, strlen("BREAK"))) {
			fprintf(stderr, "Fourth BREAK segment does not contain BREAK\n");
			return -1;
		}
		if(std::string("BREAK") != getString(break5Id, strlen("BREAK"))) {
			fprintf(stderr, "First BREAK segment does not contain BREAK\n");
			return -1;
		}

		// Extract the data from our fields into a more useable form
		// These functions provide length checks which will throw if there is an unexpected
		// length
		recordType = getField<uint16_t>(messageTypeId);
		subscriberToken = getField<uint16_t>(subscriberTokenId);
		payloadLength = getField<uint64_t>(payloadLengthId);
		appMetaLength = getField<uint64_t>(appMetaLengthId);
		sysMetaLength = getField<uint16_t>(sysMetaLengthId);
		uint16_t nonceLength = getField<uint16_t>(nonceLengthId);
		uint16_t timestampLength = getField<uint16_t>(timestampLengthId);
		if(!payloadOnDisk) {
			payloadData = stealBuffer(payloadId, payloadLength);
		} else {
			// fd is captured by the base class, we should just be able to use it
			if(0 > fd) {
				fprintf(stderr, "onDisk is true, but no fd was received from the filter\n");
				return -1;
			}
		}
		appMeta = stealBuffer(appMetaId, appMetaLength);
		sysMeta = stealBuffer(sysMetaId, sysMetaLength);
		nonce = getString(nonceId, nonceLength);
		timestamp = getString(timestampId, timestampLength);
	} catch (const std::exception &e) {
		fprintf(stderr, "ERROR: Encountered exception parsing record data: %s\n", e.what());
		return -1;
	}
	return 0;
}


JalFilterStartStream::JalFilterStartStream(const StartStreamArgs& args) {
	// MessageType
	FilterMessageType mType = FilterMessageType::StartStream;
	addFieldByCopy(&mType, sizeof(FilterMessageType));
	// Subscriber Id
	addFieldByCopy(&args.subscriberToken, sizeof(uint16_t));
	// Record Type
	addFieldByCopy(&args.type, sizeof(uint16_t));
	// Mode
	addFieldByCopy(&args.mode, sizeof(uint16_t));
	// journal resume request nonce
	if(args.resumeNonce) {
		uint16_t nonceLen = strlen(args.resumeNonce);
		addFieldByCopy(&nonceLen, sizeof(uint16_t));
		addFieldByNonOwningPointer(args.resumeNonce, nonceLen);
	} else {
		uint16_t nonceLen = 0;
		addFieldByCopy(&nonceLen, sizeof(uint16_t));
	}
}

JalFilterStopStream::JalFilterStopStream(const StopStreamArgs& args) {
	// MessageType
	FilterMessageType mType = FilterMessageType::StopStream;
	addFieldByCopy(&mType, sizeof(FilterMessageType));
	// Subscriber Id
	addFieldByCopy(&args.subscriberToken, sizeof(uint16_t));
	// Record Type
	addFieldByCopy(&args.type, sizeof(uint16_t));
}

JalFilterRecordResponse::JalFilterRecordResponse(const RecordResponseArgs& args) {
	// MessageType
	FilterMessageType mType = args.mType;
	addFieldByCopy(&mType, sizeof(FilterMessageType));
	// Subscriber Id
	addFieldByCopy(&args.subscriberToken, sizeof(uint16_t));
	// Record Type
	addFieldByCopy(&args.type, sizeof(uint16_t));
	// record Nonce
	if(args.recordNonce && (strlen(args.recordNonce) > 0)) {
		uint16_t nonceLen = strlen(args.recordNonce);
		addFieldByCopy(&nonceLen, sizeof(uint16_t));
		addFieldByNonOwningPointer(args.recordNonce, nonceLen);
	} else {
		uint16_t nonceLen = 0;
		addFieldByCopy(&nonceLen, sizeof(uint16_t));
	}
}

void *record_receive_thread(void *paramArgs) {
	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit += 1;
	pthread_mutex_unlock(&exit_count_lock);

	// Ensure we decrement the active threads counter and signal for the program to shut down
	// regardless of how we exit this thread. This thread needs to live as long as jald
	struct SelfDestruct {
		~SelfDestruct(){
			pthread_mutex_lock(&exit_count_lock);
			threads_to_exit -= 1;
			exiting = 1;
			pthread_mutex_unlock(&exit_count_lock);
		}
	} sd;

	// We need args to live
	if(NULL == paramArgs) {
		fprintf(stderr,  "FATAL: Failed to create record receive thread.");
		return NULL;
	}
	ReceiveThreadArgs* args = (ReceiveThreadArgs*)paramArgs;

	// Get the session map and mutex lock for the type of channel we care about
	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(args->record_type);

	//sessionHostMap is not used in this method.
	(void)sessionHostMap;

	UDSRecvSocket recvSock(args->socket_path);
	// Wait until the filter connects
	int poll_status = -1;
	while(!exiting && -1 == poll_status) {
		fprintf(stderr, "Waiting for connection on socket: %s\n", args->socket_path.c_str());
		poll_status = recvSock.pollSocket();
		if(-1 == poll_status) {
			sleep(1);
		}
	}

	if(-1 != poll_status) {
		fprintf(stderr, "Connection accepted on socket: %s\n", args->socket_path.c_str());
	}

	while(!exiting) {
		RecvRecordMessage recordMessage;
		UDSRecvRV rv = recvSock.recvMsg(recordMessage);
		switch(rv.status) {
			case UDSRecvStatus::Success:
				try {
					recordMessage.process();
				} catch (std::exception &e) {
					fprintf(stderr, "Failed to process data received from socket. Shutting down.\n");
					exiting = 1;
					continue;
				}
				break;
			case UDSRecvStatus::Timeout:
				// No data received for 1 second, coming up for air. Continue
				continue;
			case UDSRecvStatus::LowLevelFailure:
				fprintf(stderr, "revcmsg returned error code: %d. Shutting down.\n",
					rv.lowLevelError);
				exiting = 1;
				continue;
			case UDSRecvStatus::SocketShutdown:
				fprintf(stderr, "Filter closed socket. Shutting down.\n");
				exiting = 1;
				continue;
			case UDSRecvStatus::LogicError:
				fprintf(stderr, "Logic Error receiving. Shutting down\n");
				exiting = 1;
				continue;
			case UDSRecvStatus::LengthMismatch:
				fprintf(stderr, "Other error receiving. Shutting down\n");
				exiting = 1;
				continue;
			default:
				fprintf(stderr, "Invalid status from receive call. Shutting down\n");
				exiting = 1;
				continue;
		}

		// Get the session corresponding to this type and the subscriber token from the filter
		std::shared_ptr<struct session_ctx_t> ctxPtr;
		try {
			pthread_mutex_lock(mapLock.get());
			ctxPtr = sessionTokenMap.at(recordMessage.subscriberToken);
			pthread_mutex_unlock(mapLock.get());
		} catch (std::out_of_range& e) {
			pthread_mutex_unlock(mapLock.get());
			// This subscriber token corresponds to a hostname for which we have no active session
			// Warn, but continue
			fprintf(stderr, "WARNING: Received a record for unregistered subscriber token: %d\n.",
				recordMessage.subscriberToken);
			// Generate a record failure for the nonce so the filter doesn't wait for a response for
			// that record
			RecordResponseArgs responseArgs;
			responseArgs.mType = FilterMessageType::RecordError;
			responseArgs.subscriberToken = recordMessage.subscriberToken;
			responseArgs.type = (enum jaldb_rec_type)recordMessage.recordType;
			responseArgs.recordNonce = recordMessage.nonce.data();

			// Create and send the message
			pthread_mutex_lock(&request_socket_lock);
			requestSocket.sendMsg(JalFilterRecordResponse(responseArgs));
			pthread_mutex_unlock(&request_socket_lock);
			continue;
		}
		pthread_mutex_unlock(mapLock.get());

		// Wait for the session's "next" record to not be in use
		// We're keeping a handle to the ctx, which is slightly dangerous. Ensure that ~session_ctx_t()
		// waits for this thread to finish before releasing control
		pthread_mutex_lock(&(ctxPtr->staging_data_lock));

		// It is expected that this loop will only fire once.
		// If staged_data_occupied is false, there's room for us to place a record.
		// We already have the mutex, so immediately proceed.
		// If ctx->shutting_down is true, this session is being removed, cease operations
		// If staged_data_occupied is true, we drop into pthread_cond_wait until we
		// are signalled either by the consumer when it finishes with th record, or by
		// an invocation of shutdown()
		while(ctxPtr->staged_data_occupied && !ctxPtr->shutting_down) {
			pthread_cond_wait(&(ctxPtr->socket_thread_signal), &(ctxPtr->staging_data_lock));
		}

		// pthread_cond_wait acquires the mutex when it is signalled so we now own the lock
		// Be sure to release it before exiting or hitting the end of the loop

		if(ctxPtr->shutting_down) {
			// We don't have any state to worry about yet, the RecordMessage can clean itself up
			// Just release the lock and go back to the top of the loop
			pthread_mutex_unlock(&(ctxPtr->staging_data_lock));
			continue;
		}

		// It is the responsibility of the consumer to properly steal the memory from
		// the session_ctx_t before signalling stated_data_occuped = false
		// We'll defensively zero out our fields here, but these should always be no-ops
		free(ctxPtr->sys_meta_buf);
		ctxPtr->sys_meta_buf = NULL;
		ctxPtr->sys_meta_len = 0;

		free(ctxPtr->app_meta_buf);
		ctxPtr->app_meta_buf = NULL;
		ctxPtr->app_meta_len = 0;

		free(ctxPtr->payload_buf);
		ctxPtr->payload_buf = NULL;
		ctxPtr->payload_len = 0;

		free(ctxPtr->nonce);
		ctxPtr->nonce = NULL;

		free(ctxPtr->timestamp);
		ctxPtr->timestamp = NULL;

		ctxPtr->fd = -1;
		ctxPtr->on_disk = false;

		// Steal ownership of the system metadata buffer in recordMessage
		// and hand it to the session_ctx_t
		if(0 < recordMessage.sysMetaLength) {
			ctxPtr->sys_meta_buf = (uint8_t*)recordMessage.sysMeta;
			recordMessage.sysMeta = NULL;

			ctxPtr->sys_meta_len = recordMessage.sysMetaLength;
			recordMessage.sysMetaLength = 0;
		}

		// Steal ownership of the application metadata buffer in recordMessage
		// and hand it to the session_ctx_t
		if(0 < recordMessage.appMetaLength) {
			ctxPtr->app_meta_buf = (uint8_t*)recordMessage.appMeta;
			recordMessage.appMeta = NULL;

			ctxPtr->app_meta_len = recordMessage.appMetaLength;
			recordMessage.appMetaLength = 0;
		}

		// Steal ownership of the payload  buffer in recordMessage
		// and hand it to the session_ctx_t
		if(0 < recordMessage.payloadLength) {
			ctxPtr->payload_buf = (uint8_t*)recordMessage.payloadData;
			recordMessage.payloadData = NULL;

			ctxPtr->payload_len = recordMessage.payloadLength;
			recordMessage.payloadLength = 0;
		}

		if(recordMessage.payloadOnDisk) {
			ctxPtr->fd = recordMessage.fd;
		}

		if(!recordMessage.nonce.empty()) {
			ctxPtr->nonce = strdup(recordMessage.nonce.c_str());
			recordMessage.nonce = std::string();
		}

		if(!recordMessage.timestamp.empty()) {
			ctxPtr->timestamp = strdup(recordMessage.timestamp.c_str());
			recordMessage.timestamp = std::string();
		}

		if(recordMessage.payloadOnDisk) {
			ctxPtr->on_disk = true;
		}

		// Indicate that a record has been placed and is ready for use.
		ctxPtr->staged_data_occupied = true;
		// Release the mutex lock
		pthread_mutex_unlock(&(ctxPtr->staging_data_lock));
		// Wake the get_next_record_on_socket thread, if it happens to be waiting on data
		pthread_cond_signal(&(ctxPtr->get_next_signal));
	}
	fprintf(stderr, "Exiting thread with path: %s\n", args->socket_path.c_str());
	delete args;
	pthread_exit(NULL);
}
