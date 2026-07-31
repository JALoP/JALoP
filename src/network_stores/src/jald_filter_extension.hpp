/**
 * @file
 *
 * @brief This file contains the definitions for the extensions necessary for
 * with the in-line Rust filter process.
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
#pragma once


#include <string>
#include <memory>
#include <pthread.h>

#include <jalop/jaln_network_types.h>
#include "jald_common_definitions.hpp"
#include "jal_socket.hpp"

/** An enumeration for the types of control messages sent to
 * the in-line filter **/
enum class FilterMessageType: uint16_t {
	/** Indicates initialize of a new stream corresponding to a single
	 * record type for a single subscriber **/
	StartStream = 0x01,
	/** Indicates that an active stream must shut down **/
	StopStream = 0x02,
	/** Indicates that a record was succesfully transferred to the
	 * subscriber and acknowledged **/
	RecordSuccess = 0x04,
	/** Indicates that a record failed to transfer succesfully to the
	 * subscriber and should be retried **/
	RecordErrorRetry = 0x08,
	/** Indicates that a record failed to transfer succesfully to the
	 * subscriber and should not be retried **/
	RecordErrorNoRetry = 0x10,
};

/** A helper to bundle the arguments passed to the Socket Receive Thread
 * worker function. **/
struct ReceiveThreadArgs {
	// for error printing, connection selection, and sanity check of record type
	enum jaln_record_type record_type;
	// for creating the socket
	std::string socket_path;
};

/** Extends the UDSRecvMessage type. Defines the expected fields and lengths
 * expected when receiving from the UDSSocket, and extracts the data
 * received by the UDSSocket for program use.
 * This Message is used to receive records from the in-line filter for
 * transmission to the subscriber. **/
struct RecvRecordMessage : public UDSRecvMessage {
	/** Record Type - a uint16_t representing a enum jaln_record_type **/
	uint16_t recordType;
	/** A token given to the filter by jald to uniquely identify
	 * a particular stream **/
	uint16_t subscriberToken;
	/** length of the payload portion of the record **/
	uint64_t payloadLength;
	/** length of the application metadata portion of the record **/
	uint64_t appMetaLength;
	/** length of the system metadata portion of the record **/
	uint64_t sysMetaLength;
	/** if true, the payload portion of hte record will be transferred
	 * by file descriptor and not appear in the data. **/
	bool payloadOnDisk;
	/** The payload data (if not transmitted by FD) **/
	void* payloadData = NULL;
	/** The application metadata **/
	void* appMeta = NULL;
	/** The system metadata **/
	void* sysMeta = NULL;
	/** The jalID of the record being transferred **/
	std::string nonce;
	/** The stringified time at which this record was inserted to the local store. **/
	std::string timestamp;
	// Note - fd is handled by the base class
	// Do not specify fd here

	/** The following tokens are established when constructing the format
	 * of the message to receive, and are used to extract particular received fields **/
	int messageTypeId;
	int subscriberTokenId;
	int payloadLengthId;
	int appMetaLengthId;
	int sysMetaLengthId;
	int nonceLengthId;
	int timestampLengthId;
	int payloadOnDiskId;
	int payloadId;
	int break1Id;
	int appMetaId;
	int break2Id;
	int sysMetaId;
	int break3Id;
	int nonceId;
	int break4Id;
	int timestampId;
	int break5Id;

	RecvRecordMessage();
	~RecvRecordMessage();

	int process();
};

/** The arguments required to construct a StartStream message **/
struct StartStreamArgs {
	/** Establishes the unique id for a new stream **/
	uint16_t subscriberToken;
	/** The record type of the new stream **/
	enum jaldb_rec_type type;
	/** The mode of the new stream (archive/live) **/
	enum jaln_publish_mode mode;
	/** If the subscriber requested a journal resume,
	 * the none of that resume. **/
	char* resumeNonce = NULL;
};

/** Extends the UDSSendMessage type. Creates a message to be sent
 * over a UDSSendSocket. Creates a new record data stream **/
struct JalFilterStartStream : public UDSSendMessage {
	JalFilterStartStream(const StartStreamArgs& args);
};

/** The arguments required to construct a StopStream message **/
struct StopStreamArgs {
	/** The unique id of the stream to stop **/
	uint16_t subscriberToken;
	/** The record type of the stream to stop **/
	enum jaldb_rec_type type;
};

/** Extends the UDSSendMessage type. Creates a message to be sent
 * over a UDSSendSocket. Stops an active record data stream **/
struct JalFilterStopStream : public UDSSendMessage {
	JalFilterStopStream(const StopStreamArgs& args);
};

/** The arguments required to construct a Record Response message **/
struct RecordResponseArgs {
	/** The status of the response (success or failre) **/
	FilterMessageType mType;
	/** The unique id of the stream to stop **/
	uint16_t subscriberToken;
	/** The record type of the record in question **/
	enum jaldb_rec_type type;
	/** The nonce of the record in question **/
	const char *recordNonce = NULL;
};

/** Extends the UDSSendMessage type. Creates a message to be sent
 * over a UDSSendSocket. Signals success/failure for an in-progress record **/
struct JalFilterRecordResponse : public UDSSendMessage {
	JalFilterRecordResponse(const RecordResponseArgs& args);
};

/** This function intended to be used as a long-running thread with lifetime
 * approximately equal to that of jald. It constructs a socket listener and waits for
 * the filter to connect before proceeding into a loop which captures incoming records
 * and dispatches them to the appropriate session_ctx_t based on the embedded
 * subscriber token.
 *
 * @param[in] paramArgs A void* to a ReceiveThreadArgs struct
 */
void *record_receive_thread(void *paramArgs);
