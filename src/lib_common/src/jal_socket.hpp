/**
 * @file
 *
 * @brief This file contains functions to handle an audit
 * to the jal local store.
 *
 * ### LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#pragma once

#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <queue>

enum msgType {
	LOG_MSG = 1,
	AUDIT_MSG = 2,
	JOURNAL_MSG = 3,
	JOURNAL_FD_MSG = 4,
	UPDATE_MSG = 6,
};

enum updateType {
	UNSYNCED_RECORDS_UNSENT = 1,
	SENT = 2,
	SYNCED = 3,
};

enum recType {
	RTYPE_JOURNAL = 1 << 0, //!< Indicates a Journal Record */
	RTYPE_AUDIT = 1 << 1, //!< Indicates an Audit Record */
	RTYPE_LOG = 1 << 2, //!< Indicates a Log Record */
	RTYPE_UNKNOWN = 1 << 3, //!< Indicates the record type is unknown/unset */
};

struct Field {
	Field();
	Field(const Field&) = delete;
	Field& operator=(const Field&) = delete;
	Field(Field&& s);
	Field& operator=(Field&& s);
	~Field();

	void* owned_data = NULL;
	const void* unowned_data = NULL;
	size_t length = 0;


	const void* data() const;
	uint64_t extractDataAsLength();
	uint16_t extractDataAsOption();
	void* steal();
};

struct UDSSendMessage {
	std::vector<Field> fields;
	int fd = -1;

	int addFieldByCopy(const void* const data, const size_t length);
	int addFieldByOwningPointer(void** data, const size_t length);
	int addFieldByNonOwningPointer(const void* const data, const size_t length);
	void addFd(int fd);
};

enum class UDSRecvStatus {
	Success,
	Timeout,
	LogicError,
	LowLevelFailure,
	SocketShutdown,
	LengthMismatch,
	BadFdReceived,
	BadCmsgHeaderReceived,
};

struct UDSRecvRV {
	UDSRecvStatus status;
	int lowLevelError = 0;
};

struct UDSRecvMessage{
	std::vector<Field> fields;
	// Some fields will reference earlier fields to define their
	// expected length. This vector will contain -1 to signify no dependency
	// or the index of the field on which it depends
	std::vector<int> fieldDependencies;
	// Some fields will reference earlier fields to define whether or not they are
	// present in this data. This vector will contain -1 to signify no dependency
	// or the index of the field on which it depends
	std::vector<int> fieldOptionalDependencies;
	// Some fields will reference earlier fields to define whether or not they are
	// present in this data. This vector will contain -1 to signify no dependency
	// or the value which the field specified by fieldOptionalDependencies must
	// be equivalent to in order for this field to exist
	std::vector<uint16_t> fieldOptionalCompareValues;
	// The fd specified in the cmsg header, or -1
	int fd = -1;

	int addField(const size_t length);
	int addDependentField(const size_t dependentIndex);
	// TOOD: right now the field which indicates whether or not the optional
	// field is present must be a uint16_t. Supplying a lambda might make more sense
	// if we need to expand this capability
	int addOptionalField(
		const size_t optionIndex,
		const uint16_t exists_value,
		const size_t length);
	// TOOD: right now the comparison value must be a uin16_t
	int addOptionalDependentField(
		const size_t optionIndex,
		const uint16_t exists_value,
		const size_t dependentIndex);
	// This reference must not be used beyond the lifetime of the UDSRecieveMessage
	// class or its derived classes
	// TODO: Replace with weak_ptr for safety
	const std::vector<Field>& getFields();

	std::string getString(const int fieldId, const size_t length);
	void* stealBuffer(const int fieldId, size_t length);

	template<class T>
	T getField(const int fieldId) {
		// may throw out_of_range error
		const Field& f = fields.at(fieldId);
		if(f.length != sizeof(T)) {
			std::string msg = std::string("Requested field has length: ")
				+ std::to_string(f.length)
				+ std::string(" expected: ")
				+ std::string(std::to_string(sizeof(T)));
			throw std::runtime_error(msg);
		}
		return *((T*)f.data());
	}
};

struct UDSSendSocket {
	UDSSendSocket();
	UDSSendSocket(const UDSSendSocket&) = delete;
	UDSSendSocket& operator=(const UDSSendSocket&) = delete;
	UDSSendSocket(UDSSendSocket&& s);
	UDSSendSocket& operator=(UDSSendSocket&& s);
	~UDSSendSocket();
	int fd = -1;
	struct ucred cred;
	bool connected = false;
	
	//Sending methods
	int connectSocket(std::string path);
	int sendMsg(UDSSendMessage message);
};

// The current implementation is a one-to-one communication channel
// Only one clientFd is supported
struct UDSRecvSocket {
	// fd of the listening socket
	int sockFd; 
	// TODO - see if we can get rid of this and just dump any connections/data on the socket
	// when we begin
	int JALLS_LISTEN_BACKLOG = 20;
	// connected client info
	int clientFd;
	struct sockaddr_un peer_addr;
	unsigned int peer_addr_size = sizeof(peer_addr);
	struct ucred cred;

	UDSRecvSocket(std::string path);
	UDSRecvSocket(const UDSRecvSocket&) = delete;
	UDSRecvSocket& operator=(const UDSRecvSocket&) = delete;
	UDSRecvSocket(UDSRecvSocket&& s);
	UDSRecvSocket& operator=(UDSRecvSocket&& s);
	~UDSRecvSocket();

	int pollSocket();
	UDSRecvRV recvMsg(UDSRecvMessage& message);
	private:
	UDSRecvRV recvInternal(
		UDSRecvMessage& message,
		const size_t lower_bound,
		const size_t upper_bound);
};
