/**
 * @file
 *
 * @brief This file contains functions to handle socket connections.
 *
 * ### LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
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

#include <iostream>
#include <unistd.h>
#include <queue>
#include <poll.h>
#include <memory>
#include <stdint.h>
#include "jal_socket.hpp"

Field::Field() {
	// Use default values in header
}

Field::Field(Field&& s) {
	this->owned_data = s.owned_data;
	s.owned_data = NULL;
	this->unowned_data = s.unowned_data;
	s.unowned_data = NULL;
	this->length = s.length;
	s.length = 0;
}

Field& Field::operator=(Field&& s) {
	this->owned_data = s.owned_data;
	s.owned_data = NULL;
	this->unowned_data = s.unowned_data;
	s.unowned_data = NULL;
	this->length = s.length;
	s.length = 0;
	return (*this);
}

const void* Field::data() const {
	if(NULL != owned_data) {
		return (const void*)owned_data;
	} else if(NULL != unowned_data) {
		return  unowned_data;
	} else {
		// This shouldn't happen
		return NULL;
	}
}

Field::~Field() {
	free(owned_data);
}

uint64_t Field::extractDataAsLength() {
	// We will support length fields of only size uint8_t, uint16_t, uint32_t and uint64_t
	// for the sake of my sanity
	// And whatever it is, we'll stuff it in a uint64_t for ease of use
	uint64_t len = 0;
	switch(this->length) {
		case 1: 
		{
			uint8_t local_length = *((uint8_t*)this->data());
			// casting from small to large is safe and implicit
			len = local_length;
			break;
		}
		case 2:
		{
			uint16_t local_length = *((uint16_t*)this->data());
			len = local_length;
			break;
		}
		case 4:
		{
			uint32_t local_length = *((uint32_t*)this->data());
			len = local_length;
			break;
		}
		case 8:
		{
			uint64_t local_length = *((uint64_t*)this->data());
			len = local_length;
			break;
		}
		default:
			return UINT64_MAX;
	}
	return len;
}

uint16_t Field::extractDataAsOption() {
	// Currently on option fields of length uint16_t are supported
	if(this->length != sizeof(uint16_t)) {
		return UINT16_MAX;
	} else {
		return *((uint16_t*)this->data());
	}
}

void* Field::steal() {
	// It is sometimes legal for a field to have empty data
	// Return NULL in this case
	if(NULL == owned_data && NULL == unowned_data && 0 == length) {
		return NULL;
	}

	// It doesn't make sense to steal from a field which doesn't own its data
	// Prevent this mistake
	if(NULL == owned_data && NULL != unowned_data) {
		std::string msg = "Error: Attempting to steal unowned data from Field";
		throw std::runtime_error(msg);
	}

	// The caller is taking ownership of this buffer
	// We must not free it later
	void* buf = owned_data;
	owned_data = NULL;
	length = 0;
	return buf;
}

int UDSSendMessage::addFieldByCopy(const void* const data, const size_t length) {
	if(NULL == data || 0 >= length) {
		return -1;
	}
// A copied field is owned by the Message
	Field f;
	f.owned_data = (void*)malloc(length);
	f.length = length;
	memcpy(f.owned_data, data, length);  // nosemgrep - the copy length is less than or equal to the destination buffer size
	fields.emplace_back(std::move(f));
	return 0;
}

int UDSSendMessage::addFieldByOwningPointer(void** data, const size_t length) {
	if(NULL == data || 0 >= length) {
		return -1;
	}
	Field f;
	f.owned_data = *data;
	*data = NULL;
	f.length = length;
	fields.emplace_back(std::move(f));
	return 0;
}

int UDSSendMessage::addFieldByNonOwningPointer(const void* const data, const size_t length) {
	if(NULL == data || 0 >= length) {
		return -1;
	}
	Field f;
	f.unowned_data = data;
	f.length = length;
	fields.emplace_back(std::move(f));
	return 0;
}

void UDSSendMessage::addFd(const int paramFd) {
	fd = paramFd;
}

int UDSRecvMessage::addField(const size_t length) {
	Field f;
	f.length = length;
	fields.emplace_back(std::move(f));
	fieldDependencies.push_back(-1);
	fieldOptionalDependencies.push_back(-1);
	fieldOptionalCompareValues.push_back(UINT16_MAX);
	return fields.size() - 1;
}

int UDSRecvMessage::addDependentField(size_t dependentIndex) {
	if(fields.size() < (dependentIndex -1)) {
		fprintf(stderr, "ERROR: dependentIndex : [%zu] must refer to a field that appears \
			before the field being added\n", dependentIndex);
		return -1;
	}
	int index = (int)dependentIndex;
	Field f;
	fields.emplace_back(std::move(f));
	fieldDependencies.push_back(index);
	fieldOptionalDependencies.push_back(-1);
	fieldOptionalCompareValues.push_back(UINT16_MAX);
	return fields.size() - 1;
}

int UDSRecvMessage::addOptionalField(const size_t optionIndex, uint16_t exists_value, const size_t length) {
	if(fields.size() < (optionIndex -1)) {
		fprintf(stderr, "ERROR: optionIndex : [%zu] must refer to a field that appears \
			before the field being added\n", optionIndex);
		return -1;
	}
	if(UINT16_MAX == exists_value) {
		fprintf(stderr, "ERROR: exists_value must be less than UINT16_MAX\n");
		return -1;
	}

	Field f;
	f.length = length;
	fields.emplace_back(std::move(f));
	fieldDependencies.push_back(-1);
	fieldOptionalDependencies.push_back(optionIndex);
	fieldOptionalCompareValues.push_back(exists_value);
	return fields.size() - 1;
}

int UDSRecvMessage::addOptionalDependentField(
	const size_t optionIndex,
	uint16_t exists_value,
	const size_t dependentIndex) {
	if(fields.size() < (dependentIndex -1)) {
		fprintf(stderr, "ERROR: dependentIndex : [%zu] must refer to a field that appears \
			before the field being added\n", dependentIndex);
		return -1;
	}

	if(fields.size() < (optionIndex -1)) {
		fprintf(stderr, "ERROR: optionIndex : [%zu] must refer to a field that appears \
			before the field being added\n", optionIndex);
		return -1;
	}

	if(UINT16_MAX == exists_value) {
		fprintf(stderr, "ERROR: exists_value must be less than UINT16_MAX\n");
		return -1;
	}

	Field f;
	fields.emplace_back(std::move(f));
	int index = (int)dependentIndex;
	fieldDependencies.push_back(index);
	index = (int)optionIndex;
	fieldOptionalDependencies.push_back(index);
	fieldOptionalCompareValues.push_back(exists_value);
	return fields.size() - 1;
}

std::string UDSRecvMessage::getString(const int fieldId, const size_t length) {
	// may throw out_of_range error
	const Field& f = fields.at(fieldId);
	if(f.length != length) {
		std::string msg = std::string("Requested field has length: ")
			+ std::to_string(f.length)
			+ std::string(" expected: ")
			+ std::to_string(length);
		throw std::runtime_error(msg);
	}
	if(0 == length) {
		return std::string();
	}
	return std::string( (char*)f.data(), length );
}

void* UDSRecvMessage::stealBuffer(const int fieldId, size_t length) {
	// may throw out_of_range error
	Field& f = fields.at(fieldId);
	if(f.length != length) {
		std::string msg = std::string("Requested field has length: ")
			+ std::to_string(f.length)
			+ std::string(" expected: ")
			+ std::to_string(length);
		throw std::runtime_error(msg);
	}
	if(0 == length) {
		return NULL;
	}
	return f.steal();
}


int UDSSendSocket::connectSocket(std::string path) {
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if(-1 == sock) {
		return -1;
	}

	struct sockaddr_un sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sun_family = AF_UNIX;
	strncpy(sock_addr.sun_path, path.c_str(), sizeof(sock_addr.sun_path) - 1);  // nosemgrep - cannot convert to snprintf as the null terminator must be stripped

	if(0 != connect(sock, (struct sockaddr*) &sock_addr, sizeof(sock_addr))) {
		return -1;
	}
	else{
		connected = 1;
		fd = sock;
		return 0;
	}
}

int UDSSendSocket::sendMsg(UDSSendMessage message) {

	// Create array of iovec structs containing all fields
	std::unique_ptr<struct iovec[]> iovs = std::make_unique<struct iovec[]>(message.fields.size());

	// point the iovec structs at the fields owned by the class. These are non-owning pointers
	size_t i = 0;
	for(const auto& f : message.fields) {
		// for some reason iov_base wasn't to be a void*, not a const void* as would
		// be more appropriate.
		iovs[i].iov_base = const_cast<void*>(f.data());
		iovs[i].iov_len = f.length;
		i++;
	}
	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_iov = iovs.get();
	msgh.msg_iovlen = i;

	// If there is an fd associated with this message, include it
	char cmsg_buffer[CMSG_SPACE(sizeof(message.fd))];
	if(-1 != message.fd) {
		// this code is from man 3 cmsg
		struct cmsghdr *cmsg;
		int *fdptr;

		msgh.msg_control = cmsg_buffer;
		msgh.msg_controllen = sizeof(cmsg_buffer);

		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(message.fd));
		fdptr = (int *) CMSG_DATA(cmsg);
		memcpy(fdptr, &(message.fd), sizeof(message.fd)); // nosemgrep - the copy length is less than or equal to the destination buffer size
		msgh.msg_controllen = cmsg->cmsg_len;
	}

	// Send our msgh structure
	ssize_t bytes_sent = 0;
	ssize_t total_bytes_sent = 0;
	i = 0;
	while (i < (size_t)msgh.msg_iovlen) {
		// Stop when i exceeds the number of iovs
		if (bytes_sent >= (ssize_t)msgh.msg_iov[i].iov_len) {
			// If we have sent at least enough bytes to fully consume the first iov
			
			// Take the number of bytes in the ith iov and subtract them from the recorded
			// amount of bytes sent
			bytes_sent -= msgh.msg_iov[i].iov_len;
			// point the current iov at nothing so subsequent calls to sendmsg serialize it as
			// nothing
			msgh.msg_iov[i].iov_len = 0;
			msgh.msg_iov[i].iov_base = NULL;
			// index to the next iov
			i++;
			// This will immediately take us to the top of the loop without sending
		}
		else {
			// We land here either the first time through (i == 0) or when we have sent some
			// bytes but not enough to completely consume the ith iov
			ssize_t bytes_remaining = msgh.msg_iov[i].iov_len - bytes_sent;
			// shift the pointer to our current iov over by bytes_sent
			msgh.msg_iov[i].iov_base = ((uint8_t*)msgh.msg_iov[i].iov_base) + bytes_sent;
			// set the remaining length of the current iov to the number of bytes remaining to
			// be sent
			msgh.msg_iov[i].iov_len = bytes_remaining;

			// Do the send using the updated iov struct
			bytes_sent = sendmsg(this->fd, &msgh, 0);
			total_bytes_sent += bytes_sent;

			while (-1 == bytes_sent) {
				int myerrno;
				myerrno = errno;
				if (EINTR == myerrno) {
					bytes_sent = sendmsg(this->fd, &msgh, 0);
					total_bytes_sent += bytes_sent;
				}
				else {
					return -1;
				}
			}

			msgh.msg_control = NULL;
			msgh.msg_controllen = 0;
		}
	}
	return total_bytes_sent;
}

UDSSendSocket::UDSSendSocket() {
	// Use defaults in header
}

UDSSendSocket::UDSSendSocket(UDSSendSocket&& s) {
	this->fd = s.fd;
	s.fd = -1;
	this->cred = s.cred;
	this->connected = s.connected;
	s.connected = false;
}

UDSSendSocket& UDSSendSocket::operator=(UDSSendSocket&& s) {
	this->fd = s.fd;
	s.fd = -1;
	this->cred = s.cred;
	this->connected = s.connected;
	s.connected = false;
	return (*this);
}

UDSSendSocket::~UDSSendSocket() {
	if(-1 != fd) {
		close(fd);
	}
}

UDSRecvSocket::UDSRecvSocket(std::string path) {
	sockFd = socket(AF_UNIX, SOCK_STREAM, 0);

	// set socket path
	struct sockaddr_un sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sun_family = AF_UNIX;
	strncpy(sock_addr.sun_path, path.c_str(), sizeof(sock_addr.sun_path) - 1);  // nosemgrep - strncpy must be used here to function properly.
	sock_addr.sun_path[sizeof(sock_addr.sun_path) - 1] = '\0';

	unlink(path.c_str());

	// Set 1 second timeout on the socket so we don't just block forever and prevent
	// the program from closing on our accept and recvmsg calls
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	if(0 != setsockopt(sockFd,
		SOL_SOCKET,
		SO_RCVTIMEO,
		(const char*)&timeout,
		sizeof(timeout))) {
		std::string msg = "Failed to set timeout on socket";
		throw std::runtime_error(msg);
	}

	if(0 != bind(sockFd, (struct sockaddr*) &sock_addr, sizeof(sock_addr))) {
		std::string msg = std::string("Error binding ") + path;
		throw std::runtime_error(msg);
	}
	
	if(0 != listen(sockFd, JALLS_LISTEN_BACKLOG)) {
		std::string msg = std::string("Error listening: ") + path;
		throw std::runtime_error(msg);
	}
}

UDSRecvSocket::UDSRecvSocket(UDSRecvSocket&& s) {
	this->sockFd = s.sockFd;
	s.sockFd = -1;
	this->clientFd = s.clientFd;
	s.clientFd = -1;
	this->cred = s.cred;
	// I *think* struct sock_addr has no dynamic memory and is safe to naively copy
	this->peer_addr = s.peer_addr;
}

UDSRecvSocket& UDSRecvSocket::operator=(UDSRecvSocket&& s) {
	this->sockFd = s.sockFd;
	s.sockFd = -1;
	this->clientFd = s.clientFd;
	s.clientFd = -1;
	this->cred = s.cred;
	// I *think* struct sock_addr has no dynamic memory and is safe to naively copy
	this->peer_addr = s.peer_addr;
	return (*this);
}

UDSRecvSocket::~UDSRecvSocket() {
	if(-1 != sockFd) {
		close(sockFd);
	}
}

int UDSRecvSocket::pollSocket(){
	memset(&cred, 0, sizeof(cred));
	socklen_t cred_len = sizeof(cred);
	// Use poll to check if the socket is readable before calling accept
	// This should prevent us blocking forever in the accept
	struct pollfd fds[1];
	fds[0].fd = sockFd;
	fds[0].events = POLLIN;

	// Return immediately if the socket isn't ready
	int poll_status = poll(fds, 1, 0);
	// poll_status is set to either -1 (error), 0 (no error but no fds are ready)
	// or the number of fds with nonzero revents fields (in our case always 1)
	if(1 != poll_status) {
		return -1;
	}
	clientFd = accept(sockFd, (struct sockaddr *) &peer_addr, &peer_addr_size);

	// Set 1 second timeout on the socket so we don't just block forever and prevent
	// the program from closing on our accept and recvmsg calls
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	if(0 != setsockopt(clientFd,
		SOL_SOCKET,
		SO_RCVTIMEO,
		(const char*)&timeout,
		sizeof(timeout))) {
		std::string msg = "Failed to set timeout on socket";
		throw std::runtime_error(msg);
	}
	getsockopt(clientFd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len);
	return 0;
}

UDSRecvRV UDSRecvSocket::recvInternal(
	UDSRecvMessage& message,
	const size_t lower_bound,
	const size_t upper_bound) {
	ssize_t bytes;
	int myerrno;

	ssize_t exp_bytes = 0;
	// process fields lower_bound to upper_bound inclusive
	for (size_t i = lower_bound; i <= upper_bound; i++)
	{
		const int depends = message.fieldDependencies[i];
		const int optional = message.fieldOptionalDependencies[i];
		// TODO: Currently it is not possible to have a field which is optional which is
		// not also dependent on another field for length. If that changes, this will have
		// to accomodate that possibility
		if(-1 == depends && -1 == optional) {
			// Field is neither optional or cached, it already has its own length
			exp_bytes += message.fields[i].length;
		} else if(-1 != depends && -1 == optional) {
			// field is not optional and its length depends on another field
			uint64_t length = message.fields[depends].extractDataAsLength();
			if(UINT64_MAX == length) {
				fprintf(stderr, "ERROR: Field: %zu depends on Field %d for its length. Field %d \
					is not safely convertable to  uint8, 16, 32, or 64_t.\n",
					i, depends, depends);
				return UDSRecvRV { UDSRecvStatus::LogicError, 0 };
			}

			exp_bytes += length;
			// As long as we have the length, we might as well update the field so we don't have
			// to do this check/lookup again later
			message.fields[i].length = length;
			// and remove the dependency from our tracked dependencies - shouldn't actually
			// matter in the current implementation
			message.fieldDependencies[i] = -1;
		} else if (-1 == depends && -1 != optional) {
			// Field is optional, but has known length
			uint16_t field_existance_marker = message.fields[optional].extractDataAsOption();
			if(UINT16_MAX == field_existance_marker) {
				fprintf(stderr, "ERROR: Field: %zu is optional based on Field %d. Field %d \
					is not safely convertable to  uint16_t.\n",
					i, optional, optional);
				return UDSRecvRV { UDSRecvStatus::LogicError, 0 };
			}

			// If the option is not equal to the optionalCompareValue this field will
			// not be populated in the data we receive.
			// Indicate that it should be skipped by setting its length to 0
			if(field_existance_marker != message.fieldOptionalCompareValues[i]) {
				exp_bytes += 0;
				message.fields[i].length = 0;
			} else {
				// The fields exists, use its known length
				exp_bytes += message.fields[i].length;
			}
			// and remove the dependency from our tracked dependencies - shouldn't actually
			// matter in the current implementation
			message.fieldOptionalDependencies[i] = -1;
		}
		else {
			// This field is optional based one one field, and its length is defined by another
			uint16_t field_existance_marker = message.fields[optional].extractDataAsOption();
			if(UINT16_MAX == field_existance_marker) {
				fprintf(stderr, "ERROR: Field: %zu is optional based on Field %d. Field %d \
					is not safely convertable to  uint16_t.\n",
					i, optional, optional);
				return UDSRecvRV { UDSRecvStatus::LogicError, 0 };
			}

			// If the option is not equal to the optionalCompareValue this field will
			// not be populated in the data we receive.
			// Indicate that it should be skipped by setting its length to 0
			if(field_existance_marker != message.fieldOptionalCompareValues[i]) {
				exp_bytes += 0;
				message.fields[i].length = 0;
				// and remove the dependency from our tracked dependencies - shouldn't actually
				// matter in the current implementation
				message.fieldDependencies[i] = -1;
				message.fieldOptionalDependencies[i] = -1;
			} else {
				// This field will exist, get its length
				uint64_t length = message.fields[depends].extractDataAsLength();
				if(UINT64_MAX == length) {
					fprintf(stderr, "ERROR: Field: %zu depends on Field %d for its length. Field %d \
						is not safely convertable to  uint8, 16, 32, or 64_t.\n",
						i, depends, depends);
					return UDSRecvRV { UDSRecvStatus::LogicError, 0 };
				}

				exp_bytes += length;
				// As long as we have the length, we might as well update the field so we don't have
				// to do this check/lookup again later
				message.fields[i].length = length;
				// and remove the dependency from our tracked dependencies - shouldn't actually
				// matter in the current implementation
				message.fieldDependencies[i] = -1;
			}
		}
	}

	// form up iov structs for fields[lower_bound] through fields[upper_bound]
	size_t num_fields = upper_bound - lower_bound + 1;
	std::unique_ptr<struct iovec[]> iovs = std::make_unique<struct iovec[]>(num_fields);

	// point the iovec structs at the fields owned by the class. These are non-owning pointers
	size_t num_iovecs = 0;
	for(size_t i = 0; i < num_fields; i++) {
		Field& f = message.fields.at(i + lower_bound);

		// This field was either specified with a length of 0 or optional and omitted.
		// Just skip it
		if(0 == f.length) {
			continue;
		}

		// We need to allocate space in the field according to the length we determined.
		// This will always be owned data
		f.owned_data = (void*)malloc(f.length);

		// Point the iov to our allocated space and set the length
		iovs[i].iov_base = f.owned_data;
		iovs[i].iov_len = f.length;

		num_iovecs++;
	}

	char msg_control_buffer[CMSG_SPACE(sizeof(message.fd))];
	memset(&msg_control_buffer, 0, sizeof(msg_control_buffer));

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_control = msg_control_buffer;
	msgh.msg_controllen = sizeof(msg_control_buffer);

	msgh.msg_iov = iovs.get();
	msgh.msg_iovlen = num_fields;

	bytes = recvmsg(clientFd, &msgh, MSG_WAITALL);
	myerrno = errno;

	// Extract fd, if one was passed
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msgh);
	// Loop over all cmsg headers
	while (cmsg != NULL) {
		// We're only interested in SOL_SOCKET headers
		if (cmsg->cmsg_level == SOL_SOCKET) {
			if (cmsg->cmsg_type == SCM_RIGHTS && cmsg->cmsg_len == CMSG_LEN(sizeof(message.fd))) {
				void *tmp_fd = CMSG_DATA(cmsg);
				if (message.fd != -1) {
					fprintf(stderr, "WARNING: received duplicate ancillary data: overwrote the fd\n");
				}
				message.fd = *((int *)tmp_fd);
				if (message.fd < 0) {
					return UDSRecvRV { UDSRecvStatus::BadFdReceived, myerrno };
				}
			} else {
				return UDSRecvRV { UDSRecvStatus::BadCmsgHeaderReceived, myerrno };
			}
		}
		// Move to next header
		cmsg = CMSG_NXTHDR(&msgh, cmsg);
	}

	if (bytes == -1)
	{
		if ((EAGAIN == myerrno) || (EWOULDBLOCK == myerrno))
		{
			return UDSRecvRV { UDSRecvStatus::Timeout, myerrno };
		}
		else
		{
			return UDSRecvRV { UDSRecvStatus::LowLevelFailure, myerrno };
		}
	}
	else if (bytes == 0)
	{
		return UDSRecvRV { UDSRecvStatus::SocketShutdown, 0 };
	}
	else if (bytes != exp_bytes)
	{
		return UDSRecvRV { UDSRecvStatus::LengthMismatch, 0 };
	}
	return UDSRecvRV { UDSRecvStatus::Success, 0 };
}

// Must take the message by reference to avoid slicing and allow for polymorphism.
// Also it avoids a copy we don't want.
UDSRecvRV UDSRecvSocket::recvMsg(UDSRecvMessage& message) {
	size_t lower_bound = 0;
	size_t upper_bound = 0;
	// Walk the dependency vector
	// Take all fields until we find the next one that is dependent
	// on an earlier field. We could be more clever here, but for simplicity, just start a
	// new batch whenever we encounter a new dependent field.
	
	// Special case - ensure recvMsg isn't being called with no fields defined
	if(message.fields.size() < 1) {
		fprintf(stderr, "ERROR: recvMsg may not be called with no fields defined\n");
		return UDSRecvRV { UDSRecvStatus::LogicError, 0 };
	}

	// Ensure the fields and fieldDependencies vectors are the same size. addField* should
	// prevent this from happening
	if(message.fields.size() != message.fieldDependencies.size() 
		|| message.fields.size() != message.fieldOptionalDependencies.size()
		|| message.fields.size() != message.fieldOptionalCompareValues.size()) {
		fprintf(stderr, "ERROR: Corruption in UDSRecvMessage field descripitons.\n");
		return UDSRecvRV { UDSRecvStatus::LogicError, 0};
	}
	
	// Special case, field 0 can never be dependent on another field
	// addField* should prevent this, but we'll double-check anyway
	if(-1 != message.fieldDependencies[0]) {
		fprintf(stderr, "ERROR: The first field added to a UDSRecvMessage may not depend on \
			other fields.\n");
		return UDSRecvRV { UDSRecvStatus::LogicError, 0};
	}

	// Special case, field 0 can never be optional based on another field
	// addField* should prevent this, but we'll double-check anyway
	if(-1 != message.fieldOptionalDependencies[0]
		|| UINT16_MAX != message.fieldOptionalCompareValues[0]) {
		fprintf(stderr, "ERROR: The first field added to a UDSRecvMessage may not depend on \
			other fields.\n");
		return UDSRecvRV { UDSRecvStatus::LogicError, 0};
	}

	// lower and upper bound are "inclusive"
	while(lower_bound < message.fields.size()) {
		// Walk upper bound forward starting from lower_bound until...
		// a) upper_bound + 1 is == size
		// b) fieldDependencies[upper_bound+1] has a value greater than or equal to lower bound
		// The check against -1 is to ensure a safe cast to size_t
		upper_bound = lower_bound;
		while(message.fields.size() > (upper_bound + 1)
			&& (-1 == message.fieldDependencies[upper_bound + 1]
				|| lower_bound > (size_t)message.fieldDependencies[upper_bound + 1])
			&& (-1 == message.fieldOptionalDependencies[upper_bound + 1]
				|| lower_bound > (size_t)message.fieldOptionalDependencies[upper_bound + 1])) {
			upper_bound++;
		}
		// It is now safe to recvmsg all the fields from lower_bound to upper_bound (inclusive)
		// in a single call. The lower_bound item may be dependent on another field, but
		// we guarantee that field will have been received in a previous batch
		UDSRecvRV rv = this->recvInternal(message, lower_bound, upper_bound);
		if(UDSRecvStatus::Success != rv.status) {
			return rv;
		}

		lower_bound = upper_bound + 1;
	}
	// If we get here, the fields have all been populated without error
	return UDSRecvRV {UDSRecvStatus::Success, 0};
}

