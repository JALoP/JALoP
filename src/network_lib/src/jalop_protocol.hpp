/**
 * @file
 *
 * @brief This file contains declarations for handling sending/receiving
 * JALoP protocol messages via curl
 *
 * ### LICENSE
 *
 * Copyright (C) 2018-2026 Concurrent Technologies Corporation.
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <string>
#include <map>
#include <axl.h>
#include <curl/curl.h>
#include <stdexcept>
#include <string>
#include <vector>
extern "C" {
#include "jaln_context.h"
#include <jalop/jaln_network_types.h>
#include <jalop/jal_digest.h>
}

class InvalidMessage : public std::runtime_error {
	public:
	InvalidMessage(const std::string& reason) : std::runtime_error(reason) {};
};

class SendFailure : public std::runtime_error {
	public:
	SendFailure(const std::string reason) : std::runtime_error(reason) {};
};

class MalformedResponse : public std::runtime_error {
	public:
	MalformedResponse(const std::string reason) : std::runtime_error(reason) {};
};

class InvalidResponseType : public std::runtime_error {
	public:
	InvalidResponseType(const std::string typeStr) : std::runtime_error(typeStr) {};
};

class InvalidResponse : public std::runtime_error {
	std::string errMsg;
	public:
	std::string responseType;
	std::string reason;
	InvalidResponse(
		const std::string responseType,
		const std::string reason);
	const char* what() const noexcept override {
		return errMsg.c_str();
	}
};

enum class ResponseType {
	InitAck,
	InitNack,
	JournalMissingResponse,
	RecordFailure,
	SessionFailure,
	CloseSessionResponse,
	DigestChallenge,
	Sync,
	SyncFailure,
};

struct JalopResponse {
	std::map<std::string, std::string> headers;
	ResponseType getResponseType();
	std::string getResponseTypeString();
};

struct InitAck {
	std::string sessionId;
	std::string xmlCompression;
	enum jal_digest_algorithm digestAlgorithm;
	std::string digestAlgorithmUri;
	bool challengeDigest = true;
	std::string id;
	uint64_t offset = 0;
	InitAck(
		const JalopResponse& response,
		axlList* allowed_digest_algs,
		axlList* allowed_compressions,
		const enum jaln_digest_challenge allowed_challenge,
		const enum jaln_publish_mode mode,
		const enum jaln_record_type type);
};

struct InitNack {
	// The original unsplit error message header
	std::string errorMessage;
	// The error messages split by | with the | removed
	std::vector<std::string> errors;
	InitNack(const JalopResponse& response);
};

struct JournalMissingResponse {
	JournalMissingResponse(const JalopResponse& response);
};

struct RecordFailure {
	// The original unsplit error message header
	std::string errorMessage;
	// The error messages split by | with the | removed
	std::vector<std::string> errors;
	std::string id;
	RecordFailure(
		const JalopResponse& response,
		const std::string& expectedId);
};

struct SessionFailure {
	// The original unsplit error message header
	std::string errorMessage;
	// The error messages split by | with the | removed
	std::vector<std::string> errors;
	std::string id;
	std::string sessionId;
	SessionFailure(
		const JalopResponse &response,
		const std::string& expectedId,
		const std::string& expectedSessionId);
};

struct  DigestChallenge {
	std::string id;
	std::string digestValue;
	DigestChallenge(
		const JalopResponse& response,
		const std::string& expectedId);
};

struct Sync {
	std::string id;
	Sync(
		const JalopResponse& response,
		const std::string& expectedId);
};

struct SyncFailure {
	// The original unsplit error message header
	std::string errorMessage;
	// The error messages split by | with the | removed
	std::vector<std::string> errors;
	std::string id;
	SyncFailure(
		const JalopResponse& response,
		const std::string& expectedId);
};

struct CloseSessionResponse {
	CloseSessionResponse(const JalopResponse& response);
};

struct JalopMessage {
	std::map<std::string, std::string> headers;

	JalopMessage();
	JalopResponse sendMessage(
		CURL* curl,
		const long curl_timeout_period,
		const long curl_retry_count);

};

struct InitMessage : public JalopMessage {
	InitMessage(
		const enum jaln_publish_mode mode,
		const enum jaln_record_type type,
		const std::string& publisherId,
		const enum jaln_digest_challenge digestChallenge,
		axlList* dgst_list,
		axlList* cmp_list);
};

struct JournalMissingMessage : public JalopMessage {
	JournalMissingMessage(
		const std::string& sessionId,
		const std::string& recordId);
};

struct CloseSessionMessage : public JalopMessage {
	CloseSessionMessage(
		const std::string& sessionId);
};

struct RecordMessage : public JalopMessage {
	// Non-owning pointers, do not free
	struct jal_digest_ctx* digestContext = NULL;
	const uint8_t* sysMeta = NULL;
	const uint8_t* appMeta = NULL;
	const uint8_t* payload = NULL;

	// Owned pointer
	void* digestInstance = NULL;

	uint64_t sysMetaLen = 0;
	uint64_t appMetaLen = 0;
	uint64_t payloadLen = 0;
	uint64_t resumeOffset = 0;
	uint64_t postSize = 0;

	bool expectDigestChallenge = true;
	bool payloadOnDisk = false;
	int payloadFd = -1;

	enum jaln_record_type type;

	// Storage for the calculated digest
	uint8_t* calculatedDigest = NULL;

	RecordMessage(
		const std::string& sessionId,
		const std::string& nonce,
		const enum jaln_record_type type,
		const bool expectDigestChallenge,
		const uint8_t* sysMeta,
		const uint64_t sysMetaLen,
		const uint8_t* appMeta,
		const uint64_t appMetaLen,
		const bool payloadOnDisk,
		const uint64_t payloadLen,
		const int payloadFd,
		const uint8_t* payload,
		const uint64_t resumeOffset,
		struct jal_digest_ctx* digestContext);

	JalopResponse sendMessage(
		CURL* curl,
		const long curl_timeout_period,
		const long curl_retry_count);

	~RecordMessage();

	uint8_t* takeCalculatedDigest();
};

struct DigestResponseMessage : public JalopMessage {
	DigestResponseMessage(
		const std::string& sessionId,
		const std::string& id,
		const uint8_t* localDigest,
		const uint32_t localSize,
		const uint8_t* peerDigest,
		const uint32_t peerSize);
};
