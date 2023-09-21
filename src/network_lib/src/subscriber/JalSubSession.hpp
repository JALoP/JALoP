/*
 * Copyright (C) 2023 The National Security Agency (NSA)
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
#ifndef __JAL__SUB__SESSSION__H__
#define __JAL__SUB__SESSSION__H__

#include <string>
#include <regex>
#include <stdexcept>
#include <sstream>
#include <map>
#include <memory>
#include <utility>
#include <chrono>
#include <jalop/jal_digest.h>
#include "jal_base64_internal.h"

#include "JalSubConstants.hpp"
#include "JalSubConfig.hpp"
#include "JalSubMessaging.hpp"
#include "JalSubEnumTypes.hpp"
#include "JalSubDatabase.hpp"
#include "JalSubRecordInfo.hpp"

class InvalidStateException : public std::exception
{
	private:
	std::string msg;

	public:
	InvalidStateException(std::string& errMsg)
		: msg(errMsg){}
	const char* what() const noexcept override
	{
		return msg.c_str();
	}
};

// Disallow subclassing as it will case object-slicing the way we're using our map
class Session final
{
	private:

	std::string sessionId;

	RecordInfo currentRecordInfo;

	// Each session is configured to use a specific digest algorithm during initialization
	enum jal_digest_algorithm digestAlgorithm = JAL_DIGEST_ALGORITHM_DEFAULT;

	// Each session has a unique id generated during initialization
	std::string uuid;

	// Each publisher will attach a UUID to its messages, established in the init handshake
	std::string publisherId;

	// TODO: Unused
	std::string xmlCompression = "None";

	// Each session has a single RecordType it is associated with, requested
	// by the publisher
	RecordType recordType;

	// Whether or not to send digest challenge messages in response to records
	bool shouldChallengeDigest;

	// Polymorphic interface to the Database held by the subscriber
	std::weak_ptr<JalSubDatabase> jdb;

	// Configuration settings for the subscriber
	SubscriberConfig config;

	// Time of creation or last message handled
	std::chrono::time_point<std::chrono::steady_clock> lastAccess 
		= std::chrono::steady_clock::now();
	
	// Information about whether or not this session should request a journal resume
	std::string resumeId;
	size_t resumeOffset = 0;

	// Functions
	bool validateAndStorePublisherId(const Message& message);

	bool validateVersion(const Message& message);

	bool validateAndStoreXmlCompression(const Message& message);

	bool validateAndStoreAcceptDigest(const Message& message);

	bool validateAndStoreAcceptConfigureDigestChallenge(const Message& message);

	bool validateAndStoreRecordType(const Message& message);

	bool validateMode(const Message& message);

	Response handleAuditMessage(const Message& message);

	Response handleLogMessage(const Message& message);

	Response handleJournalMessage(const Message& message);

	Response handleJournalMissing(const Message& message);

	Response handleDigestChallengeResponse(const Message& message);

	std::string calculateDigest(const Message& message);

	Response generateNack(std::string errorMessage);

	Response generateDigestChallenge();

	Response generateRecordFailure(std::string errorMessage, std::string jalId);

	Response generateSyncFailure();

	bool shouldResume();

	public:
	enum jal_digest_algorithm getDigestAlgorithm();

	std::string getPublisherId();

	ModeType getReceiveMode();

	Response handleRecord(const Message& message, RecordType recordType);

	Response handleInitMessage(const Message& message);

	Response handleCloseMessage(const Message& message);

	Response handleMessage(ReceiveMessageType type, const Message& message);

	std::chrono::time_point<std::chrono::steady_clock> getLastAccess() const;

	Session(const Session& orig) = delete;
	Session(Session&&) = default;
	Session& operator=(const Session&) = delete;
	Session& operator=(Session&&) = default;

	Session(
		std::string uuid,
		std::weak_ptr<JalSubDatabase> jdb,
		SubscriberConfig config);

	~Session();
};

#endif
