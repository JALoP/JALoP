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
#ifndef __JAL__SUB_MESSAGING__H__
#define __JAL__SUB_MESSAGING__H__

#include <map>
#include <string>
#include <exception>
#include <vector>
#include <fstream>
#include <mutex>

#include "JalSubRecordInfo.hpp"
#include "JalSubEnumTypes.hpp"
#include "JalSubDigestCalculator.hpp"
#include "JalSubConstants.hpp"

// Exception thrown when a required header is missing
class MissingHeaderException : public std::exception
{
	private:
	std::string msg;

	public:
	MissingHeaderException(std::string& msgStr) : msg(msgStr){}

	const char* what() const noexcept override
	{
		return msg.c_str();
	}
};

class MessageBase
{
	private:
	// Data
	std::map<std::string, std::string> headers;

	// Functions
	//
	public:
	// Data
	//
	// Functions
	void addHeader(std::string key, std::string value);

	std::string getHeader(const std::string key) const;

	// TODO: This is slightly dangerous as the reference could potentially outlive
	// the class and become dangling. Consider alternatives or return a copy
	std::map<std::string, std::string>& getHeaders();
};

class Response : public MessageBase
{
	private:
	// Data
	int status = JAL_STATUS_OK;

	// Functions
	public:
	void setStatus(int status);

	int getStatus() const;

	Response();
};

class Message : public MessageBase
{
	private:
	// Static Members
	// Used to store configuration information so it gets correctly populated in all
	// instances
	// TODO: Consider using a factory to construct messages rather than using static
	// members to store configuration settings. There's a small risk of race condition
	// for the first few messages created when starting the http server
	//
	static bool debug;

	static size_t bufferSize;

	// Used to ensure messages getting written to disk
	// have unique filenames
	static size_t msgCounter;
	static std::mutex msgCounterMutex;

	// Base path for all temporary files
	static std::string tempFilePath;

	// Non-static Data

	// When handling records, info will contain the record data
	RecordInfo info;

	ReceiveMessageType messageType = ReceiveMessageType::UNKNOWN_MESSAGE;

	// Container for state information used during pre-processing of record data
	struct ParsingState
	{
		DigestCalculator digestCalculator{digestAlgorithm};
		// Track which segment we're currently processing
		enum class RecordSegment
		{
			NEW_RECORD,
			SYS_METADATA,
			BREAK1,
			APP_METADATA,
			BREAK2,
			PAYLOAD,
			BREAK3,
			DONE
		} currentSegment = RecordSegment::NEW_RECORD;

		// Track progress through the current segment
		size_t segmentOffset = 0;

		// Track progress through the current content
		size_t bytesProcessed = 0;

		// If a parse/storage related failure occurs during data collection, note that for later
		bool parseErrorEncountered = false;

		// Used during pre-parsing of record messages. Signals a basic violation, like a missing
		// messageType, invalid/missing content-length, or similar. This will trigger an outright
		// rejection of the message as an error 500 or similar at the http layer with no JALoP
		// response of any kind
		bool shouldAbort = false;

		// If an error is encountered during pre-parsing, these values
		// are used to generate the eventual response
		std::string errorKind;
		std::string errorMessage;

		void transitionState(RecordSegment nextSegment)
		{
			segmentOffset = 0;
			currentSegment = nextSegment;
		}

		// Track how many bytes of the record data have been handled so far
		bool fileOpened = false;
		std::ofstream payloadFile;

		bool messageComplete = false;

		enum jal_digest_algorithm digestAlgorithm = JAL_DIGEST_ALGORITHM_DEFAULT;

		std::string publisherId;

		ModeType mode;

		RecordType recordType;
	} parsingState;

	// Private functions
	bool processMetadata(
		const uint8_t*& data,
		size_t& bytesRemaining,
		std::vector<uint8_t>& destVec,
		size_t metadataLen,
		ParsingState::RecordSegment nextRecordSegment);

	bool processBreak(
		const uint8_t*& data,
		size_t& bytesRemaining,
		ParsingState::RecordSegment nextRecordSegment);

	bool prepareForPayload();

	bool resumeJournal();

	bool processPayload(
		const uint8_t*& data,
		size_t& bytesRemaining);

	bool processPayloadToFile(
		const uint8_t*& data,
		size_t& bytesRemaining);
	
	bool processPayloadToBuffer(
		const uint8_t*& data,
		size_t& bytesRemaining);

	void transitionState(ParsingState::RecordSegment recordSegment);

	public:

	// Total size of the received http message as indicated by the content-length header
	size_t contentLength;

	~Message();

	static void setDebug(bool debug);

	static void setBufferSize(size_t size);

	static void setTempFilePath(std::string path);

	static std::string getTempFilePath();

	void addData(const uint8_t* data, size_t* size);

	void notifyTimeout();

	void processHeaders();

	void finalizeData();

	RecordInfo getInfo();

	ReceiveMessageType getMessageType() const;

	std::string getDigest() const;

	Response generateError();

	void setError(std::string errorKind, std::string errorMessage);

	bool shouldError();

	bool shouldAbort();

	bool isRecord();

	bool messageIsComplete();

	void setDigestAlgorithm(enum jal_digest_algorithm alg);

	void setPublisherId(std::string id);

	void setReceiveMode(ModeType mode);
};

#endif
