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
#include <exception>
#include <string>
#include <map>
#include <vector>
#include <stdexcept>
#include <fstream>

#include "JalSubConstants.hpp"
#include "JalSubMessaging.hpp"
#include "JalSubDigestCalculator.hpp"
#include "JalSubUtils.hpp"

// Initialization of static members
size_t Message::msgCounter = 0;
size_t Message::bufferSize = 4096;
bool Message::debug = false;
std::string Message::tempFilePath = "";
std::mutex Message::msgCounterMutex;

void Message::setDebug(bool newVal)
{
	Message::debug = newVal;
}

void Message::setBufferSize(size_t size)
{
	if(0 == size)
	{
		std::string errMsg = "bufferSize must be > 0. At least 4096 is recommended";
		throw std::runtime_error(errMsg);
	}
	bufferSize = size;
}

void Message::setTempFilePath(std::string path)
{
	if(path.length() <= 0)
	{
		std::string errMsg = "Argument to Message::setTempFilePath must not be empty";
		throw std::runtime_error(errMsg);
	}
	// May throw if the given path cannot be canonicalized
	// We would just throw anyway, so let it pop out the top and prevent startup
	Message::tempFilePath = path;

	// If the specified path does not exist, attempt to create it
	// May likewise throw if the directory can't be created
	if(!createDir(path))
	{
		std::string errMsg = "Failed to initialize in-transit payload directory: " + path;
		throw std::runtime_error(errMsg);
	}
}

std::string Message::getTempFilePath()
{
	return Message::tempFilePath;
}

static bool extractSizeT(const std::string& source, size_t& dest)
{
	size_t charsRead;
	try
	{
		dest = std::stoul(source, &charsRead);
	}
	catch(...)
	{
		return false;
	}

	if(source.length() != charsRead)
	{
		return false;
	}
	return true;
}

void MessageBase::addHeader(std::string key, std::string value)
{
	// Store all headers
	headers[key] = value;
}

std::string MessageBase::getHeader(const std::string key) const
{
	try
	{
		return headers.at(key);
	}
	catch(std::out_of_range &e)
	{
		return "";
	}
}

Response::Response()
{
	this->addHeader(HEADER_CONTENT_TYPE, HEADER_CONTENT_TYPE_DEFAULT);
}

int Response::getStatus() const
{
	return status;
}

void Response::setStatus(int newStatus)
{
	this->status = newStatus;
}

void Message::processHeaders()
{
	// All messages must have a messageType
	std::string messageTypeStr = getHeader(HEADER_MESSAGE_TYPE);
	if(messageTypeStr.empty())
	{
		parsingState.shouldAbort = true;
		return;
	}

	// Ensure the messageType is valid
	try
	{
		this->messageType = receiveMessageTypeFromString(messageTypeStr);
	}
	catch(...)
	{
		parsingState.shouldAbort = true;
		return;
	}

	// We want the contentLength regardless of the message type
	std::string contentLengthStr = getHeader(HEADER_CONTENT_LENGTH);
	if(contentLengthStr.empty() ||
		!extractSizeT(contentLengthStr, this->contentLength))
	{
		parsingState.shouldAbort = true;
		return;
	}

	// If the message isn't a record of some kind, we're done. Everything else can be
	// processed later.
	// If the message is a record of some kind, we need to various lengths to accurately
	// calcaulte the digest and offload the payload to disk (if necessary) as POST messages
	// come in
	switch(this->messageType)
	{
		case ReceiveMessageType::MSG_LOG:
			parsingState.recordType = RecordType::JAL_LOG;
			break;
		case ReceiveMessageType::MSG_AUDIT:
			parsingState.recordType = RecordType::JAL_AUDIT;
			break;
		case ReceiveMessageType::MSG_JOURNAL:
			parsingState.recordType = RecordType::JAL_JOURNAL;
			break;
		default:
			this->parsingState.messageComplete = true;
			return;
			break;
	}

	// There should be a jalId in the record message, which we'll need for error generation
	this->info.jalId = getHeader(HEADER_JAL_ID_TYPE);
	if(this->info.jalId.empty())
	{
		setError(MSG_RECORD_FAILURE_STR, JAL_INVALID_JAL_ID);
		return;
	}

	std::string sysMetaLengthStr = getHeader(HEADER_JAL_SYSTEM_METADATA_LENGTH);
	if(sysMetaLengthStr.empty() ||
		!extractSizeT(sysMetaLengthStr, this->info.sysMetadataLen))
	{
		setError(MSG_RECORD_FAILURE_STR, JAL_INVALID_SYSTEM_METADATA_LENGTH);
		return;
	}

	std::string appMetaLengthStr = getHeader(HEADER_JAL_APPLICATION_METADATA_LENGTH);
	if(appMetaLengthStr.empty() ||
		!extractSizeT(appMetaLengthStr, this->info.appMetadataLen))
	{
		setError(MSG_RECORD_FAILURE_STR, JAL_INVALID_APPLICATION_METADATA_LENGTH);
		return;
	}

	std::string payloadLenHeader;
	std::string payloadLenErrorValue;
	switch(this->messageType)
	{
		case ReceiveMessageType::MSG_LOG:
			payloadLenHeader = HEADER_JAL_LOG_LENGTH;
			payloadLenErrorValue = JAL_INVALID_LOG_LENGTH;
			break;
		case ReceiveMessageType::MSG_AUDIT:
			payloadLenHeader = HEADER_JAL_AUDIT_LENGTH;
			payloadLenErrorValue = JAL_INVALID_AUDIT_LENGTH;
			break;
		case ReceiveMessageType::MSG_JOURNAL:
			payloadLenHeader = HEADER_JAL_JOURNAL_LENGTH;
			payloadLenErrorValue = JAL_INVALID_JOURNAL_LENGTH;
			break;
		default:
			// All other cases should cause early return. If this default is hit
			// an error has been injected that needs to be dealt with. Fail loudly
			std::string errMsg = "Program failure in processHeaders(). Unreachable code reached.";
			throw std::runtime_error(errMsg);
			break;
	}
	
	std::string payloadLenStr = getHeader(payloadLenHeader);
	if(payloadLenHeader.empty() ||
		!extractSizeT(payloadLenStr, this->info.payloadLen))
	{
		setError(MSG_RECORD_FAILURE_STR, payloadLenErrorValue);
		return;
	}
	return;
}

void Message::setError(std::string errorKind, std::string errorMessage)
{
	parsingState.errorKind = errorKind;
	parsingState.errorMessage = errorMessage;
	parsingState.parseErrorEncountered = true;
}

Response Message::generateError()
{
	Response response;
	response.addHeader(HEADER_MESSAGE_TYPE, this->parsingState.errorKind);
	response.addHeader(HEADER_JAL_ERROR_MESSAGE_TYPE, this->parsingState.errorMessage);
	if(!this->info.jalId.empty())
	{
		response.addHeader(HEADER_JAL_ID_TYPE, this->info.jalId);
	}
	return response;
}

bool Message::processMetadata(
	const uint8_t*& data,
	size_t& bytesRemaining,
	std::vector<uint8_t>& destVec,
	size_t metadataLen,
	ParsingState::RecordSegment nextRecordSegment)
{
	// The received data either is less than the remaining system metadata
	// exactly the length of the remainging system metadata
	// or more then that remaining system metadata
	//
	// In the first two cases, just append all the data to our vector
	size_t remainingMetadata = metadataLen - parsingState.segmentOffset;
	size_t bytesToCopy;
	if(bytesRemaining <= remainingMetadata)
	{
		bytesToCopy = bytesRemaining;
	}
	// Otherwise, copy however many bytes are left in the segment
	else
	{
		bytesToCopy = remainingMetadata;
	}
	// Append all available data to the systemMetadata collector
	destVec.insert(destVec.end(), data, data + bytesToCopy);

	// Advance the segment offset by the amount of data handled
	parsingState.segmentOffset += bytesToCopy;

	// Update the data pointer/remaining size parameters accordingly
	data += bytesToCopy;
	bytesRemaining -= bytesToCopy;

	// Sanity check for use during development
	if(parsingState.segmentOffset > metadataLen)
	{
		throw std::runtime_error(
			"FAIL LOUDLY: more data copied to metadata than should exist");
	}

	// Check for transition to next segment
	if(parsingState.segmentOffset == metadataLen)
	{
		// Feed the metadata segment to the digest calculator
		parsingState.digestCalculator.addData(destVec);
		parsingState.transitionState(nextRecordSegment);
	}
	return true;
}

bool Message::processBreak(
	const uint8_t*& data,
	size_t& bytesRemaining,
	ParsingState::RecordSegment nextRecordSegment)
{
	static const std::vector<uint8_t> BREAK = {'B','R','E','A','K'};

	size_t bytesToCheck;
	size_t remainingBreak = BREAK.size() - parsingState.segmentOffset;

	if(bytesRemaining >= remainingBreak)
	{
		bytesToCheck = remainingBreak;
	}
	else
	{
		bytesToCheck = bytesRemaining;
	}

	// TODO: There's got to be a better c++ way to do this
	// Fail out if we don't find the BREAK marker where we expect
	for(auto i = parsingState.segmentOffset; i < bytesToCheck; i++)
	{
		if(BREAK[i] != data[i])
		{
			setError(MSG_RECORD_FAILURE_STR, JAL_RECORD_FAILURE);
			return false;
		}
	}
	parsingState.segmentOffset += bytesToCheck;
	data += bytesToCheck;
	bytesRemaining -= bytesToCheck;

	if(parsingState.segmentOffset == BREAK.size())
	{
		parsingState.transitionState(nextRecordSegment);
	}
	return true;
}

bool Message::processPayloadToBuffer(const uint8_t*& data, size_t& bytesRemaining)
{
	// If we haven't already done so,
	// increase size of vector before copy to ensure only 1 allocation
	if(info.payload.capacity() != info.payloadLen)
	{
		info.payload.reserve(info.payloadLen);
	}
	size_t remainingPayload = info.payloadLen - parsingState.segmentOffset;
	size_t bytesToWrite;
	if(remainingPayload >= bytesRemaining)
	{
		bytesToWrite = bytesRemaining;
	}
	else
	{
		bytesToWrite = remainingPayload;
	}

	// copy the data to our vector
	info.payload.insert(info.payload.end(), data, data + bytesToWrite);
	parsingState.segmentOffset += bytesToWrite;
	data += bytesToWrite;
	bytesRemaining -= bytesToWrite;

	if(parsingState.segmentOffset == info.payloadLen)
	{
		// Feed the payload buffer to the digest calculator
		parsingState.digestCalculator.addData(info.payload);
		parsingState.transitionState(ParsingState::RecordSegment::BREAK3);
	}
	return true;
}

bool Message::processPayloadToFile(const uint8_t*&data, size_t& bytesRemaining)
{
	size_t remainingPayload = info.payloadLen - parsingState.segmentOffset;
	size_t bytesToWrite;
	if(remainingPayload >= bytesRemaining)
	{
		bytesToWrite = bytesRemaining;
	}
	else
	{
		bytesToWrite = remainingPayload;
	}

	// Write the current data to the payload file
	// fstream wants char* not uint8_t*, but that conversion should be safe in all cases
	// since we're writing in binary mode
	parsingState.payloadFile.write((const char*)data, bytesToWrite);
	if(parsingState.payloadFile.fail() || parsingState.payloadFile.bad())
	{
		fprintf(stderr, "Failed to write to payloadFile: %s\n", info.payloadFileName.c_str());
		setError(MSG_RECORD_FAILURE_STR, JAL_RECORD_FAILURE);
		return false;
	}

	// Feed this portion of the payload to the digest calculator
	parsingState.digestCalculator.addData(data, bytesToWrite);
	bytesRemaining -= bytesToWrite;
	data += bytesToWrite;
	parsingState.segmentOffset += bytesToWrite;

	if(parsingState.segmentOffset == info.payloadLen)
	{
		parsingState.transitionState(ParsingState::RecordSegment::BREAK3);
	}
	return true;
}

bool Message::resumeJournal()
{
	// Attempt to open the calculated payload filename for reading. If it exists, we'll
	// attempt to resume
	std::ifstream existingPayloadFile(info.payloadFileName, std::ios::in | std::ios::binary);

	// If it doesn't exist, there's nothing to resume. Move on
	if(!existingPayloadFile)
	{
		return true;
	}
	debugOutput(Message::debug, stdout,
		"Attempting to resume payload file: %s\n", info.payloadFileName.c_str());

	// The file exists, run all the data it contains through the digest algorithm to
	// "catch up" before proceeding
	uint8_t* buffer = new uint8_t[bufferSize];
	do
	{
		existingPayloadFile.read((char*)buffer, bufferSize);
		size_t byteCount = existingPayloadFile.gcount();
		if(byteCount > 0)
		{
			try
			{
				parsingState.digestCalculator.addData(buffer, byteCount);
			}
			catch(...)
			{
				fprintf(stderr, "Failed to add journal resume data to digest calculator\n");
				setError(MSG_RECORD_FAILURE_STR, JAL_RECORD_FAILURE);
				return false;
			}
		}
	} while(existingPayloadFile); // eof and fail bits get set when we run out of data
	delete[] buffer;
	return true;
}

bool Message::prepareForPayload()
{
	// If the message is of Journal type, or the payload exceeds the buffer size limit
	// the payload will be offloaded to a file
	// If both of these conditions are false, there's nothing to be done
	if(ReceiveMessageType::MSG_JOURNAL != messageType && contentLength <= bufferSize)
	{
		return true;
	}

	// Ensure a staging directory exists for this publisher/messageType
	std::string publisherPath = Message::tempFilePath + "/" + parsingState.publisherId;
	std::string recordPath = publisherPath + "/" + recordTypeToString(parsingState.recordType);
	if(!dirExists(recordPath))
	{
		createDir(publisherPath);
		createDir(recordPath);
	}

	// Get the appropriate name for the payload file
	info.payloadFileName = getPayloadFileName(
		tempFilePath,
		parsingState.publisherId,
		messageType,
		info.jalId);

	// For journal messages only, and only in the archive mode
	if(ReceiveMessageType::MSG_JOURNAL == messageType && ModeType::ARCHIVE == parsingState.mode)
	{
		// If there is an existing payload to be resumed with this ID and by this publisher,
		// do that now
		if(!resumeJournal())
		{
			return false;
		}
	}

	// Open a payload file to dump payload data to
	// Open for append, in case there is already data being resumed
	parsingState.payloadFile.open(info.payloadFileName,
		std::ios::app | std::ios::binary);
	debugOutput(Message::debug, stdout, 
		"opening payload file for writing: %s\n", info.payloadFileName.c_str());
	if(!parsingState.payloadFile.is_open())
	{
		// Some filesystem failure has occurred. Abort
		fprintf(stderr, "Failed to open payloadFile for writing: %s\n",
			info.payloadFileName.c_str());
		setError(MSG_RECORD_FAILURE_STR, JAL_RECORD_FAILURE);
		return false;
	}

	parsingState.fileOpened = true;
	return true;
}

bool Message::processPayload(
	const uint8_t*& data,
	size_t& bytesRemaining)
{
	// If this is the first time we've hit this function for this payload, prepare
	// payload file and perform a resume if needed
	if(0 == parsingState.segmentOffset)
	{
		prepareForPayload();
	}

	// If the size of the payload exceeds the bufferSize, we'll offload it to a file
	// To support journal resume. Always write journal payloads to disk
	if(bufferSize < info.payloadLen || ReceiveMessageType::MSG_JOURNAL == messageType)
	{
		return processPayloadToFile(data, bytesRemaining);
	}
	else
	{
		return processPayloadToBuffer(data, bytesRemaining);
	}
}

void Message::addData(const uint8_t* messageData, size_t* size)
{
	// Regardless of how we exit this function, increment our byte counter
	// by the number of bytes passed in
	parsingState.bytesProcessed += *size;

	// If we're going to generate a JAL-Record-Failure based on missing boundary markers
	// mismatched length, or failure to write to disk
	// or if we'll generate a JAL-Session-Failure because there's no session with a matching
	// session id
	// skip this processing
	if(parsingState.parseErrorEncountered)
	{
		*size = 0;
		return;
	}

	const uint8_t* remainingData = messageData;
	size_t remainingLen = *size;
	bool parseOk = true;

	while(remainingLen > 0 && parseOk)
	{
		switch(parsingState.currentSegment)
		{
			// Initialize digest context
			case ParsingState::RecordSegment::NEW_RECORD:
				parsingState.transitionState(ParsingState::RecordSegment::SYS_METADATA);
				break;
			case ParsingState::RecordSegment::SYS_METADATA:
				parseOk = processMetadata(
					remainingData,
					remainingLen,
					info.sysMetadata,
					info.sysMetadataLen,
					ParsingState::RecordSegment::BREAK1);
				break;
			case ParsingState::RecordSegment::BREAK1:
				parseOk = processBreak(
					remainingData,
					remainingLen,
					ParsingState::RecordSegment::APP_METADATA);
				break;
			case ParsingState::RecordSegment::APP_METADATA:
				parseOk = processMetadata(
					remainingData,
					remainingLen,
					info.appMetadata,
					info.appMetadataLen,
					ParsingState::RecordSegment::BREAK2);
				break;
			case ParsingState::RecordSegment::BREAK2:
				parseOk = processBreak(
					remainingData,
					remainingLen,
					ParsingState::RecordSegment::PAYLOAD);
				break;
			case ParsingState::RecordSegment::PAYLOAD:
				parseOk = processPayload(
					remainingData,
					remainingLen);
				break;
			case ParsingState::RecordSegment::BREAK3:
				parseOk = processBreak(
					remainingData,
					remainingLen,
					ParsingState::RecordSegment::DONE);
				break;
			case ParsingState::RecordSegment::DONE:
				// If we actually land here, we have more data than we expected
				// This is an error
				parseOk = false;
				setError(MSG_RECORD_FAILURE_STR, JAL_RECORD_FAILURE);
				break;
		}
		if(!parseOk)
		{
			parsingState.parseErrorEncountered = true;
		}
	}
	// If we've run out of data and aren't in the DONE state, that is an error
	if(ParsingState::RecordSegment::DONE != parsingState.currentSegment
		&& parsingState.bytesProcessed >= contentLength)
	{
		setError(MSG_RECORD_FAILURE_STR, JAL_RECORD_FAILURE);
	}

	// Only if we finished the while with a state of DONE, no remaining data,
	// and no errors do we conclude the message has been fully received
	if(ParsingState::RecordSegment::DONE == parsingState.currentSegment
		&& 0 == remainingLen && parseOk)
	{
		this->info.digest = parsingState.digestCalculator.finalizeDigest();
		parsingState.messageComplete = true;
	}

	// TODO: We're assuming we can always accomodate all received data
	//  - or we're dropping it becaue of an error -
	// If this ever stops being true, we need set size to the amount of unprocessed bytes
	*size = 0;
}

void Message::notifyTimeout()
{
	// The http exchange this message is associated with has timed out
	// The session will be removed
	// In order to facilitate journal resume, if and only if this is a journal record
	// and is configured for archive mode - close and orphan the payloadFile so it
	// is left behind for a potential resume. Otherwise, do nothing and allow the destrution
	// of the recordInfo to destroy the staged payload
	if(ModeType::ARCHIVE == parsingState.mode &&
		RecordType::JAL_JOURNAL == parsingState.recordType)
	{
		parsingState.payloadFile.close();
		info.payloadFileName.clear();
	}
}

void Message::finalizeData()
{
	// if the data is being written to a file, close the file handle
	if(parsingState.payloadFile.is_open())
	{
		parsingState.payloadFile.close();
	}

	// If this is called and we we're in the middle of processing record data,
	// clearly there was something wrong with either the data or headers we were
	// sent
	// Note - only override the current error state if one doesn't already exist
	if(!parsingState.messageComplete && !shouldError())
	{
		setError(MSG_RECORD_FAILURE_STR, JAL_RECORD_FAILURE);
	}
}

std::string Message::getDigest() const
{
	return info.digest;
}

// TODO: This is slightly dangerous as the reference could potentially outlive
// the class and become dangling. Consider alternatives or return a copy
std::map<std::string, std::string>& MessageBase::getHeaders() 
{
	return headers;
}

bool Message::shouldError()
{
	return parsingState.parseErrorEncountered;
}

bool Message::shouldAbort()
{
	return parsingState.shouldAbort;
}

bool Message::messageIsComplete()
{
	return parsingState.messageComplete;
}

void Message::setDigestAlgorithm(enum jal_digest_algorithm algorithm)
{
	parsingState.digestAlgorithm = algorithm;
	parsingState.digestCalculator.changeAlgorithm(algorithm);
}

void Message::setPublisherId(std::string id)
{
	parsingState.publisherId = id;
}

void Message::setReceiveMode(ModeType mode)
{
	parsingState.mode = mode;
}

RecordInfo Message::getInfo()
{
	return std::move(info);
}

ReceiveMessageType Message::getMessageType() const
{
	return messageType;
}

bool Message::isRecord()
{
	if(ReceiveMessageType::MSG_LOG == messageType
		|| ReceiveMessageType::MSG_AUDIT == messageType
		|| ReceiveMessageType::MSG_JOURNAL == messageType)
	{
		return true;
	}
	return false;
}

Message::~Message()
{
	// All of our members can be allowed to destruct on their own with one exception
	// If a temp payload file exists in the recordInfo - i.e. the recordInfo was created
	// but hasn't been stolen from us via move semantics - delete it
	//
	// This should only occur if we shut down mid-transfer or there is a network timeout
	//
	// There is one exception to this. If
	// 1 - There hasn't yet been an error in parsing
	// 2 - The record type is journal
	// 3 - The mode is archive
	// Skip the removal of the payload file. This record may be resumed
	if(!shouldError()
		&& RecordType::JAL_JOURNAL == parsingState.recordType
		&& ModeType::ARCHIVE == parsingState.mode)
	{
		// Do nothing, allow the payloadFile to remain if it exists
	}
	// Otherwise, if a payload file exists, remove it
	else if(!info.payloadFileName.empty())
	{
		// We don't bother checking this return. If we can't find the file we want to remove it
		// apparently doesn't need to be removed.
		remove(info.payloadFileName.c_str());
		debugOutput(Message::debug, stdout, 
			"~Message Removing file: %s\n", info.payloadFileName.c_str());
		info.payloadFileName.clear();
	}
}
