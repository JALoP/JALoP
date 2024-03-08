/**
 * @file test_jal_subscribe.hpp This file contains utility functions used by the
 * tests for the JalSubscriber.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <ftw.h>
#include "JalSubConfig.hpp"
#include "JalSubMessaging.hpp"
#include "JalSubConstants.hpp"
#include "test_jal_subscribe_utils.hpp"

// Provided to nftw to remove all encountered files
static int rmFiles(
	const char* path,
	const struct stat* /*sbuf*/,
	int /*type*/,
	struct FTW* /*ftwb*/)
{
	if(remove(path) < 0)
	{
		return -2;
	}
	return 0;
}

bool recursiveFileRemoval(const std::string path, int maxDepth)
{
	int err = nftw(path.c_str(), rmFiles, maxDepth, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
	if(0 == err)
	{
		return true;
	}
	else
	{
		perror("recursiveFileRemoval Failure");
		return false;
	}
}

// Helper functions for generating specific messages
void populateInit(
	Message& message,
	const std::string& publisherId,
	const std::string& acceptDigest,
	// std::string acceptXMLCompression - not implemented
	const std::string& acceptConfigureDigestChallenge,
	const std::string& type,
	const std::string& mode)
{
	message.addHeader(HEADER_MESSAGE_TYPE, MSG_INIT_STR);
	message.addHeader(HEADER_CONTENT_LENGTH, "0");
	message.addHeader(HEADER_JAL_PUBLISHER_ID_TYPE, publisherId);
	message.addHeader(HEADER_JAL_VERSION_TYPE, "2.0.0.0");
	message.addHeader(HEADER_JAL_ACCEPT_DIGEST, acceptDigest);
	message.addHeader(HEADER_JAL_ACCEPT_CONFIGURE_DIGEST_CHALLENGE,
		acceptConfigureDigestChallenge);
	message.addHeader(HEADER_JAL_RECORD_TYPE, type);
	message.addHeader(HEADER_JAL_MODE_TYPE, mode);

	// Let the message process these headers as if they were just received and
	// set its internal state
	message.processHeaders();
}

bool populateRecordValid(
	Message& message,
	std::string& computedDigest,
	const std::string& sessionId,
	const std::string& jalId,
	const std::vector<uint8_t>& sysMetadata,
	const std::vector<uint8_t>& appMetadata,
	const std::vector<uint8_t>& payload,
	const RecordType& type)
{
	switch(type)
	{
		case RecordType::JAL_AUDIT:
			message.addHeader(HEADER_MESSAGE_TYPE, MSG_AUDIT_STR);
			message.addHeader(HEADER_JAL_AUDIT_LENGTH,
				std::to_string(payload.size()));
			break;
		case RecordType::JAL_LOG:
			message.addHeader(HEADER_MESSAGE_TYPE, MSG_LOG_STR);
			message.addHeader(HEADER_JAL_LOG_LENGTH,
				std::to_string(payload.size()));
			break;
		case RecordType::JAL_JOURNAL:
			message.addHeader(HEADER_MESSAGE_TYPE, MSG_JOURNAL_STR);
			message.addHeader(HEADER_JAL_JOURNAL_LENGTH,
				std::to_string(payload.size()));
			break;
	}
	message.addHeader(HEADER_JAL_SESSION_ID_TYPE, sessionId);
	message.addHeader(HEADER_JAL_ID_TYPE, jalId);

	// Total length of content is appMetadata + sysMetadata + payload
	// + 3*"BREAK"
	std::string BREAK = "BREAK";
	size_t contentLen = appMetadata.size() + sysMetadata.size() + payload.size()
		+ 3*BREAK.size();
	message.addHeader(HEADER_CONTENT_LENGTH, std::to_string(contentLen));

	message.addHeader(HEADER_JAL_APPLICATION_METADATA_LENGTH,
		std::to_string(appMetadata.size()));
	message.addHeader(HEADER_JAL_SYSTEM_METADATA_LENGTH,
		std::to_string(sysMetadata.size()));

	// Let the message process these headers as if they were just received and
	// set its internal state
	message.processHeaders();

	// Add our test data to the message in the order:
	// System Metadata BREAK
	// Application Metadata BREAK
	// payload BREAK
	size_t size = sysMetadata.size();
	message.addData(sysMetadata.data(), &size);
	if(0 != size || message.shouldAbort() || message.shouldError())
	{
		return false;
	}
	size = BREAK.size();
	message.addData((uint8_t*)BREAK.c_str(), &size);
	if(0 != size || message.shouldAbort() || message.shouldError())
	{
		return false;
	}
	size = appMetadata.size();
	message.addData(appMetadata.data(), &size);
	if(0 != size || message.shouldAbort() || message.shouldError())
	{
		return false;
	}
	size = BREAK.size();
	message.addData((uint8_t*)BREAK.c_str(), &size);
	if(0 != size || message.shouldAbort() || message.shouldError())
	{
		return false;
	}
	size = payload.size();
	message.addData(payload.data(), &size);
	if(0 != size || message.shouldAbort() || message.shouldError())
	{
		return false;
	}
	size = BREAK.size();
	message.addData((uint8_t*)BREAK.c_str(), &size);
	if(0 != size || message.shouldAbort() || message.shouldError())
	{
		return false;
	}

	// Finalize the record data, signalling digest computation
	message.finalizeData();
	if(0 != size || message.shouldAbort() || message.shouldError())
	{
		return false;
	}
	computedDigest = message.getDigest();
	return true;
}

bool populateDigestResponse(
	Message& message,
	const std::string& jalId,
	const std::string& sessionId,
	const DigestStatus& expectedStatus)
{
	message.addHeader(HEADER_MESSAGE_TYPE, MSG_DIGEST_CHALLENGE_RESP_STR);
	message.addHeader(HEADER_CONTENT_LENGTH, "0");
	message.addHeader(HEADER_JAL_SESSION_ID_TYPE, sessionId);
	message.addHeader(HEADER_JAL_ID_TYPE, jalId);
	message.addHeader(HEADER_JAL_DIGEST_STATUS, digestStatusToString(expectedStatus));

	// Let the message process these headers as if they were just received and
	// set its internal state
	message.processHeaders();

	if(message.shouldAbort() || message.shouldError())
	{
		return false;
	}

	return true;
}

bool compareHeader(
	const Response& response,
	const char* filename,
	const int lineNo,
	const std::string& header,
	const std::string& expectedValue)
{
	// allow getHeader to throw if the header is missing
	if(response.getHeader(header) != expectedValue)
	{
		fprintf(stderr, "Context: %s:%d. Expected header: %s with value: %s, found %s\n",
			filename, lineNo, header.c_str(), response.getHeader(header).c_str(), expectedValue.c_str());
		return false;
	}
	return true;
}

bool checkInit(
	const Response& response,
	const std::string& digest,
	const std::string& configureDigestChallenge)
{
	std::string nextHeader = HEADER_CONTENT_TYPE;
	try
	{
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, HEADER_CONTENT_TYPE_DEFAULT))
		{
			return false;
		}
		nextHeader = HEADER_MESSAGE_TYPE;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, MSG_INIT_ACK_STR))
		{
			return false;
		}
		nextHeader = HEADER_CONTENT_LENGTH;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, ""))
		{
			return false;
		}
		nextHeader = HEADER_JAL_DIGEST;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, digest))
		{
			return false;
		}
		nextHeader = HEADER_JAL_CONFIGURE_DIGEST_CHALLENGE;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, configureDigestChallenge))
		{
			return false;
		}
	}
	catch(std::runtime_error &e)
	{
		fprintf(stderr, "Context: %s:%d. Expected header: %s not found.\n",
			__FILE__, __LINE__, nextHeader.c_str());
		return false;
	}
	return true;
}

bool checkDigestChallenge(
	const Response& response,
	const std::string& jalId,
	const std::string& computedDigest)
{
	std::string nextHeader = HEADER_CONTENT_TYPE;
	try
	{
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, HEADER_CONTENT_TYPE_DEFAULT))
		{
			return false;
		}
		nextHeader = HEADER_MESSAGE_TYPE;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, MSG_DIGEST_CHALLENGE_STR))
		{
			return false;
		}
		nextHeader = HEADER_CONTENT_LENGTH;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, ""))
		{
			return false;
		}
		nextHeader = HEADER_JAL_ID_TYPE;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, jalId))
		{
			return false;
		}
		nextHeader = HEADER_JAL_DIGEST_VALUE;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, computedDigest))
		{
			return false;
		}
	}
	catch(std::runtime_error &e)
	{
		fprintf(stderr, "Context: %s:%d. Expected header: %s not found.\n",
			__FILE__, __LINE__, nextHeader.c_str());
		return false;
	}
	return true;
}

bool checkSync(
	const Response& response,
	const std::string& jalId)
{
	std::string nextHeader = HEADER_CONTENT_TYPE;
	try
	{
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, HEADER_CONTENT_TYPE_DEFAULT))
		{
			return false;
		}
		nextHeader = HEADER_MESSAGE_TYPE;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, MSG_SYNC_STR))
		{
			return false;
		}
		nextHeader = HEADER_CONTENT_LENGTH;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, ""))
		{
			return false;
		}
		nextHeader = HEADER_JAL_ID_TYPE;
		if(!compareHeader(response, __FILE__, __LINE__, nextHeader, jalId))
		{
			return false;
		}
	}
	catch(std::runtime_error &e)
	{
		fprintf(stderr, "Context: %s:%d. Expected header: %s not found.\n",
			__FILE__, __LINE__, nextHeader.c_str());
		return false;
	}
	return true;
}

TestSubscriberConfig::TestSubscriberConfig(std::string dbRoot)
	: SubscriberConfig()
{
	enableTls = false;
	// tlsConfig is irrelevant with enableTls = false
	// listenPort won't be used by the mock http server
	bufferSize = 4096;
	sessionLimit = 100;
	// httpServerThreadPoolSize unused by the mock http server
	allowedRecordTypes = { "audit", "log", "journal" };
	allowedConfigureDigest = { JAL_DIGEST_ALGORITHM_DEFAULT };
	databasePath = dbRoot;
	mode = ModeType::ARCHIVE;
	networkTimeout = 0;
	dbType = DBType::BDB;
	ipAddr = "0.0.0.0";
	debug = false;
}

const SubscriberConfig& TestSubscriberConfig::getSubscriberConfig()
{
	return *this;
}
