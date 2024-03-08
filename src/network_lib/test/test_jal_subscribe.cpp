/**
 * @file test_jal_subscribe.cpp This file contains tests for the JalSubscriber.
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
#include <string.h>
#include <fcntl.h>

#include "JalSubUtils.hpp"
#include "JalSubConstants.hpp"
#include "JalSubscriber.hpp"
#include "mock_http_server_impl.hpp"
#include "test_jal_subscribe_utils.hpp"
// The mock http server needs storage for a static instance of
// the singleton implementation
std::shared_ptr<MockHttpServer> MockHttpServer::server = nullptr;
#include "mock_db_impl.hpp"
// The mock db server needs storage for a static instance of
// the singleton implementation
std::shared_ptr<MockDb> MockDb::db = nullptr;

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
extern "C" {
#include <test-dept.h>
}
#define __STDC_FORMAT_MACROS

static const std::string TMP_DIR = "/tmp/JalSubUnitTest/";
FILE* testStdout;
int origStdout;
extern "C" void setup()
{
	// our test lib outputs stdout in line with all the dots if a test passes,
	// or outputs stderr in the case that a test fails
	// Redirect stdout to stderr so we see nothing for a pass, and see context
	// information for failures

	// save the original fd for stdout
	origStdout = dup(STDOUT_FILENO);

	// redirect stdout to point to /dev/null
	fflush(stdout);
	dup2(STDERR_FILENO, STDOUT_FILENO);
	if(dirExists(TMP_DIR))
	{
		// 10 levels deep should be more than enough for our purposes
		if(!recursiveFileRemoval(TMP_DIR, 10))
		{
			std::string errMsg = "Failed to clean up previous " + TMP_DIR;
			throw std::runtime_error(errMsg);
		}
	}

	if(!createDir(TMP_DIR))
	{
		std::string errMsg = "Failed to set up " + TMP_DIR + " for unit testing";
		throw std::runtime_error(errMsg);
	}
}

extern "C" void teardown()
{
	// 10 levels deep should be more than enough for our purposes
	if(!recursiveFileRemoval(TMP_DIR, 10))
	{
		std::string errMsg = "Failed to clean up " + TMP_DIR + " after tests";
		throw std::runtime_error(errMsg);
	}
	// restore stdout
	fflush(stdout);
	dup2(origStdout, STDOUT_FILENO);
	close(origStdout);
}

extern "C" void test_init()
{
	TestSubscriberConfig config(TMP_DIR);

	JalSubscriber subscriber(config.getSubscriberConfig(),
		MockDb::MockDbFactory,
		MockHttpServer::MockHttpServerFactory);

	// Get a handle to the singleton mock server
	std::shared_ptr<MockHttpServer> server = MockHttpServer::getServerHandle();
	assert_not_equals(nullptr, server);

	// Get a handle to the singleton mock db
	std::shared_ptr<MockDb> db = MockDb::getDbHandle();
	assert_not_equals(nullptr, db);

	// Due to an issue with the way Messages are handled, a new message object must be
	// created for each transaction and an existing message cannot be reassigned with =
	// Create init message
	Message initMessage;
	populateInit(
		initMessage, // the message to fill
		"00000000-0000-0000-0000-000000000000", // publisherId
		DIGEST_ALGORITHM_SHA_256 + ","
		+ DIGEST_ALGORITHM_SHA_384 + ","
		+ DIGEST_ALGORITHM_SHA_512, // acceptDigest
		"on,off", // acceptConfigureDigestChallenge
		recordTypeToString(RecordType::JAL_AUDIT), // record type
		modeTypeToString(ModeType::ARCHIVE)); // mode

	// Stimulate subscriber with init message, capture init_ack
	Response initResponse = server->sendMessage(initMessage);

	// Validate init_ack
	assert_true(checkInit(initResponse, DIGEST_ALGORITHM_SHA_256, "on"));

	std::string logSessionId = initResponse.getHeader(HEADER_JAL_SESSION_ID_TYPE);

	// Create a log record message
	Message logRecord;
	std::string logRecordJalId = "00000000-0000-0000-0000-000000000001";
	std::string computedDigest;
	std::vector<uint8_t> sysMetadata;
	std::vector<uint8_t> appMetadata;
	std::vector<uint8_t> payload;
	assert_true(populateRecordValid(
		logRecord,
		computedDigest,
		logSessionId,
		logRecordJalId,
		sysMetadata,
		appMetadata,
		payload,
		RecordType::JAL_LOG));

	// Stimulate subscriber with log record, capture digest challenge
	Response logDigestChallenge = server->sendMessage(logRecord);

	// Validate digest challenge
	assert_true(checkDigestChallenge(logDigestChallenge, logRecordJalId, computedDigest));

	// Create digest response message
	Message digestResponse;
	assert_true(populateDigestResponse(
		digestResponse,
		logRecordJalId,
		logSessionId,
		DigestStatus::CONFIRMED));

	// stimulate subscriber with digest response, catpure sync
	Response logSync = server->sendMessage(digestResponse);

	// Validate sync message
	assert_true(checkSync(logSync, logRecordJalId));

	// Check for existence of record with jalId in test db
	assert(db->checkForRecord(logRecordJalId));
}
