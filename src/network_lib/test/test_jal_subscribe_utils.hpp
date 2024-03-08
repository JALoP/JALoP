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
#pragma once

bool recursiveFileRemoval(
	const std::string,
	int maxDepth);

// Helper functions for generating specific messages
void populateInit(
	Message& message,
	const std::string& publisherId,
	const std::string& acceptDigest,
	// std::string acceptXMLCompression - not implemented
	const std::string& acceptConfigureDigestChallenge,
	const std::string& type,
	const std::string& mode);

bool populateRecordValid(
	Message& logRecord,
	std::string& computedDigest,
	const std::string& sessionId,
	const std::string& jalId,
	const std::vector<uint8_t>& sysMetadata,
	const std::vector<uint8_t>& appMetadata,
	const std::vector<uint8_t>& payload,
	const RecordType& type);

bool populateDigestResponse(
	Message& message,
	const std::string& jalId,
	const std::string& sessionId,
	const DigestStatus& status);

bool checkInit(
	const Response& response,
	const std::string& digest,
	const std::string& configureDigestChallenge);

bool checkDigestChallenge(
	const Response& response,
	const std::string& jalId,
	const std::string& computedDigest);

bool checkSync(
	const Response& response,
	const std::string& jalId);

bool compareHeader(
	const Response& response,
	const char* filename,
	const int lineNo,
	const std::string& header,
	const std::string& expectedValue);

SubscriberConfig generateDefaultConfig(const std::string& configDir);

struct TestSubscriberConfig : public SubscriberConfig
{
	// Explicitly set all members to friendly defaults for unit testing
	TestSubscriberConfig(std::string dbRoot);

	// Return a const reference to this, but with the base class's type
	// All the extra Test bits will be hidden, allowing us to pass an object
	// of type SubscriberConfig into our library objects. These objects
	// make local copies of the config, which will cause slicing and they end up
	// with only a coherent SubscriberConfig
	const SubscriberConfig& getSubscriberConfig();
};
