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
#ifndef __JAL__SUB__CONFIG__H__
#define __JAL__SUB__CONFIG__H__

#include <vector>
#include <string>

#include <jalop/jal_digest.h>

#include "JalSubEnumTypes.hpp"

// Configuration settings for the Subscriber
struct SubscriberConfig
{
	public:
	bool enableTls = false;
	struct TlsConfig
	{
		std::string privateKey;
		std::string publicCert;
		std::string trustStore;
	} tlsConfig;

	// Config File Settings
	int listenPort;
	int bufferSize;
	int sessionLimit;
	unsigned int httpServerThreadPoolSize;
	std::vector<std::string> allowedRecordTypes;
	// Default to supporting only the required SHA_256 digest algorithm
	std::vector<enum jal_digest_algorithm> allowedConfigureDigest = 
		{ JAL_DIGEST_ALGORITHM_DEFAULT };
	std::string databasePath;
	ModeType mode;
	int networkTimeout;
	// Default to BerkeleyDB storage
	DBType dbType = DBType::BDB;
	// Default to listen on all addresses
	std::string ipAddr = "0.0.0.0";
	
	// CLI Only Settings
	bool debug;
	
	SubscriberConfig(std::string configFilePath);

	void printConfiguration() const;
	void setDigestAlgorithms(std::string digests);

	// Make the no-arg constructor protected
	// This may be useful for customer-made extensions that want to circumvent the
	// file-parsing constructor and test code, but is not intended to be called directly
	// in the context of the library
	protected:
	SubscriberConfig() {};
};

#endif
