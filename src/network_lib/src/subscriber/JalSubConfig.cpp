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
#include <libconfig.h>
#include <vector>
#include <string>
#include <stdexcept>

#include <jalop/jal_digest.h>

#include "JalSubEnumTypes.hpp"
#include "JalSubConfig.hpp"

const bool REQUIRED = false;
const bool OPTIONAL = true;

static void handleBoolConfigSetting(
	config_t* root,
	const char* path,
	const bool optional,
	bool& destination)
{
	// Abort if root is NULL
	if(NULL == root)
	{
		throw std::runtime_error("Null config root");
	}

	// Abort if path is NULL
	if(NULL == path)
	{
		throw std::runtime_error("Null config setting path");
	}

	// Lookup the desired setting
	config_setting_t *config_item = config_lookup(root, path);

	// Optional item does not exist, do nothing, return
	if(optional && NULL == config_item)
	{
		return;
	}
	// Required item does not exist, do nothing, return failure
	else if(NULL == config_item)
	{
		throw std::runtime_error("Required config setting: " + std::string(path)
			+ " not present in config file");
	}

	// We know the setting exists, now check if it also satisfies constraints with a more
	// focused lookup.
	int intSetting;
	int lookupStatus = config_lookup_bool(root, path, &intSetting);
	if(CONFIG_FALSE == lookupStatus)
	{
		// CONFIG_FALSE is returned either if the setting is not found or if it doesn't match
		// type constraints. Since we know from above the setting exists, we know it didn't
		// match one of [true|false]
		throw std::runtime_error("Expected one of [true|false] for setting: "
			+ std::string(path));
	}

	// If we get this far, the boolean setting exists and was valid, convert from the integer
	// macro CONFIG_TRUE or CONFIG_FALSE to an appropriate boolean value

	destination = (CONFIG_TRUE == intSetting);
}

static void handleStringConfigSetting(
	config_t* root, // config root
	const char* path, // path to the config settings relative to the config root
	const bool optional, // if false, generates an error if the setting is absent
	std::string& destination) // reference to the string to update on success
{
	// Abort if root is NULL
	if(NULL == root)
	{
		throw std::runtime_error("Null config root");
	}

	// Abort if path is NULL
	if(NULL == path)
	{
		throw std::runtime_error("Null config setting path");
	}

	// Lookup the desired setting
	config_setting_t *config_item = config_lookup(root, path);

	// Optional item does not exist, do nothing, return
	if(optional && NULL == config_item)
	{
		return;
	}
	// Required item does not exist, do nothing, return failure
	else if(NULL == config_item)
	{
		throw std::runtime_error("Required config setting: " + std::string(path)
			+ " not present in config file");
	}

	// Item exists, attempt parse
	// DO NOT FREE stringSetting LIBCONFIG DOES THIS FOR US
	const char* stringSetting = config_setting_get_string(config_item);

	// This would be weird since we know the setting exists, but we'll check anyway
	if(NULL == stringSetting)
	{
		throw std::runtime_error("Failed to retrieve string for config setting: "
			+ std::string(path));
	}
	destination = std::string(stringSetting);
}

static void handleIntConfigSetting(
	config_t* root, // config root
	const char* path, // path to the config setting relative to the config root
	const bool optional, // if false, generates an error if the setting is absent
	int& destination) // reference to the value to update on success
{
	// Abort if root is NULL
	if(NULL == root)
	{
		throw std::runtime_error("Null config root");
	}

	// Abort if path is NULL
	if(NULL == path)
	{
		throw std::runtime_error("Null config setting path encountered parsing config file");
	}

	// Lookup the desired setting
	config_setting_t *config_item = config_lookup(root, path);

	// Optional item does not exist, do nothing, return
	if(optional && NULL == config_item)
	{
		return;
	}
	// Required item does not exist, do nothing, throw
	else if(NULL == config_item)
	{
		throw std::runtime_error("Required config setting: "
			+ std::string(path) + " not found in config file");
	}

	// Item exists, attempt parse
	if(CONFIG_FALSE == config_lookup_int(root, path, &destination))
	{
		// There are technically two ways this can fail - a type-mismatch and failure to
		// find the setting specified by path. Since we already know the setting exists
		// we can assume a failure to parse an int
		throw std::runtime_error("Failed to parse config setting: " + std::string(path)
			+ " Expects integer.");
	}
}

void SubscriberConfig::setDigestAlgorithms(
	std::string digests)
{
	if(digests.empty())
	{
		throw std::runtime_error("Empty string provided as digest algorithms list");
	}

	size_t num_digests = 0;
	enum jal_digest_algorithm* digest_list = NULL;
	enum jal_status status = jal_parse_digest_algorithm_str(
		digests.c_str(),
		&digest_list,
		&num_digests);

	if(JAL_OK != status)
	{
		free(digest_list);
		std::string errMsg = "Failed to parse digest list: " + digests;
		throw std::runtime_error(errMsg);
	}

	if(0 == num_digests)
	{
		free(digest_list);
		std::string errMsg = "Discovered 0 digest algorithms in digest list: " + digests;
		throw std::runtime_error(errMsg);
	}

	allowedConfigureDigest = std::vector<enum jal_digest_algorithm>(
		digest_list,
		digest_list + num_digests);
	free(digest_list);
}

SubscriberConfig::SubscriberConfig(std::string configFilePath)
{
	// This simply provides a destructor so we guarantee the config object is cleaned up
	// no matter how we leave this scope
	struct ConfigHandler
	{
		config_t config;
		ConfigHandler()
		{
			config_init(&config);
		}

		~ConfigHandler()
		{
			config_destroy(&config);
		}
	} handler;

	config_t* config = &(handler.config);

	if(CONFIG_TRUE != config_read_file(config, configFilePath.c_str()))
	{
		std::string errMsg = "Failed to read config file at path: " + configFilePath
			+ " with error at line [" + std::to_string(config_error_line(config)) + "]: "
			+ config_error_text(config) +  ".";
		throw std::runtime_error(errMsg);
	}

	handleStringConfigSetting(config, "address", REQUIRED, ipAddr);
	handleIntConfigSetting(config, "port", REQUIRED, listenPort);
	handleIntConfigSetting(config, "session_limit", REQUIRED, sessionLimit);
	std::string modeString;
	handleStringConfigSetting(config, "mode", REQUIRED, modeString);
	this->mode = modeTypeFromString(modeString);
	handleStringConfigSetting(config, "db_root", REQUIRED, databasePath);
	handleIntConfigSetting(config, "buffer_size", REQUIRED, bufferSize);
	handleBoolConfigSetting(config, "enable_tls", REQUIRED, enableTls);
	handleIntConfigSetting(config, "network_timeout", REQUIRED, networkTimeout);
	if(this->enableTls)
	{
		handleStringConfigSetting(config, "private_key", REQUIRED, tlsConfig.privateKey);
		handleStringConfigSetting(config, "public_cert", REQUIRED, tlsConfig.publicCert);
		handleStringConfigSetting(config, "trust_store", REQUIRED, tlsConfig.trustStore);
	}

	std::string digests;
	handleStringConfigSetting(config, "digest_algorithms", OPTIONAL, digests);
	if(!digests.empty())
	{
		this->setDigestAlgorithms(digests);
	}

	std::string dbTypeStr;
	// Review note - do we want to have a default setting, or make this required?
	handleStringConfigSetting(config, "database_type", OPTIONAL, dbTypeStr);
	if(!dbTypeStr.empty())
	{
		this->dbType = dbTypeFromString(dbTypeStr);
	}
}

void SubscriberConfig::printConfiguration() const
{
	// Take the resulting digest vector and do the equivalent of a .join(JAL_DIGEST_ALGORITHM_DELIMETER)
	// This allows us to see the configured algorithms
	std::string configuredAllowedAlgorithms = "";

	for(auto iter = allowedConfigureDigest.begin(); iter < allowedConfigureDigest.end(); iter++)
	{
		if (allowedConfigureDigest.begin() != iter) {
			configuredAllowedAlgorithms += JAL_DIGEST_ALGORITHM_DELIMETER;
		}

		configuredAllowedAlgorithms += std::string(digest_str[*iter]);
	}

	printf("address: %s\n", ipAddr.c_str());
	printf("port: %d\n", listenPort);
	std::string smode = modeTypeToString(mode);
	printf("mode: %s\n", smode.c_str());
	printf("db_root: %s\n", databasePath.c_str());
	printf("buffer_size: %d\n", bufferSize);
	printf("session_limit: %d\n", sessionLimit);
	printf("network_timeout: %d\n", networkTimeout);
	printf("TLS: %s\n", enableTls ? "enabled" : "disabled");
	if(enableTls)
	{
		printf("Private Key File: %s\n", tlsConfig.privateKey.c_str());
		printf("Public Cert File: %s\n", tlsConfig.publicCert.c_str());
		printf("Trust Store File: %s\n", tlsConfig.trustStore.c_str());
	}
	printf("digest_algorithms: %s\n", configuredAllowedAlgorithms.c_str());
	printf("database_type: %s\n", dbTypeToString(dbType).c_str());
}
