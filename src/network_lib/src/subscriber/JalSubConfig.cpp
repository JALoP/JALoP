/**
 * @file
 *
 * @brief The JAL subscriber config handling class
 *
 * ### LICENSE
 *
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
#include "jal_config.h"
#include <vector>
#include <string>
#include <stdexcept>

#include <jalop/jal_digest.h>
#include <jal_config.h>

#include "JalSubEnumTypes.hpp"
#include "JalSubConfig.hpp"

const bool REQUIRED = false;
const bool OPTIONAL = true;

static void handleBoolConfigSetting(
	config_setting_t* root,
	const char* path,
	const bool optional,
	bool& destination)
{
	int value = 0;
	if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
		root,
		path,
		&value,
		optional ? JAL_CFG_OPTIONAL : JAL_CFG_REQUIRED))
	{
		throw std::runtime_error("Expected one of [true|false] for setting: "
			+ std::string(path));
	}
	destination = (CONFIG_TRUE == value);
}

static void handleStringListConfigSetting(
	config_setting_t* root, // config root
	const char* path, // path to the config settings relative to the config root
	const bool optional, // if false, generates an error if the setting is absent
	std::vector<std::string>& destination) // reference to the vector of string to update on success
{
	int listLen = 0;
	config_setting_t* settingList = NULL;
	if(JAL_CFG_SUCCESS != jal_config_lookup_list(
		root,
		path,
		&settingList,
		&listLen,
		optional ? JAL_CFG_OPTIONAL : JAL_CFG_REQUIRED))
	{
		throw std::runtime_error("Failed to parse config list/array: " + std::string(path));
	}
	// If we get here, but settingList isn't set to anything, this setting was optional
	// Do nothing and return success
	if(NULL == settingList)
	{
		return;
	}

	// Otherwise, we have a list of some length
	std::vector<std::string> newList;
	for(int i = 0; i < listLen; i++)
	{
		// This pointer must not be freed by the caller - managed by libConfig
		const char* listElemStr = config_setting_get_string_elem(settingList, i);
		if(NULL == listElemStr)
		{
			std::string errMsg = "Failed to extract element: " + std::to_string(i)
				+ " from list for setting: " + path;
			throw std::runtime_error(errMsg);
		}
		newList.push_back(std::string(listElemStr));
	}
	// Only if we got all the way through, copy our results to the out-param
	destination = newList;
}

static void handleStringConfigSetting(
	config_setting_t* root, // config root
	const char* path, // path to the config settings relative to the config root
	const bool optional, // if false, generates an error if the setting is absent
	std::string& destination) // reference to the string to update on success
{
	// Defer to jal_config to extract a C string from the config
	char* value = NULL;
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		path,
		&value,
		optional ? JAL_CFG_OPTIONAL : JAL_CFG_REQUIRED))
	{
		throw std::runtime_error("Failed to retrieve string for config setting: "
			+ std::string(path));
	}

	//Only set if not null, otherwise default to ""
	if (NULL != value)
	{
		destination = std::string(value);
		free(value);
	}
	else
	{
		destination = "";
	}
}

static void handleIntConfigSetting(
	config_setting_t* root, // config root
	const char* path, // path to the config setting relative to the config root
	const bool optional, // if false, generates an error if the setting is absent
	int& destination) // reference to the value to update on success
{
	if(JAL_CFG_SUCCESS != jal_config_lookup_int(
		root,
		path,
		&destination,
		optional ? JAL_CFG_OPTIONAL : JAL_CFG_REQUIRED))
	{
		throw std::runtime_error("Failed to retrieve int for config setting: "
			+ std::string(path));
	}
}

static void handleUIntConfigSetting(
	config_setting_t* root, // config root
	const char* path, // path to the config setting relative to the config root
	const bool optional, // if false, generates an error if the setting is absent
	unsigned int& destination) // reference to the value to update on success
{
	// defer to get int, then check against negative numbers
	int maybeNegative;
	handleIntConfigSetting(root, path, optional, maybeNegative);

	if(0 > maybeNegative)
	{
		throw std::runtime_error("Failed to parse config setting: " + std::string(path)
			+ " Expected positive integer.");
	}
	else
	{
		destination = (unsigned int)maybeNegative;
	}
}

static void handleLongLongConfigSetting(
	config_setting_t* root, // config root
	const char* path, // path to the config setting relative to the config root
	const bool optional, // if false, generates an error if the setting is absent
	long long& destination) // reference to the value to update on success
{
	if(JAL_CFG_SUCCESS != jal_config_lookup_int64(
		root,
		path,
		&destination,
		optional ? JAL_CFG_OPTIONAL : JAL_CFG_REQUIRED))
	{
		throw std::runtime_error("Failed to retrieve long long for config setting: "
			+ std::string(path));
	}
}

void SubscriberConfig::setAllowedRecordTypes(
		const std::vector<std::string>& recordTypes)
{
	std::vector<RecordType> convertedTypes;
	for(const auto& type : recordTypes)
	{
		// Will throw if we have a string we don't expect - let it
		convertedTypes.push_back(recordTypeFromString(type));
	}
	this->allowedRecordTypes = convertedTypes;
}

void SubscriberConfig::setDigestAlgorithms(
	const std::string& digests)
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

void SubscriberConfig::setDatabaseOption(
	const std::string& database_option)
{
	#ifdef JALDB_TYPE_LMDB
	//Default to JDB_NONE if empty
	if(database_option.empty())
	{
		jdb_flags = JDB_NONE;
	}
	else
	{
		if(JALDB_OK != jaldb_get_db_flags(database_option.c_str(), &jdb_flags))
		{
			std::string errMsg = "Failed to parse database option: " + database_option;
			throw std::runtime_error(errMsg);
		}
	}
	#else
	(void)database_option;
	jdb_flags = JDB_NONE;
	#endif
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
			if(JAL_CFG_SUCCESS != jal_config_init(&config))
			{
				std::string errMsg = "Failed to initialize config_t";
				throw std::runtime_error(errMsg);
			}
		}

		~ConfigHandler()
		{
			config_destroy(&config);
		}
	} handler;

	config_t* config = &(handler.config);

	if(JAL_CFG_SUCCESS != jal_config_read_file(config, configFilePath.c_str()))
	{
		std::string errMsg = "Failed to read config file at path: " + configFilePath
			+ " with error at line [" + std::to_string(config_error_line(config)) + "]: "
			+ config_error_text(config) +  ".";
		throw std::runtime_error(errMsg);
	}

	// Extract root configuration setting
	config_setting_t *root = config_root_setting(config);

	handleStringConfigSetting(root, "address", REQUIRED, ipAddr);
	handleIntConfigSetting(root, "port", REQUIRED, listenPort);
	handleIntConfigSetting(root, "session_limit", REQUIRED, sessionLimit);
	std::string modeString;
	handleStringConfigSetting(root, "mode", REQUIRED, modeString);
	this->mode = modeTypeFromString(modeString);
	handleStringConfigSetting(root, "db_root", REQUIRED, databasePath);
	handleIntConfigSetting(root, "buffer_size", REQUIRED, bufferSize);
	handleBoolConfigSetting(root, "enable_tls", REQUIRED, enableTls);
	handleIntConfigSetting(root, "network_timeout", REQUIRED, networkTimeout);
	handleUIntConfigSetting(root, "http_server_thread_pool_size",
		REQUIRED, httpServerThreadPoolSize);
	// Additionally require httpServerThreadPoolSize > 0
	if(httpServerThreadPoolSize < 1)
	{
		std::string errMsg = "http_server_thread_pool_size must be at least 1";
		throw std::runtime_error(errMsg);
	}

	if(this->enableTls)
	{
		handleStringConfigSetting(root, "private_key", REQUIRED, tlsConfig.privateKey);
		handleStringConfigSetting(root, "public_cert", REQUIRED, tlsConfig.publicCert);
		handleStringConfigSetting(root, "trust_store", REQUIRED, tlsConfig.trustStore);
		std::string clientCertValidationString;
		handleStringConfigSetting(root, "client_certificate_validation", REQUIRED, clientCertValidationString);
		tlsConfig.clientCertValidation = clientCertValidationFromString(clientCertValidationString);
	}

	std::string digests;
	handleStringConfigSetting(root, "digest_algorithms", OPTIONAL, digests);
	if(!digests.empty())
	{
		this->setDigestAlgorithms(digests);
	}

	//Parses database option (only in lmdb build)
	#ifdef JALDB_TYPE_LMDB
	handleStringConfigSetting(root, "database_option", OPTIONAL, database_option_str);

	//Default to "JDB_NONE" if entry not present in the config file
	if (database_option_str.empty())
	{
		database_option_str = JDB_NONE_STR;
	}

	#else
		//In BDB build, the database_option field is not used and is default to "JDB_NONE" by passing in empty string
		database_option_str = "";
	#endif
	this->setDatabaseOption(database_option_str);

	std::string dbTypeStr;
	// Default to database storage if not present
	handleStringConfigSetting(root, "database_type", OPTIONAL, dbTypeStr);
	if(!dbTypeStr.empty())
	{
		this->dbType = dbTypeFromString(dbTypeStr);
	}
	else
	{
		this->dbType = DBType::JALDB;
	}

	std::vector<std::string> recordTypes;
	handleStringListConfigSetting(root, "record_type", REQUIRED, recordTypes);
	// Sanity check against an empty but present record_type settings
	if(0 >= recordTypes.size())
	{
		throw std::runtime_error("record_type contains no elements");
	}
	this->setAllowedRecordTypes(recordTypes);

	handleLongLongConfigSetting(root, "journal_resume_threshold_size", OPTIONAL,
		journalResumeThresholdSize);

	//Expands all file path config entries
	if (!this->expandAllFilePaths())
	{
		throw std::runtime_error("Failed to resolve file path entry in config file");
	}
}

bool SubscriberConfig::expandAllFilePaths()
{
	//Expands all filepaths
	if(this->enableTls)
	{
		char *expanded_priv_key_path = jal_expand_path(tlsConfig.privateKey.c_str(), "private_key");
		if (expanded_priv_key_path == NULL)
		{
			return false;
		}

		tlsConfig.privateKey = std::string(expanded_priv_key_path);
		free(expanded_priv_key_path);

		char *expanded_pub_cert_path = jal_expand_path(tlsConfig.publicCert.c_str(), "public_cert");
		if (expanded_pub_cert_path == NULL)
		{
			return false;
		}
		tlsConfig.publicCert = std::string(expanded_pub_cert_path);
		free(expanded_pub_cert_path);

		char *expanded_truststore_path = jal_expand_path(tlsConfig.trustStore.c_str(), "trust_store");
		if (expanded_truststore_path == NULL)
		{
			return false;
		}
		tlsConfig.trustStore = std::string(expanded_truststore_path);
		free(expanded_truststore_path);
	}

	char *expanded_db_path = jal_expand_path(databasePath.c_str(), "db_root");
	if (expanded_db_path == NULL)
	{
		return false;
	}
	databasePath = std::string(expanded_db_path);
	free(expanded_db_path);

	return true;
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

	std::string configuredAllowedRecordTypes = "[";
	for(const auto& type : allowedRecordTypes)
	{
		configuredAllowedRecordTypes += "\"" + recordTypeToString(type) + "\",";
	}
	configuredAllowedRecordTypes += "]";

	printf("address: %s\n", ipAddr.c_str());
	printf("port: %d\n", listenPort);
	std::string smode = modeTypeToString(mode);
	printf("record_type: %s\n", configuredAllowedRecordTypes.c_str());
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
		std::string clientCertValidation = clientCertValidationToString(tlsConfig.clientCertValidation);
		printf("Client Certificate Validation: %s\n", clientCertValidation.c_str());
	}
	printf("digest_algorithms: %s\n", configuredAllowedAlgorithms.c_str());
	printf("database_type: %s\n", dbTypeToString(dbType).c_str());

	#ifdef JALDB_TYPE_LMDB
	printf("database_option: %s\n", database_option_str.c_str());
	#endif
	printf("http_server_thread_pool_size: %d\n", httpServerThreadPoolSize);
}
