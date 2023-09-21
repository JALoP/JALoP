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

#include <string>
#include <JalSubConfig.hpp>
#include <JalSubscriber.hpp>
#include <JalSubscribe.h>
#include <jalop/jal_status.h>

struct SubscriberConfig_t* jal_subscriber_config_create(
	const char* configFile,
	char** errBuf)
{
	if(NULL != errBuf)
	{
		*errBuf = NULL;
	}

	if(NULL == configFile)
	{
		if(NULL != errBuf)
		{
			std::string errMsg = "NULL config file provided to jal_subscriber_config_create";
			*errBuf = strdup(errMsg.c_str());
		}
		return NULL;
	}
	SubscriberConfig* config;
	try
	{
		config = new SubscriberConfig(std::string(configFile));
	}
	catch(std::exception& e)
	{
		if(NULL != errBuf)
		{
			*errBuf = strdup(e.what());
		}
		return NULL;
	}
	return reinterpret_cast<struct SubscriberConfig_t*>(config);
}

void jal_subscriber_config_destroy(struct SubscriberConfig_t** config)
{
	if(NULL == config)
	{
		return;
	}
	delete reinterpret_cast<SubscriberConfig*>(*config);
	*config = NULL;
}

struct Subscriber_t* jal_subscriber_create(
	const struct SubscriberConfig_t* config,
	char** errBuf)
{
	if(NULL != errBuf)
	{
		*errBuf = NULL;
	}

	if(NULL == config)
	{
		if(NULL != errBuf)
		{
			std::string errMsg = "NULL config provided to jal_subscriber_create";
			*errBuf = strdup(errMsg.c_str());
		}
		return NULL;
	}

	const SubscriberConfig* jalSubConfig = reinterpret_cast<const SubscriberConfig*>(config);
	if(NULL == jalSubConfig)
	{
		if(NULL != errBuf)
		{
			std::string errMsg = "Error handling config provided to jal_subscriber_create";
			*errBuf = strdup(errMsg.c_str());
		}
		return NULL;
	}

	JalSubscriber* subscriber;
	try
	{
		subscriber = new JalSubscriber(*jalSubConfig);
	}
	catch(std::exception& e)
	{
		if(NULL != errBuf)
		{
			*errBuf = strdup(e.what());
		}
		return NULL;
	}
	return reinterpret_cast<Subscriber_t*>(subscriber);
}

void jal_subscriber_destroy(struct Subscriber_t** subscriber)
{
	if(NULL == subscriber)
	{
		return;
	}
	delete reinterpret_cast<JalSubscriber*>(*subscriber);
	*subscriber = NULL;
}

void jal_subscriber_config_print_configuration(const struct SubscriberConfig_t* config)
{
	if(NULL == config)
	{
		return;
	}
	const SubscriberConfig* jalSubConfig = reinterpret_cast<const SubscriberConfig*>(config);

	if(NULL == jalSubConfig)
	{
		return;
	}

	jalSubConfig->printConfiguration();
}

enum jal_status jal_subscriber_config_set_port(
	struct SubscriberConfig_t* config,
	const int portno)
{
	if(NULL == config)
	{
		return JAL_E_INVAL;
	}
	SubscriberConfig* jalSubConfig = reinterpret_cast<SubscriberConfig*>(config);

	if(NULL == jalSubConfig)
	{
		return JAL_E_INVAL;
	}

	jalSubConfig->listenPort = portno;
	return JAL_OK;
}

enum jal_status jal_subscriber_config_set_database_path(
	struct SubscriberConfig_t* config,
	const char* databasePath)
{
	if(NULL == config)
	{
		return JAL_E_INVAL;
	}
	SubscriberConfig* jalSubConfig = reinterpret_cast<SubscriberConfig*>(config);

	if(NULL == jalSubConfig)
	{
		return JAL_E_INVAL;
	}

	jalSubConfig->databasePath = std::string(databasePath);
	return JAL_OK;
}

enum jal_status jal_subscriber_config_set_mode(
	struct SubscriberConfig_t* config,
	const char* modeStr)
{
	if(NULL == config)
	{
		return JAL_E_INVAL;
	}
	SubscriberConfig* jalSubConfig = reinterpret_cast<SubscriberConfig*>(config);

	if(NULL == jalSubConfig)
	{
		return JAL_E_INVAL;
	}

	try
	{
		jalSubConfig->mode = modeTypeFromString(std::string(modeStr));
	}
	catch(std::exception &e)
	{
		return JAL_E_INVAL;
	}
	return JAL_OK;
}

enum jal_status jal_subscriber_config_set_debug(
	struct SubscriberConfig_t* config,
	const int debug)
{
	if(NULL == config)
	{
		return JAL_E_INVAL;
	}
	SubscriberConfig* jalSubConfig = reinterpret_cast<SubscriberConfig*>(config);

	if(NULL == jalSubConfig)
	{
		return JAL_E_INVAL;
	}

	if(debug)
	{
		jalSubConfig->debug = true;;
	}
	else
	{
		jalSubConfig->debug = false;
	}
	return JAL_OK;
}

enum jal_status jal_subscriber_config_set_digest_algorithms(
	struct SubscriberConfig_t* config,
	const char* digestAlgorithmsStr)
{
	if(NULL == config)
	{
		return JAL_E_INVAL;
	}
	SubscriberConfig* jalSubConfig = reinterpret_cast<SubscriberConfig*>(config);

	if(NULL == jalSubConfig)
	{
		return JAL_E_INVAL;
	}

	try
	{
		jalSubConfig->setDigestAlgorithms(digestAlgorithmsStr);
	}
	catch(std::exception &e)
	{
		return JAL_E_INVAL;
	}
	return JAL_OK;
}

enum jal_status jal_subscriber_config_set_tls(
	struct SubscriberConfig_t* config,
	const int tls)
{
	if(NULL == config)
	{
		return JAL_E_INVAL;
	}
	SubscriberConfig* jalSubConfig = reinterpret_cast<SubscriberConfig*>(config);

	if(NULL == jalSubConfig)
	{
		return JAL_E_INVAL;
	}

	if(tls)
	{
		jalSubConfig->enableTls = true;;
	}
	else
	{
		jalSubConfig->enableTls = false;
	}
	return JAL_OK;
}

enum jal_status jal_subscriber_config_set_db_type(
	struct SubscriberConfig_t* config,
	enum DB_Type dbType)
{
	if(NULL == config)
	{
		return JAL_E_INVAL;
	}
	SubscriberConfig* jalSubConfig = reinterpret_cast<SubscriberConfig*>(config);

	if(NULL == jalSubConfig)
	{
		return JAL_E_INVAL;
	}

	if(DB_TYPE_BDB == dbType)
	{
		jalSubConfig->dbType = DBType::BDB;
	}
	else if(DB_TYPE_FS == dbType)
	{
		jalSubConfig->dbType = DBType::FS;
	}
	else
	{
		return JAL_E_INVAL;
	}
	return JAL_OK;
}

enum jal_status jal_subscriber_config_set_server_ip(
	struct SubscriberConfig_t* config,
	const char* addr)
{
	if(NULL == config)
	{
		return JAL_E_INVAL;
	}
	SubscriberConfig* jalSubConfig = reinterpret_cast<SubscriberConfig*>(config);

	if(NULL == jalSubConfig)
	{
		return JAL_E_INVAL;
	}

	if(NULL == addr)
	{
		return JAL_E_INVAL;
	}

	if(0 == strlen(addr))
	{
		return JAL_E_INVAL;
	}
	jalSubConfig->ipAddr = std::string(addr);
	return JAL_OK;
}
