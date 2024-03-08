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
#include <random>
#include <exception>
#include <mutex>
#include <shared_mutex>
#include <memory>

#include "JalSubscriber.hpp"
#include "JalSubConfig.hpp"
#include "JalSubUtils.hpp"
#include "JalSubBerkeleyDb.hpp"
#include "JalSubFsDb.hpp"

// TODO: Replace with libuuid or similar
// This implementation is "insufficiently random" according to some research into
// mt19937_gen
static std::string generateNewUuid()
{
	static std::random_device rd;
	static std::mt19937 gen(rd());
	static std::uniform_int_distribution<> dis(0,15);
	static std::uniform_int_distribution<> dis2(8,11);

	std::stringstream ss;
	int i;

	ss << std::hex;
	for(i = 0; i < 8; i++)
	{
		ss << dis(gen);
	}

	ss << "-";
	for(i = 0; i < 4; i++)
	{
		ss << dis(gen);
	}

	ss << "-4";
	for(i = 0; i < 3; i++)
	{
		ss << dis(gen);
	}

	ss << "-";
	ss<< dis2(gen);
	for(i = 0; i < 3; i++)
	{
		ss << dis(gen);
	}

	ss << "-";
	for(i = 0; i < 12; i++)
	{
		ss << dis(gen);
	}
	return ss.str();
}

// Helper to remove oldest session from the active session list
void JalSubscriber::pruneOldestSession()
{
	std::string oldestKey = "";
	std::chrono::time_point<std::chrono::steady_clock> tp;
	// obtain exclusive access to the session list before modifying
	// released when the lock goes out of scope
	std::unique_lock lock(sessionsMutex);
	for( auto const& [key, value] : activeSessions)
	{
		if(oldestKey.empty())
		{
			oldestKey = key;
			tp = value.getLastAccess();
			continue;
		}
		else
		{
			if(value.getLastAccess() < tp)
			{
				oldestKey = key;
				tp = value.getLastAccess();
			}
		}
	}
	activeSessions.erase(oldestKey);
}

Response generateSessFailure(
	const Message& message,
	std::string uuid,
	std::string errorMessage)
{
	Response response;
	response.addHeader(HEADER_JAL_SESSION_ID_TYPE, uuid);
	response.addHeader(HEADER_JAL_ERROR_MESSAGE_TYPE, errorMessage);

	// If the incoming message had a JAL-Id, include it in the session failure message
	std::string id = message.getHeader(HEADER_JAL_ID_TYPE);
	if(!id.empty())
	{
		response.addHeader(HEADER_JAL_ID_TYPE, id);
	}
	return response;
}

// This callback is used by the httpServer to associate a given incoming message with
// the digest algorithm to use during payload receipt
// Throws out_of_range if there is no matching session or the HEADER_JAL_SESSION_ID_TYPE
// header is missing
enum jal_digest_algorithm JalSubscriber::getDigestAlgorithm(const Message& message)
{
	std::string uuid = message.getHeader(HEADER_JAL_SESSION_ID_TYPE);
	// Obtain a read-lock on the session list.
	std::shared_lock lock(sessionsMutex);
	return activeSessions.at(uuid).getDigestAlgorithm();
}

// This callback is used by the httpServer to associate a given incoming message with
// the publisherId to use during payload receipt
// Throws out_of_range if there is no matching session or the HEADER_JAL_SESSION_ID_TYPE
// header is missing
std::string JalSubscriber::getPublisherId(const Message& message)
{
	std::string uuid = message.getHeader(HEADER_JAL_SESSION_ID_TYPE);
	// Obtain a read-lock on the session list.
	std::shared_lock lock(sessionsMutex);
	return activeSessions.at(uuid).getPublisherId();
}

// This callback is used by the httpServer to associate a given incoming message with
// the receive mode to use during payload receipt
// Throws out_of_range if there is no matching session or the HEADER_JAL_SESSION_ID_TYPE
// header is missing
ModeType JalSubscriber::getReceiveMode(const Message& message)
{
	std::string uuid = message.getHeader(HEADER_JAL_SESSION_ID_TYPE);
	// Obtain a read-lock on the session list.
	std::shared_lock lock(sessionsMutex);
	return activeSessions.at(uuid).getReceiveMode();
}

// This callback is used by the httpServer to notify the subscriber that a particular
// http exchange has timed out - signalling that we should assume that session has been
// discontinued by a misbehaving publisher, power outage, or network outage
// Supressing the potential exception generated by a missing session. There's nothing to be
// done about it
void JalSubscriber::notifyTimeout(Message& message)
{
	// First, let the message know it is being destroyed because of a timeout
	message.notifyTimeout();

	try
	{
		std::string uuid = message.getHeader(HEADER_JAL_SESSION_ID_TYPE);
		// Obtain an exclusive-lock on the session list.
		std::unique_lock lock(sessionsMutex);
		activeSessions.erase(uuid);
	}
	catch(...)
	{
		// Always print, this should really never happen. There's nothing to be done anyway.
		// We're only here because the publisher isn't listening anymore and we apparently
		// don't know which session this message belongs to
		fprintf(stderr, "Failed to cleanly handle timeout.\n");
	}
}

// This is the callback that will be invoked by the httpServer upon receipt of a message
// Take care with any shared data, such as the active sessions list. Each message
// will be handled in a separate thread, potentially concurrently
// Determine the message type and uuid for the connection (if any) then defer
// to the session message handler
Response JalSubscriber::messageHandler(const Message& message)
{
	Response response;

	// The message type is extracted during pre-parsing
	ReceiveMessageType type = message.getMessageType();

	// At this point, we have a valid message Type, figure out who its for
	std::string uuid;
	// If the messageType is initialize, create a new session to handle it
	if(ReceiveMessageType::MSG_INIT == type)
	{
		// Uniquely identify this new session by the UUID we generate for the JAL-Session-Id
		// There's an extremely low chance of uuid collision, but we'll make sure we don't already
		// have a session by this uuid and retry until we get a new one
		// TODO: Put a limit on this so it can't run forever - probably generate a NACK after X retries
		do
		{
			uuid = generateNewUuid();
		} while(activeSessions.find(uuid) != activeSessions.end());
		// If this session would put us over the sesion limit, first prune the oldest
		// current session
		// This cast is safe because the config setting for sessionLimit cannot be < 0
		if(activeSessions.size() > (size_t)config.sessionLimit)
		{
			// locks the sessionList internally
			pruneOldestSession();
		}
		// Obtain an exclusive-lock on the session list.
		std::unique_lock lock(sessionsMutex);
		activeSessions.emplace(
			std::make_pair(uuid, Session(uuid, jdb, config)));
	}
	// Else, hand off the message to an existing session
	else
	{
		uuid = message.getHeader(HEADER_JAL_SESSION_ID_TYPE);
	}

	// Dispatch message handling to the appropriate session
	try
	{
		// Obtain a read-lock on the session list.
		std::shared_lock lock(sessionsMutex);
		response = activeSessions.at(uuid).handleMessage(type, message);
	}
	catch(std::out_of_range& e)
	{
		// This can only happen on non-init calls
		// Return a "Session Failure Message"
		debugOutput(config.debug, stderr, "generating session failure\n");
		return generateSessFailure(message, uuid, JAL_UNSUPPORTED_SESSION_ID);
	}

	// In the case of a close session message, remove it from the active session list after
	// handling
	if(ReceiveMessageType::MSG_CLOSE_SESSION == type)
	{
		// Obtain an exclusive-lock on the session list.
		std::unique_lock lock(sessionsMutex);
		activeSessions.erase(uuid);
	}

	for(const auto& header : response.getHeaders())
	{
		debugOutput(config.debug, stdout,
			"send header: %s:%s\n", header.first.c_str(), header.second.c_str());
	}
	return response;
}


JalSubscriber::JalSubscriber(
	SubscriberConfig paramConfig) : config(paramConfig)
{
	// HttpServer not specified in this constructor, default to LibMicroHttpdServer
	std::function<std::shared_ptr<HttpServer>(
		std::vector<std::string>,
		SubscriberCallbacks,
		SubscriberConfig)> serverFactory =
		&LibMicroHttpdServer::factory;

	// DB type not specified in this constructor, use option in provided config
	std::function<std::shared_ptr<JalSubDatabase>(SubscriberConfig)> dbFactory;

	switch(paramConfig.dbType)
	{
		case DBType::BDB:
			dbFactory = BerkeleyDb::berkeleyDbFactory;
			break;
		case DBType::FS:
			dbFactory = FsDb::fsDbFactory;
			break;
		// Purposely omitting the default statement, if any valid value of the enum
		// is ever not covered, we want the compiler to complain
	}

	constructorImpl(paramConfig, dbFactory, serverFactory);
}

JalSubscriber::JalSubscriber(
	SubscriberConfig paramConfig,
	std::function<std::shared_ptr<JalSubDatabase>(SubscriberConfig)> dbFactory)
	: config(paramConfig)
{
	// HttpServer not specified in this constructor, default to LibMicroHttpdServer
	std::function<std::shared_ptr<HttpServer>(
		std::vector<std::string>,
		SubscriberCallbacks,
		SubscriberConfig)> serverFactory =
		&LibMicroHttpdServer::factory;

	constructorImpl(paramConfig, dbFactory, serverFactory);
}

JalSubscriber::JalSubscriber(
	SubscriberConfig paramConfig,
	std::function<std::shared_ptr<HttpServer>(
		std::vector<std::string>,
		SubscriberCallbacks,
		SubscriberConfig)> serverFactory)
	: config(paramConfig)
{
	std::function<std::shared_ptr<JalSubDatabase>(SubscriberConfig)> dbFactory;

	// DB type not specified in this constructor, use option in provided config
	switch(paramConfig.dbType)
	{
		case DBType::BDB:
			dbFactory = BerkeleyDb::berkeleyDbFactory;
			break;
		case DBType::FS:
			dbFactory = FsDb::fsDbFactory;
			break;
		// Purposely omitting the default statement, if any valid value of the enum
		// is ever not covered, we want the compiler to complain
	}
	constructorImpl(paramConfig, dbFactory, serverFactory);
}

JalSubscriber::JalSubscriber(
	SubscriberConfig paramConfig,
	std::function<std::shared_ptr<JalSubDatabase>(SubscriberConfig)> dbFactory,
	std::function<std::shared_ptr<HttpServer>(
		std::vector<std::string>,
		SubscriberCallbacks,
		SubscriberConfig)> serverFactory)
	: config(paramConfig)
{
	constructorImpl(paramConfig, dbFactory, serverFactory);
}

void JalSubscriber::constructorImpl(
	SubscriberConfig paramConfig,
	std::function<std::shared_ptr<JalSubDatabase>(SubscriberConfig)> dbFactory,
	std::function<std::shared_ptr<HttpServer>(
		std::vector<std::string>,
		SubscriberCallbacks,
		SubscriberConfig)> serverFactory)
{
	// Apply configuration options to message class
	Message::setBufferSize(paramConfig.bufferSize);
	// Test that the specified databasePath exists to provide a clearer error message
	// in some cases
	if(!dirExists(paramConfig.databasePath))
	{
		std::string errMsg = "Selected db_root: " + paramConfig.databasePath 
			+ " does not exist.";
			throw std::runtime_error(errMsg);
	}
	Message::setTempFilePath(paramConfig.databasePath + "/staging");
	Message::setDebug(paramConfig.debug);

	// Initialize database
	this->jdb = dbFactory(paramConfig);
	
	// Initialize httpServer
	this->httpServer = serverFactory(
		{}, // parameter currently unused
				// provides future support for allowing only producers with specific ips
		{ std::bind(&JalSubscriber::messageHandler,
			this, std::placeholders::_1),
			std::bind(&JalSubscriber::getDigestAlgorithm,
			this, std::placeholders::_1),
			std::bind(&JalSubscriber::getPublisherId,
			this, std::placeholders::_1),
			std::bind(&JalSubscriber::getReceiveMode,
			this, std::placeholders::_1),
			std::bind(&JalSubscriber::notifyTimeout,
			this, std::placeholders::_1)
		},
		paramConfig);
}
