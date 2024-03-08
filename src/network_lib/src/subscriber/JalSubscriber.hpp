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
#ifndef __JAL_SUBSCRIBER__H__
#define __JAL_SUBSCRIBER__H__

#include <memory> // smart pointers
#include <vector>
#include <string>
#include <shared_mutex>

#include "JalSubConfig.hpp"
#include "JalSubSession.hpp"
#include "JalSubNetworkLayer.hpp"
#include "JalSubEnumTypes.hpp"
#include "JalSubDatabase.hpp"

// This class manages the resources and execution flow of a single
// subscriber. It is primarily responsible for serializing requests to
// the database, managing the http server, and keeping track of active sessions

class JalSubscriber
{
	private:
	// Config settings
	SubscriberConfig config;

	// Polymorphic base class pointer
	std::shared_ptr<JalSubDatabase> jdb;

	// A list of active sessions using the sesionId as a key
	std::map<std::string, Session> activeSessions;

	// A lock to guard against the activeSessions list being modified by multiple
	// threads simultaneously, or while is is being read
	std::shared_mutex sessionsMutex;

	// A wrapper for the libmicrohttpd server to manage state and lifetime
	// Note - keep this declared last. the HttpServer relies on some of the other members
	// of JalSubscriber (notably the activeSessions and jdb), so should be destructed first
	std::shared_ptr<HttpServer> httpServer;

	Response messageHandler(const Message& message);

	enum jal_digest_algorithm getDigestAlgorithm(const Message& message);

	std::string getPublisherId(const Message& message);

	ModeType getReceiveMode(const Message& message);

	void notifyTimeout(Message& message);

	void pruneOldestSession();

	// Consolidates actual construction, should be called only from
	// within public constructors
	void constructorImpl(
		SubscriberConfig config,
		std::function<std::shared_ptr<JalSubDatabase>(SubscriberConfig)> dbFactory,
		std::function<std::shared_ptr<HttpServer>(
			std::vector<std::string>,
			SubscriberCallbacks callbacks,
			SubscriberConfig)> serverFactory);

	public:
	JalSubscriber(
		SubscriberConfig config);

	// For advanced users
	// The following constructors allow the use of httpServer or JalSubDatabase implementations
	// which might not be in the same library as the subscriber without rebuilding
	// the subscriber itself
	//
	// NOTE - The JalSubDatabase constructors will override the db selection in the config
	//
	// Specify a custom database
	JalSubscriber(
		SubscriberConfig config,
		std::function<std::shared_ptr<JalSubDatabase>(SubscriberConfig)> dbFactory);

	// Specify a custom httpServer
	JalSubscriber(
		SubscriberConfig config,
		std::function<std::shared_ptr<HttpServer>(
			std::vector<std::string>,
			SubscriberCallbacks,
			SubscriberConfig)> httpServer);

	// Specify a custom database and http server
	JalSubscriber(
		SubscriberConfig paramConfig,
		std::function<std::shared_ptr<JalSubDatabase>(SubscriberConfig)> dbFactory,
		std::function<std::shared_ptr<HttpServer>(
			std::vector<std::string>,
			SubscriberCallbacks,
			SubscriberConfig)> httpServer);
};

#endif
