/**
 * @file mock_http_server_impl.hpp This file contains a mocked-out implementation
 * of the HttpServer for use in testing
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
#include "JalSubNetworkLayer.hpp"
#include "JalSubConstants.hpp"

struct SessionInfo
{
	std::string sessionUuid;
};

class MockHttpServer : public HttpServer
{
	private:
	static std::shared_ptr<MockHttpServer> server;
	size_t publisherIndex = 0;
	// The following callbacks are used by the httpServer;
	// messageHandler
	//   Provide an input message and get and response message
	//
	// The following query the Subscriber's set of established sessions based on the
	// session uuid in the Message
	// getDigestAlgorithm
	//   Retrieves the digest algorithm for this session
	// getPublisherId 
	//   Retrieves the publisher ID for this session
	// getReceiveMode
	//   Retrives the mode for this session
	//   
	// notifyTimeout
	//   Informs the Subscriber that a Message timed out during transmission
	public:
	// This shouldn't need to be public, but the compiler complains about it
	MockHttpServer(std::vector<std::string>, // unused
		SubscriberCallbacks paramCallbacks,
		SubscriberConfig config) :
		HttpServer(paramCallbacks, config)
	{
	}
	// The MockHttpServer is going to use the singleton pattern so the test engine
	// can get a handle to the same object created for the Subscriber under test
	static std::shared_ptr<HttpServer> MockHttpServerFactory(
		std::vector<std::string> allowedHosts,
		SubscriberCallbacks callbacks,
		SubscriberConfig config)
	{
		if(nullptr == server)
		{
			server = std::make_shared<MockHttpServer>(
				allowedHosts,
				callbacks,
				config);
		}
		return server;
	}

	static std::shared_ptr<MockHttpServer> getServerHandle()
	{
		return server;
	}

	Response sendMessage(Message& message)
	{
		return responseFuncSettings.callbacks.messageHandler(message);
	}

	enum jal_digest_algorithm getDigestAlgorithm(const Message& message)
	{
		return responseFuncSettings.callbacks.getDigestAlgorithm(message);
	}
};
