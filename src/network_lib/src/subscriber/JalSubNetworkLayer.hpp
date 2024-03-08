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
#ifndef __JAL__SUB__NETWORK__LAYER__H__
#define __JAL__SUB__NETWORK__LAYER__H__

#include <vector>
#include <string>
#include <functional>
#include <memory>
#include "JalSubMessaging.hpp"
#include "JalSubCallbacks.hpp"
#include "JalSubConfig.hpp"

struct ResponseFuncSettings
{
	SubscriberCallbacks callbacks;
	bool debug;
	bool tlsEnabled;

	ResponseFuncSettings(SubscriberCallbacks paramCallbacks, bool paramDebug, bool paramTlsEnabled) :
		callbacks(paramCallbacks), debug(paramDebug), tlsEnabled(paramTlsEnabled)
		{}
};

// Base class to allow polymorphic handling and flexibility for multiple
// http server factories to exist
// Currently only the libmicrohttpdserver implementation exists outside of the testing
// environment
class HttpServer
{
	public:
	ResponseFuncSettings responseFuncSettings;

	HttpServer(SubscriberCallbacks paramCallbacks, SubscriberConfig paramConfig) :
		responseFuncSettings(ResponseFuncSettings(paramCallbacks, paramConfig.debug, paramConfig.enableTls))
	{
	}

	virtual ~HttpServer() {};
};

class LibMicroHttpdServer : public HttpServer
{
	struct MHD_Daemon* daemon;
	std::vector<std::string> allowedHosts;
	char* privateKey = NULL;
	char* publicCert = NULL;
	char* trustStore = NULL;

	public:
	static std::shared_ptr<HttpServer> factory(
		std::vector<std::string> allowedHosts,
		SubscriberCallbacks callbacks,
		SubscriberConfig config);

	LibMicroHttpdServer(
		std::vector<std::string> allowedHosts, // List of ipv4 addresses to accept messages from
		SubscriberCallbacks callbacks,
		SubscriberConfig config);

	~LibMicroHttpdServer();
};

#endif
