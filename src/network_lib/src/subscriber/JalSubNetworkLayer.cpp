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

#include <vector>
#include <string>
#include <cstring>
#include <arpa/inet.h>
#include <functional>
#include <microhttpd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "JalSubMessaging.hpp"
#include "JalSubNetworkLayer.hpp"
#include "JalSubCallbacks.hpp"
#include "JalSubUtils.hpp"
#include "JalSubConfig.hpp"

// Filter out all messages that aren't from one of our expected hosts
// Invoked by the httpd server
static int accept_func(
	void* cls,
	const struct sockaddr* addr,
	socklen_t addrlen)
{
	// TODO unused addrlen
	(void)addrlen;

	// Only enforce if one or more allowed hosts are specified
	auto allowedHosts = (std::vector<std::string>*)(cls);
	if(allowedHosts->empty())
	{
		return MHD_YES;
	}

	// TODO - assuming the addr is an ipv4 family address
	// should check the family type first
	// TODO - does not support ipv6
	char*ip = inet_ntoa( ((sockaddr_in*)(addr))->sin_addr );

	for(auto& host : (*allowedHosts))
	{
		if(0 == strcmp(host.c_str(), ip))
		{
			return MHD_YES;
		}
	}
	return MHD_NO;
}

// Helper to determine file size, taken (almost) verbatim from the libmicrohttpd docs
static long get_file_size(const char* filename)
{
	FILE *fp;
	fp = fopen(filename, "rb");
	if(!fp)
	{
		return 0;
	}

	long size;

	if((0 != fseek(fp, 0, SEEK_END)) || (-1 == (size = ftell(fp))))
	{
		size = 0;
	}
	fclose(fp);
	return size;
}

// Helper to load cert and key files, taken (almost) verbatim from the libmicrohttpd docs
static char* load_file(const char* filename)
{
	FILE *fp;
	char* buffer;
	long size;

	size = get_file_size(filename);
	if(0 == size)
	{
		return NULL;
	}

	fp = fopen(filename, "rb");
	if(!fp)
	{
		return NULL;
	}

	buffer = (char*)malloc(size + 1);
	if(!buffer)
	{
		fclose(fp);
		return NULL;
	}
	buffer[size] = '\0';

	if(size != (long)fread(buffer, 1, size, fp))
	{
		free(buffer);
		buffer = NULL;
	}

	fclose(fp);
	return buffer;
}

void* request_completed(
	void* cls,
	struct MHD_Connection* conn,
	void** con_cls,
	enum MHD_RequestTerminationCode toe)
{
	(void)conn;

	// Extract callbacks handle
	SubscriberCallbacks callbacks = ((ResponseFuncSettings*)cls)->callbacks;

	Message* messagePtr = (Message*)(*con_cls);
	
	// If this exchange has been completed because of a timeout,
	// notify the message class to take any necessary steps
	if(MHD_REQUEST_TERMINATED_TIMEOUT_REACHED == toe)
	{
		// Always print, this is an unusual error
		fprintf(stderr, "Http timeout reached.\n");
		callbacks.notifyTimeout(*messagePtr);
	}
	delete messagePtr;
	*con_cls = NULL;
	return NULL;
}

int header_func(
	void* cls,
	enum MHD_ValueKind kind,
	const char* key,
	const char* value)
{
	// TODO unused kind
	(void)kind;

	Message* messagePtr = (Message*)cls;
	// If we have a problem with one of the headers, skip the rest
	messagePtr->addHeader(key, value);
	return MHD_YES;
}

// Instructions for the httpd server on message receive
static int response_func(
	void *cls,
	struct MHD_Connection *conn,
	const char* url,
	const char* method,
	const char* version,
	const char* upload_data,
	size_t* upload_data_size,
	void** con_cls)
{
	Message* messagePtr;
	// TODO examine unused params
	(void)url;
	(void)method;
	(void)version;
	bool newMessage = false;
	// Save off the amount of data received this call to help us
	// decide when we're done
	size_t upload_data_received = *upload_data_size;

	// Extract cls values
	SubscriberCallbacks callbacks = ((ResponseFuncSettings*)cls)->callbacks;
	bool debug = ((ResponseFuncSettings*)cls)->debug;

	if(NULL == *con_cls)
	{
		// set con_cls to some state which can be used in subsequent calls to this function
		// during the same transaction
		// Free this in the request_complete handler
		// During the first call, allocate a new message for collecting received data

		newMessage = true;
		messagePtr = new Message();
		*con_cls = (void*)messagePtr;

		// Subsequent messages in the same transaction have the same headers, process the
		// headers only on the first one
		MHD_get_connection_values(conn, MHD_HEADER_KIND, &header_func, messagePtr);

		if(debug)
		{
			for(const auto& [key, value] : messagePtr->getHeaders())
			{
				// Not using debugOuput here because we want to skip the loop entirely
				// if !debug, and there's no reason to repeat the check for every header
				fprintf(stdout, "Key: [%s], Value: [%s]\n", key.c_str(), value.c_str());
			}
		}


		// Once all headers have been received, process a select few which might be needed
		// during data collection
		// Failures here will not be immediately acted upon - instead storing an error kind
		// and error cause internally for use when building a response message
		// The exception is failures in the content-type, content-length, and message type
		// headers which will result in rejecting the incoming message entirely
		messagePtr->processHeaders();
		if(messagePtr->shouldAbort())
		{
			return MHD_NO;
		}
	}
	else
	{
		// If this isn't the first call of this transaction, get a pointer to
		// the message we already created
		messagePtr = (Message*) (*con_cls);
	}

	// If the message is some kind of record process the record data
	if(messagePtr->isRecord())
	{
		// Only if this is the first round of processing
		// Hand the message off to the Subscriber (by reference) to attempt to
		// get the digestAlgorithm associated with the session that shares this
		// message's Id.
		// Note that the first iteration through POST messages usually has only the headers
		// and no data
		if(newMessage)
		{
			try
			{
				messagePtr->setDigestAlgorithm(callbacks.getDigestAlgorithm(*messagePtr));
				messagePtr->setPublisherId(callbacks.getPublisherId(*messagePtr));
				messagePtr->setReceiveMode(callbacks.getReceiveMode(*messagePtr));
			}
			catch(...)
			{
				// If the digest algorithm, receiveMode, or publisherId couldn't be obtained,
				// a session hasn't been created with an Id matching the one in this message
				messagePtr->setError(MSG_SESSION_FAILURE_STR, JAL_UNSUPPORTED_SESSION_ID);
			}
		}

		size_t totalLength = messagePtr->contentLength;
		if(totalLength > 0 && *upload_data_size > 0 && NULL != upload_data)
		{
			// Treat the incoming data as bytes instead of chars
			// This cast should always be safe
			messagePtr->addData((const uint8_t*)upload_data, upload_data_size);
		}
	}

	// libmicrohttpd guarantees that this function will always be called at least
	// twice. First with headers only. It is not legal to generate a response to this
	// first call even if we know the message will only contain headers. Then, this
	// function will be called with data until *upload_data_size is 0. Only once the
	// full message is received should we generate our response.
	if(newMessage || upload_data_received > 0)
	{
		// Abort early, with no response we dont' have the whole message yet
		return MHD_YES;
	}

	// We have received the complete message data (if any)
	// potentially perform cleanup, internally checks if our record data (if any)
	// is complete
	messagePtr->finalizeData();

	Response response;
	if(messagePtr->shouldError())
	{
		response = messagePtr->generateError();
	}
	else
	{
		auto messageHandler = callbacks.messageHandler;

		// Hand off recieved message to be handled by provided callback
		response = messageHandler(*messagePtr);
	}

	MHD_Response* mhd_response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
	for(const auto& header : response.getHeaders())
	{
		MHD_add_response_header(mhd_response, header.first.c_str(), header.second.c_str());
	}
	MHD_queue_response(conn, response.getStatus(), mhd_response);
	MHD_destroy_response(mhd_response);

	return MHD_YES;
}

HttpServer::HttpServer(
	std::vector<std::string> paramAllowedHosts,
	SubscriberCallbacks callbacks,
	SubscriberConfig config)
	: allowedHosts(paramAllowedHosts), responseFuncSettings(callbacks, config.debug)
{
	struct addrinfo hints;
	struct addrinfo* result;
	struct addrinfo* res;
	int error;

	// Constraints for the returned addrinfo
	// In this case, we're just restricting to an ipv4 address with AF_INET
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = 0;
	hints.ai_protocol = 0;
	// Convert the provided address (which may be a hostname like localhost) into an addrinfo
	error = getaddrinfo(config.ipAddr.c_str(), std::to_string(config.listenPort).c_str(), &hints, &result);
	if(0 != error)
	{
		std::string errMsg = "Failure to create addrinfo struct from address: " + config.ipAddr;
		throw std::runtime_error(errMsg);
	}

	// Loop over returned results
	// TODO: For now, we'll just take the first of the possible results. For the purpose of
	// specifying the ip/port for the server, any result should be sufficient, and in most cases
	// there will be either 1 or 0 anyway
	// If/when we move to support ipv6 this may need to become more complicated
	res = result;
	if(NULL == res)
	{
		std::string errMsg = "No results from getaddrinfo with address: " + config.ipAddr;
		throw std::runtime_error(errMsg);
	}

	if(config.enableTls)
	{
		// Load necessary key/cert files
		// First, the private key
		privateKey = load_file(config.tlsConfig.privateKey.c_str());
		if(NULL == privateKey)
		{
			throw std::runtime_error("Failed to load private key file: "
				+ config.tlsConfig.privateKey);
		}
		publicCert = load_file(config.tlsConfig.publicCert.c_str());
		if(publicCert == NULL)
		{
			throw std::runtime_error("Failed to load public certificate file: "
				+ config.tlsConfig.publicCert);
		}
		trustStore = load_file(config.tlsConfig.trustStore.c_str());
		if(trustStore == NULL)
		{
			throw std::runtime_error("Failed to load trust store file: "
				+ config.tlsConfig.trustStore);
		}

		daemon = MHD_start_daemon(
			MHD_USE_SSL | MHD_USE_POLL | MHD_USE_THREAD_PER_CONNECTION,
			0, // port ignored when using MHD_OPTION_SOCK_ADDR
			&accept_func,
			(void*)&(this->allowedHosts),
			&response_func,
			&(this->responseFuncSettings),
			MHD_OPTION_HTTPS_MEM_KEY, privateKey,
			MHD_OPTION_HTTPS_MEM_CERT, publicCert,
			MHD_OPTION_HTTPS_MEM_TRUST, trustStore,
			MHD_OPTION_NOTIFY_COMPLETED, request_completed, &(this->responseFuncSettings),
			MHD_OPTION_HTTPS_MEM_KEY, privateKey,
			MHD_OPTION_CONNECTION_TIMEOUT, config.networkTimeout,
			MHD_OPTION_SOCK_ADDR, res->ai_addr,
			MHD_OPTION_END);
	}
	else
	{
		daemon = MHD_start_daemon(
			MHD_USE_POLL | MHD_USE_THREAD_PER_CONNECTION,
			0, // port ignored when using MHD_OPTION_SOCK_ADDR
			&accept_func,
			(void*)&(this->allowedHosts),
			&response_func,
			&(this->responseFuncSettings),
			MHD_OPTION_NOTIFY_COMPLETED, request_completed, &(this->responseFuncSettings),
			MHD_OPTION_CONNECTION_TIMEOUT, config.networkTimeout,
			MHD_OPTION_SOCK_ADDR, res->ai_addr,
			MHD_OPTION_END);
	}

	freeaddrinfo(result);

	if(NULL == daemon)
	{
		throw std::runtime_error("Failed to start http daemon");
	}
	debugOutput(config.debug, stdout, "daemon start\n");
}

HttpServer::~HttpServer()
{
	// TODO - I think this call will wait for any currently active threads to join
	// before shutting down. So we shouldn't get interrupted during our handling, but
	// this may be worth looking at in more depth
	MHD_stop_daemon(daemon);
	free(privateKey);
	free(publicCert);
	free(trustStore);
}
