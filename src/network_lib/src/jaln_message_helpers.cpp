/**
 * @file
 *
 * @brief This file contains function
 * definitions for internal library functions related to creating JALoP
 * messages
 *
 * ### LICENSE
 *
 * Copyright (C) 2018-2026 Concurrent Technologies Corporation.
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <stdlib.h>
#include <string>
#include "jalop_protocol.hpp"

extern "C" {
	#include <jalop/jaln_network_types.h>
	#include "jaln_session.h"
	#include "jaln_message_helpers.h"
}

void jaln_send_close_session(jaln_session *sess)
{
	const long curl_timeout_period = sess->jaln_ctx->network_timeout * 60L;
	const long curl_retry_count = sess->jaln_ctx->http_client_retry_count;
	CURL *curl = sess->curl_ctx;
	// Sending the CloseSession message is "best effort". If sending it fails, or the
	// response is mangled, there's really no recovery path.
	// We'll throw a warning if something looks weird, but that's about it.
	try {
		CloseSessionMessage closeSessionMessage(sess->id);
		JalopResponse response = closeSessionMessage.sendMessage(
				curl,
				curl_timeout_period,
				curl_retry_count);
		if(ResponseType::CloseSessionResponse != response.getResponseType()) {
			std::string messageTypeString = response.getResponseTypeString();
			throw InvalidResponseType(messageTypeString);
		}

	} catch(const InvalidMessage& e) {
		fprintf(stderr, "Warning: Failed to construct close-session: %s\n", e.what());
		fprintf(stderr, "Subscriber Session may not have closed.\n");
	} catch(const SendFailure& e) {
		fprintf(stderr, "Warning: Failed to send close-session: %s\n", e.what());
		fprintf(stderr, "Subscriber Session may not have closed.\n");
	} catch(const MalformedResponse& e) {
		fprintf(stderr, "Warning: Malformed response to close-session: %s\n", e.what());
		fprintf(stderr, "Subscriber Session may not have closed.\n");
	} catch(const InvalidResponseType& e) {
		fprintf(stderr, "Warning: Unexpected response to close-session: %s\n", e.what());
		fprintf(stderr, "Subscriber Session may not have closed.\n");
	} catch(const InvalidResponse& e) {
		fprintf(stderr, "Warning: Response message of type: %s is invalid: %s\n",
			e.responseType.c_str(),
			e.reason.c_str());
		fprintf(stderr, "Subscriber Session may not have closed.\n");
	}
}
