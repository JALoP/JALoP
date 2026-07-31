/**
 * @file
 *
 * @brief This file contains definitions for handling sending/receiving
 * JALoP protocol messages via curl
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
#include <string>
#include <cstddef>
#include <curl/curl.h>
#include <stdexcept>
#include <axl.h>
#include <algorithm>

#include "jalop_protocol.hpp"

extern "C" {
#include "jaln_strings.h"
#include "jaln_context.h"
#include "jal_alloc.h"
#include <jalop/jaln_network_types.h>
#include "jaln_string_utils.h"
#include "jaln_strings.h"
#include <jalop/jal_digest.h>
}

static size_t jaln_noop_write(
                __attribute__((unused)) char *ptr,
                __attribute__((unused)) size_t size,
                size_t nmemb,
                __attribute__((unused)) void *user_data)
{
        return nmemb;
}

static bool add_header(const char *prefix, const char *val, struct curl_slist **headers)
{
	bool ret;
	size_t prefix_len = strlen(prefix);
	size_t colon_space_len = strlen(JALN_COLON_SPACE);
	size_t val_len = strlen(val);
	char *header_str = (char*)jal_malloc(prefix_len + colon_space_len + val_len + 1);
	memcpy(header_str, prefix, prefix_len); // nosemgrep - the copy length is less than or equal to the destination buffer size
	memcpy(header_str + prefix_len, JALN_COLON_SPACE, colon_space_len); // nosemgrep - the copy length is less than or equal to the destination buffer size
	memcpy(header_str + prefix_len + colon_space_len, val, val_len + 1); // nosemgrep - the copy length is less than or equal to the destination buffer size

	struct curl_slist *tmp = curl_slist_append(*headers, header_str);
	if (!tmp) {
		curl_slist_free_all(*headers);
		*headers = NULL;
		ret = false;
	} else {
		*headers = tmp;
		ret = true;
	}
	free(header_str);
	return ret;
}

static std::vector<std::string> splitErrors(std::string str, std::string messageName)
{
	const std::string delim = "|";
	std::vector<std::string> errors;
	std::size_t prev = 0;
	std::size_t next = 0;
	while(next < str.length() && std::string::npos != next) {
		next = str.find(delim, prev);
		// Skip "leading" |
		if(next == prev) {
			prev += 1;
			next += 1;
			continue;
		}

		try {
			if(std::string::npos == next) {
				errors.push_back(str.substr(prev));
			} else {
				errors.push_back(str.substr(prev, (next-prev)));
				prev = next + 1;
				next = prev;
			}
		} catch(...) {
			break;
		}
	}

	// If no errors could be extracted, this message is out-of-spec
	if(0 == errors.size()) {
		throw InvalidResponse(messageName, std::string("Empty JAL-Error-Message."));
	}
	return errors;
}

static size_t header_handler(char *ptr, size_t size, size_t nmemb, void *user_data) {
	// From the curl docs, size is always 1
	// The return value should represent the number of bytes handled, if the return
	// does not == size*nmemb, it signals an error to curl
	if(NULL == user_data) {
		fprintf(stderr, "Error: Invalid user_data passed to CURLOPT_HEADERFUNCTION callback\n");
		return 0;
	}
	const size_t bytes = size * nmemb;
	// Header contents is of the form [HEADER_NAME]:[HEADER_VALUE]
	// Split the data on :
	// The header line is not expected to have a null terminator, so use the string consturctor
	// that takes a size
	std::string header_line = std::string(ptr, bytes);
	size_t delimiter = header_line.find(":");
	if(std::string::npos == delimiter) {
		return bytes;
	}

	// advance through whitespace
	size_t header_start = delimiter + 1;
	while(header_start < bytes && (' ' == header_line[header_start] || '\t' == header_line[header_start])) {
		header_start++;
	}

	if(header_start >= bytes || header_start + 1 >= bytes) {
		fprintf(stderr, "Error: CURLOPT_HEADERFUNCTION handled header line with no content after ':'\n");
		fprintf(stderr, "%s\n", header_line.c_str());
		return 0;
	}

	if(0 == header_start) {
		fprintf(stderr, "Error: CURLOPT_HEADERFUNCTION handled header line with no content preceeding ':'\n");
		fprintf(stderr, "%s\n", header_line.c_str());
		return 0;
	}

	std::string name = header_line.substr(0, delimiter);
	// Don't include the : in the value
	size_t valueLen = header_line.length()
		- 2 // The last two bytes are always \r\n
		- header_start; // subtract off the length of the name, :, and leading whitespace
	std::string value = header_line.substr(header_start, valueLen);

	// Normalize incoming headers to lower-case
	std::transform(name.begin(), name.end(), name.begin(),
		[](unsigned char c) { return std::tolower(c);});

	// Add the header to the response message map
	JalopResponse* response = (JalopResponse*) user_data;
	response->headers[name] = value;
	return bytes;
}

ResponseType JalopResponse::getResponseType() {
	std::string contentType;
	try {
		contentType = headers.at(std::string(JALN_HDRS_CONTENT_TYPE));
	} catch (std::out_of_range& e) {
		std::string reason = std::string("JalopResponse does not appear to be a JALoP message. Missing header: ")
			+ std::string(JALN_HDRS_CONTENT_TYPE) + std::string(".");
		throw MalformedResponse(reason);
	}

	if(std::string(JALN_STR_CT_JALOP) != contentType) {
		std::string reason = std::string("JalopResponse Content Type: ") + contentType + " does not match expected value: "
			+ std::string(JALN_STR_CT_JALOP) + ".";
			throw MalformedResponse(reason);
	}

	std::string message_type;
	try {
		message_type = headers.at(std::string(JALN_HDRS_MESSAGE));
	} catch (std::out_of_range& e) {
		std::string reason = std::string("JalopResponse does not indicate a message type. Missing header: ")
			+ std::string(JALN_HDRS_MESSAGE) + std::string(".");
		throw MalformedResponse(reason);
	}

	if(std::string(JALN_MSG_INIT_ACK) == message_type) {
		return ResponseType::InitAck;
	} else if(std::string(JALN_MSG_INIT_NACK) == message_type) {
		return ResponseType::InitNack;
	} else if (std::string(JALN_MSG_JOURNAL_MISSING_RESPONSE) == message_type) {
		return ResponseType::JournalMissingResponse;
	} else if (std::string(JALN_MSG_RECORD_FAILURE) == message_type) {
		return ResponseType::RecordFailure;
	} else if (std::string(JALN_MSG_SESSION_FAILURE) == message_type) {
		return ResponseType::SessionFailure;
	} else if (std::string(JALN_MSG_CLOSE_SESSION_RESPONSE) == message_type) {
		return ResponseType::CloseSessionResponse;
	} else if (std::string(JALN_MSG_DIGEST_CHALLENGE) == message_type) {
		return ResponseType::DigestChallenge;
	} else if (std::string(JALN_MSG_SYNC) == message_type) {
		return ResponseType::Sync;
	} else if (std::string(JALN_MSG_SYNC_FAILURE) == message_type) {
		return ResponseType::SyncFailure;
	} else {
		std::string reason = std::string("JalopResponse contains unrecognized message type: ") + message_type;
		throw MalformedResponse(reason);
	}
}

std::string JalopResponse::getResponseTypeString() {
	std::string message_type;
	try {
		message_type = headers.at(std::string(JALN_HDRS_MESSAGE));
	} catch (std::out_of_range& e) {
		message_type = "Unable to determine message type.";
	}
	return message_type;
}

InvalidResponse::InvalidResponse(std::string responseTypeParam, std::string reasonParam)
	: std::runtime_error("Invalid JalopResponse") {
	responseType = responseTypeParam;
	reason = reasonParam;
	errMsg = std::string("Failed to construct JalopResponse of type: ") + responseType + std::string(". Reason: ")
		+ reason + std::string(".");
}

JalopMessage::JalopMessage() {
	// All messages get the following headers
	// Content-Type : application/http+jalop
	headers[std::string(JALN_HDRS_CONTENT_TYPE)] = std::string(JALN_STR_CT_JALOP);
}

// Base send for all non-record messages
JalopResponse JalopMessage::sendMessage(
	CURL* curl,
	const long curl_timeout_period,
	const long curl_retry_count) {
	if(NULL == curl) {
		throw SendFailure("CURL context invalid when attempting to send message");
	}

	JalopResponse response;

	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, jaln_noop_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_handler);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)&response);

	// All messages need headers
	struct curl_slist *curl_headers = NULL;
	for(const auto& [key, value] : headers) {
		add_header(key.c_str(), value.c_str(), &curl_headers);
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);

	// All messages may return errors during sending
	char buf[CURL_ERROR_SIZE];
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, &buf);

	// Configure the optional timeout for all messages
	if(curl_timeout_period > 0) {
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, curl_timeout_period);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	}

	// Do the send, retrying a configurable number of times if necessary
	CURLcode rc = CURLE_OK;
	int retry_count = 0;
	do {
		retry_count++;
		rc = curl_easy_perform(curl);
	} while(CURLE_COULDNT_CONNECT == rc && retry_count < curl_retry_count);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, NULL);
	curl_slist_free_all(curl_headers);

	// If the final result is not OK, throw an exception with the appropriate error message
	if(CURLE_OK != rc) {
		std::string errMsg = std::string("Curl error: (")
			+ std::to_string(rc) + std::string("): ") + std::string(buf);
		throw SendFailure(errMsg);
	}
	return response;
}

InitMessage::InitMessage(
	const enum jaln_publish_mode mode,
	const enum jaln_record_type type,
	const std::string& publisherId,
	const enum jaln_digest_challenge digestChallenge,
	axlList* dgst_list,
	axlList* cmp_list) {
	headers[std::string(JALN_HDRS_VERSION)] = std::string(JALN_VERSION);
	headers[std::string(JALN_HDRS_MESSAGE)] = std::string(JALN_MSG_INIT);

	// Publisher ID must not be empty
	if(publisherId.empty()) {
		std::string reason = std::string("Publisher ID must not be empty.");
		throw InvalidMessage(reason);
	}
	headers[std::string(JALN_HDRS_PUBLISHER_ID)] = publisherId;

	switch(mode) {
		case JALN_LIVE_MODE:
			headers[std::string(JALN_HDRS_MODE)] = std::string(JALN_MSG_PUBLISH_LIVE);
			break;
		case JALN_ARCHIVE_MODE:
			headers[std::string(JALN_HDRS_MODE)] = std::string(JALN_MSG_PUBLISH_ARCHIVE);
			break;
		default:

			std::string reason = std::string("Invalid Mode enum value: ") + std::to_string(mode)
				+ std::string(".");
			throw InvalidMessage(reason);
	}

	switch(type) {
		case JALN_RTYPE_JOURNAL:
			headers[std::string(JALN_HDRS_RECORD_TYPE)] = std::string(JALN_STR_JOURNAL);
			break;
		case JALN_RTYPE_AUDIT:
			headers[std::string(JALN_HDRS_RECORD_TYPE)] = std::string(JALN_STR_AUDIT);
			break;
		case JALN_RTYPE_LOG:
			headers[std::string(JALN_HDRS_RECORD_TYPE)] = std::string(JALN_STR_LOG);
			break;
		default:
			std::string reason = std::string("Invalid Type enum value: ") + std::to_string(type)
				+ std::string(".");
			throw InvalidMessage(reason);
	}

	// The jaln_digest_challenge enum is defined a little weirdly (jaln_context.h)
	// The list of defined values are:
	// JALN_DC_UNSET
	// JALN_DC_OFF_BIT
	// JALN_DC_ON_BIT
	// JALN_DC_PREF_BIT
	// JALN_DC_OFF
	// JALN_DC_ON
	// JALN_DC_PREF_OFF
	// JALN_DC_PREF_ON
	// but based on the way they are used, the *_BIT values are helper values and should
	// not actually be used except to define the other values, so we're assuming those are
	// not valid here. They should probably be pulled out of the enum definition
	switch(digestChallenge) {
		case JALN_DC_UNSET:
			// Omit the header, this is essentially the same as specifying JALN_DC_ON per the spec
			break;
		case JALN_DC_PREF_OFF:
			headers[std::string(JALN_HDRS_ACCEPT_CONFIGURE_DIGEST_CHALLENGE)] =
				std::string(JALN_DIGEST_CHALLENGE_OFF) + std::string(", ") + std::string(JALN_DIGEST_CHALLENGE_ON);
			break;
		case JALN_DC_PREF_ON:
			headers[std::string(JALN_HDRS_ACCEPT_CONFIGURE_DIGEST_CHALLENGE)] =
				std::string(JALN_DIGEST_CHALLENGE_ON) + std::string(", ") + std::string(JALN_DIGEST_CHALLENGE_OFF);
			break;
		case JALN_DC_ON:
			headers[std::string(JALN_HDRS_ACCEPT_CONFIGURE_DIGEST_CHALLENGE)] = std::string(JALN_DIGEST_CHALLENGE_ON);
			break;
		case JALN_DC_OFF:
			headers[std::string(JALN_HDRS_ACCEPT_CONFIGURE_DIGEST_CHALLENGE)] = std::string(JALN_DIGEST_CHALLENGE_OFF);
			break;
		default:
			std::string reason = std::string("Invalid Accept Digest Challenge enum value: ")
				+ std::to_string(digestChallenge) + std::string(".");
			throw InvalidMessage(reason);
	}

	// If the list is empty (or NULL), do nothing and omit the header.
	// This is essentially the same as specifying sha256 per the spec
	if(NULL != dgst_list && !axl_list_is_empty(dgst_list)) {
		axlListCursor *cursor = axl_list_cursor_new(dgst_list);
		axl_list_cursor_first(cursor);

		std::string dgst_str;
		while(axl_list_cursor_has_item(cursor)) {
			// Any time (except the first) we hit the top of the loop, add a ", ". This wont happen
			// after the last item, and shouldn't happen if there is only one item
			if(!dgst_str.empty()) {
				dgst_str += std::string(", ");
			}

			// Get the next item in the list
			struct jal_digest_ctx *dgst = (struct jal_digest_ctx *)axl_list_cursor_get(cursor);

			// Attempt to add the uri to our growing string, catching the possible exception thrown by += if
			// we exceed maximum string length, but this is highly unlikely
			try {
				dgst_str += std::string(dgst->algorithm_uri);
			} catch(const std::length_error& e) {
				std::string reason = std::string("Digest Algorithm List header value exceeds maximum string length");
				throw InvalidMessage(reason);
			}
			axl_list_cursor_next(cursor);
		}
		axl_list_cursor_free(cursor);
		headers[JALN_HDRS_ACCEPT_DIGEST] = dgst_str;
	}

	// If the list is empty (or NULL), do nothing and omit the header.
	// This is essentially the same as specifying None per the spec
	if(NULL != cmp_list && !axl_list_is_empty(cmp_list)) {
		axlListCursor *cursor = axl_list_cursor_new(cmp_list);
		axl_list_cursor_first(cursor);

		std::string cmp_str;
		while(axl_list_cursor_has_item(cursor)) {
			// Any time (except the first) we hit the top of the loop, add a ", ". This wont happen
			// after the last item, and shouldn't happen if there is only one item
			if(!cmp_str.empty()) {
				cmp_str += std::string(", ");
			}

			// Get the next item in the list
			char *cmp = (char*)axl_list_cursor_get(cursor);
			try {
				cmp_str += std::string(cmp);
			} catch(const std::length_error& e) {
				std::string reason = std::string("Compression Algorithm List header value exceeds maximum string length");
				throw InvalidMessage(reason);
			}
			axl_list_cursor_next(cursor);
		}
		axl_list_cursor_free(cursor);
		headers[std::string(JALN_HDRS_ACCEPT_COMPRESSION)] = std::string(cmp_str);
	}
}

JournalMissingMessage::JournalMissingMessage(
	const std::string& sessionId,
	const std::string& recordId) {
	headers[std::string(JALN_HDRS_MESSAGE)] = std::string(JALN_MSG_JOURNAL_MISSING);
	headers[std::string(JALN_HDRS_SESSION_ID)] = sessionId;
	headers[std::string(JALN_HDRS_ID)] = recordId;
}

InitAck::InitAck(
	const JalopResponse& response,
	axlList* allowedDigestAlgs,
	axlList* allowedCompressions,
	const enum jaln_digest_challenge allowedChallenge,
	const enum jaln_publish_mode mode,
	const enum jaln_record_type type) {
	// getResponseType should have already verified that this is a JALoP init ack response, so we won't re-check
	// content-type and message-type
	//
	// InitAck has the following headers
	// session-id (required)
	// xml-compression (required)
	// digest (required)
	// configure-digest-challenge (required)
	// id (resume) (optional)
	// journal-offset (resume) (optional)

	// extract the required headers
	std::string nextHeader;
	std::string configureDigestChallenge;
	std::string contentLength;
	try {
		nextHeader = std::string(JALN_HDRS_CONTENT_LENGTH);
		contentLength = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_SESSION_ID);
		sessionId = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_COMPRESSION);
		xmlCompression = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_DIGEST);
		digestAlgorithmUri = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_CONFIGURE_DIGEST_CHALLENGE);
		configureDigestChallenge = response.headers.at(nextHeader);
	} catch (std::out_of_range& e) {
		throw InvalidResponse("InitAck", std::string("Missing Header: ") + nextHeader);
	}

	// Content length should always be 0
	if(std::string("0") != contentLength) {
		throw InvalidResponse("InitAck", std::string("Unexpected non-zero content length: ") + contentLength + ".");
	}
	

	// If either id or journal-offset is present, they must both be present and non-empty
	const auto& idIter = response.headers.find(std::string(JALN_HDRS_ID));
	if(response.headers.end() != idIter) {
		id = idIter->second;
	}
	const auto& offsetIter = response.headers.find(std::string(JALN_HDRS_JOURNAL_OFFSET));
	std::string offset_str;
	if(response.headers.end() != offsetIter) {
		offset_str = offsetIter->second;
	}

	if(id.empty() && !offset_str.empty()) {
		throw InvalidResponse("InitAck", std::string(JALN_HDRS_JOURNAL_OFFSET) + std::string(" is present, but ") + std::string(JALN_HDRS_ID) + std::string(" is missing."));
	} else if(!id.empty() && offset_str.empty()) {
		throw InvalidResponse("InitAck", std::string(JALN_HDRS_ID) + std::string(" is present, but ") + std::string(JALN_HDRS_JOURNAL_OFFSET) + std::string(" is missing."));
	} else if(!id.empty() && !offset_str.empty() && JALN_RTYPE_JOURNAL != type) {
		throw InvalidResponse("InitAck", std::string("Received journal resume id/offset, but resume is not \
			allowed for non-journal records."));
	} else if(!id.empty() && !offset_str.empty() && JALN_LIVE_MODE == mode) {
		throw InvalidResponse("InitAck", std::string("Received journal resume id/offset, but resume is not \
			allowed in Live mode."));
	}

	// If we have an offset, convert it from a string to a uint64_t
	if(!offset_str.empty() && !jaln_ascii_to_uint64(offset_str.c_str(), &offset)) {
		throw InvalidResponse("InitAck", std::string("Failed to convert: ") + offset_str
			+ std::string(" to a uint64_t."));
	}
	// Our headers are consistent, now we need to make sure the options selected by the subscriber
	// are within the values we provided in our init message
	// Session-Id can be anything except empty
	if(sessionId.empty()) {
		throw InvalidResponse("InitAck", std::string(JALN_HDRS_SESSION_ID) + std::string(" is empty."));
	}

	// Check if the compression we received is in our allowed compression list
	bool compressionMatch = false;
	axlListCursor* cursor = axl_list_cursor_new(allowedCompressions);
	axl_list_cursor_first(cursor);
	while(axl_list_cursor_has_item(cursor)) {
		char* comp = (char*) axl_list_cursor_get(cursor);
		if(std::string(comp) == xmlCompression) {
			compressionMatch = true;
			break;
		}
		axl_list_cursor_next(cursor);
	}
	axl_list_cursor_free(cursor);

	if(!compressionMatch) {
		throw InvalidResponse("InitAck", std::string("Received xml compression: ") + xmlCompression
			+ std::string(" is not present in list of allowed xml compressions."));
	}

	// Check if the digest algorithm we received is in our allowed digest algorithm list
	bool digestAlgorithmMatch = false;
	cursor = axl_list_cursor_new(allowedDigestAlgs);
	axl_list_cursor_first(cursor);
	while(axl_list_cursor_has_item(cursor)) {
		struct jal_digest_ctx* dctx = (struct jal_digest_ctx*)axl_list_cursor_get(cursor);
		if(std::string(dctx->algorithm_uri) == digestAlgorithmUri) {
			digestAlgorithmMatch = true;
			break;
		}
		axl_list_cursor_next(cursor);
	}
	axl_list_cursor_free(cursor);

	if(!digestAlgorithmMatch) {
		throw InvalidResponse("InitAck", std::string("Received digest algorithm: ") + digestAlgorithmUri
			+ std::string(" is not present in list of allowed digest algorithms."));
	}

	// Convert the digest algorithm to its enum form for later use
	if(JAL_OK != jal_get_digest_from_uri(digestAlgorithmUri.c_str(), &digestAlgorithm)) {
		throw InvalidResponse("InitAck", std::string("Failed to convert: ") + digestAlgorithmUri
				+ std::string(" to a known digest algorithm."));
	}

	// Check if the digest challenge we recieve is in our allowed digest challenge list
	if(std::string(JALN_DIGEST_CHALLENGE_ON) == configureDigestChallenge) {
		if(JALN_DC_UNSET == allowedChallenge ||
			JALN_DC_ON_BIT & allowedChallenge) {
			challengeDigest = true;
		} else {
			throw InvalidResponse("InitAck", std::string("Received configure digest challenge: ")
				+ configureDigestChallenge + " is not present in the list of allowed digest challenge options.");
		}
	} else if(std::string(JALN_DIGEST_CHALLENGE_OFF) == configureDigestChallenge) {
		if(JALN_DC_OFF_BIT & allowedChallenge) {
			challengeDigest = false;
		} else {
			throw InvalidResponse("InitAck", std::string("Received configure digest challenge: ")
				+ configureDigestChallenge + " is not present in the list of allowed digest challenge options.");
		}
	} else {
			throw InvalidResponse("InitAck", std::string("Received configure digest challenge: ")
				+ configureDigestChallenge + " is not a valid digest challenge value.");
	}
}

CloseSessionMessage::CloseSessionMessage(const std::string& sessionId) {
	headers[std::string(JALN_HDRS_MESSAGE)] = std::string(JALN_MSG_CLOSE_SESSION);
	headers[std::string(JALN_HDRS_SESSION_ID)] = sessionId;
}

DigestResponseMessage::DigestResponseMessage(
	const std::string& sessionId,
	const std::string& id,
	const uint8_t* localDigest,
	const uint32_t localSize,
	const uint8_t* peerDigest,
	const uint32_t peerSize) {
	if(NULL == localDigest) {
		std::string reason = std::string("NULL localDigest provided.");
		throw InvalidMessage(reason);
	}
	if(NULL == peerDigest) {
		std::string reason = std::string("NULL peerDigest provided.");
		throw InvalidMessage(reason);
	}

	headers[std::string(JALN_HDRS_MESSAGE)] = std::string(JALN_MSG_DIGEST_RESP);
	headers[std::string(JALN_HDRS_SESSION_ID)] = sessionId;
	headers[std::string(JALN_HDRS_ID)] = id;
	if(peerSize == localSize && 0 == memcmp(localDigest, peerDigest, localSize))  {
		headers[std::string(JALN_HDRS_DIGEST_STATUS)] = std::string(JALN_STR_CONFIRMED);
	} else {
		headers[std::string(JALN_HDRS_DIGEST_STATUS)] = std::string(JALN_STR_INVALID);
	}
}

InitNack::InitNack(const JalopResponse& response) {
	// getResponseType should have already verified that this is a JALoP init nack response, so we won't re-check
	// content-type and message-type
	//
	// InitNack has the following headers
	// error-message
	//
	// extract the required headers
	std::string nextHeader;
	std::string contentLength;
	try {
		nextHeader = std::string(JALN_HDRS_CONTENT_LENGTH);
		contentLength = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_ERROR_MESSAGE);
		errorMessage = response.headers.at(nextHeader);
	} catch (std::out_of_range& e) {
		throw InvalidResponse("InitNack", std::string("Missing Header: ") + nextHeader);
	}

	// Content length should always be 0
	if(std::string("0") != contentLength) {
		throw InvalidResponse("InitNack", std::string("Unexpected non-zero content length: ") + contentLength + ".");
	}

	errors = splitErrors(errorMessage, "InitNack");
}

JournalMissingResponse::JournalMissingResponse(const JalopResponse& response) {
	// getResponseType should have already verified that this is a JALoP journal-missing-response response, so we
	// won't re-check content-type and message-type
	//
	// JournalMissingResponse has no required headers
	// Nothing to do here, this constructor mostly exists to keep the pattern
	(void)response;
}

RecordFailure::RecordFailure(
		const JalopResponse& response,
		const std::string& expectedId) {
	// getResponseType should have already verified that this is a JALoP record-failure response, so we won't
	// re-check content-type and message-type
	//
	// RecordFailure has the following headers
	// id
	// error-message
	//
	// extract the required headers
	std::string nextHeader;
	std::string contentLength;
	try {
		nextHeader = std::string(JALN_HDRS_CONTENT_LENGTH);
		contentLength = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_ERROR_MESSAGE);
		errorMessage = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_ID);
		id = response.headers.at(nextHeader);
	} catch (std::out_of_range& e) {
		throw InvalidResponse("RecordFailure", std::string("Missing Header: ") + nextHeader);
	}

	// Content length should always be 0
	if(std::string("0") != contentLength) {
		throw InvalidResponse("RecordFailure", std::string("Unexpected non-zero content length: ") + contentLength + ".");
	}

	errors = splitErrors(errorMessage, "RecordFailure");

	// The record id returned must match the expected record id, or some wires have crossed
	if(expectedId != id) {
		throw InvalidResponse("RecordFailure", std::string("Expected Record Id: ") + expectedId
			+ std::string(" received: ") + id + std::string("."));
	}
}

SessionFailure::SessionFailure(
		const JalopResponse& response,
		const std::string& expectedId,
		const std::string& expectedSessionId) {
	// getResponseType should have already verified that this is a JALoP session-failure reponse, so we won't
	// re-check content-type and message-type
	//
	// SessionFailure has the following headers
	// id
	// session-id
	// error-message
	//
	// extract the required headers
	std::string nextHeader;
	std::string contentLength;
	try {
		nextHeader = std::string(JALN_HDRS_CONTENT_LENGTH);
		contentLength = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_ERROR_MESSAGE);
		errorMessage = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_ID);
		id = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_SESSION_ID);
		sessionId = response.headers.at(nextHeader);
	} catch (std::out_of_range& e) {
		throw InvalidResponse("SessionFailure", std::string("Missing Header: ") + nextHeader);
	}

	// Content length should always be 0
	if(std::string("0") != contentLength) {
		throw InvalidResponse("SessionFailure", std::string("Unexpected non-zero content length: ") + contentLength + ".");
	}

	errors = splitErrors(errorMessage, "SessionFailure");

	// The record id returned must match the expected record id, or some wires have crossed
	if(expectedId != id) {
		throw InvalidResponse("SessionFailure", std::string("Expected Record Id: ") + expectedId
			+ std::string(" received: ") + id + std::string("."));
	}
	// The session id returned must match the expected session id, or some wires have crossed
	if(expectedSessionId != sessionId) {
		throw InvalidResponse("SessionFailure", std::string("Expected Session Id: ") + expectedId
			+ std::string(" received: ") + id + std::string("."));
	}
}

DigestChallenge::DigestChallenge(
		const JalopResponse& response,
		const std::string& expectedId) {
	// getResponseType should have already verified that this is a JALoP digest-challenge response, so we won't
	// re-check content-type and message-type
	//
	// DigestChallenge has the following headers
	// id
	// digest-value
	//
	// extract the required headers
	std::string nextHeader;
	std::string contentLength;
	try {
		nextHeader = std::string(JALN_HDRS_CONTENT_LENGTH);
		contentLength = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_ID);
		id = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_DIGEST_VALUE);
		digestValue = response.headers.at(nextHeader);
	} catch (std::out_of_range& e) {
		throw InvalidResponse("DigestChallenge", std::string("Missing Header: ") + nextHeader);
	}

	// Content length should always be 0
	if(std::string("0") != contentLength) {
		throw InvalidResponse("DigestChallenge", std::string("Unexpected non-zero content length: ") + contentLength + ".");
	}

	// The record id returned must match the expected record id, or some wires have crossed
	if(expectedId != id) {
		throw InvalidResponse("DigestChallenge", std::string("Expected Record Id: ") + expectedId
			+ std::string(" received: ") + id + std::string("."));
	}
}

Sync::Sync(
		const JalopResponse& response,
		const std::string& expectedId) {
	// getResponseType should have already verified that this is a JALoP sync response, so we won't
	// re-check content-type and message-type
	//
	// Sync has the following headers
	// id
	//
	// extract the required headers
	std::string nextHeader;
	std::string contentLength;
	try {
		nextHeader = std::string(JALN_HDRS_CONTENT_LENGTH);
		contentLength = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_ID);
		id = response.headers.at(nextHeader);
	} catch (std::out_of_range& e) {
		throw InvalidResponse("Sync", std::string("Missing Header: ") + nextHeader);
	}

	// Content length should always be 0
	if(std::string("0") != contentLength) {
		throw InvalidResponse("Sync", std::string("Unexpected non-zero content length: ") + contentLength + ".");
	}

	// The record id returned must match the expected record id, or some wires have crossed
	if(expectedId != id) {
		throw InvalidResponse("Sync", std::string("Expected Record Id: ") + expectedId
			+ std::string(" received: ") + id + std::string("."));
	}
}

SyncFailure::SyncFailure(
		const JalopResponse& response,
		const std::string& expectedId) {
	// getResponseType should have already verified that this is a JALoP sync-failure response, so we won't
	// re-check content-type and message-type
	//
	// SyncFailure has the following headers
	// id
	// error-message
	//
	// extract the required headers
	std::string nextHeader;
	std::string contentLength;
	try {
		nextHeader = std::string(JALN_HDRS_CONTENT_LENGTH);
		contentLength = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_ERROR_MESSAGE);
		errorMessage = response.headers.at(nextHeader);
		nextHeader = std::string(JALN_HDRS_ID);
		id = response.headers.at(nextHeader);
	} catch (std::out_of_range& e) {
		throw InvalidResponse("SyncFailure", std::string("Missing Header: ") + nextHeader);
	}

	// Content length should always be 0
	if(std::string("0") != contentLength) {
		throw InvalidResponse("SyncFailure", std::string("Unexpected non-zero content length: ") + contentLength + ".");
	}

	errors = splitErrors(errorMessage, "SyncFailure");

	// The record id returned must match the expected record id, or some wires have crossed
	if(expectedId != id) {
		throw InvalidResponse("SyncFailure", std::string("Expected Record Id: ") + expectedId
			+ std::string(" received: ") + id + std::string("."));
	}
}

CloseSessionResponse::CloseSessionResponse(const JalopResponse& response) {
	// getResponseType should have already verified that this is a JALoP close-session response, so we
	// won't re-check content-type and message-type
	//
	// CloseSessionResponse has no required headers
	// Nothing to do here, this constructor mostly exists to keep the pattern
	(void)response;
}

static bool get_bytes_on_disk(
	const uint64_t offset,
	uint8_t* const buffer,
	uint64_t* size,
	int fd) {
	if(-1 == lseek64(fd, offset, SEEK_SET)) {
		return false;
	}

	size_t to_read = *size;
	ssize_t bytes_read = read(fd, buffer, to_read);
	if(0 > bytes_read) {
		return false;
	} else {
		*size = bytes_read;
		return true;
	}
}

static void get_bytes_in_memory(
		const uint64_t offset,
		uint8_t* const buffer,
		uint64_t* size,
		const uint8_t* const source,
		const uint64_t source_size) {
	// starting from &source[offset], copy the remaining bytes to buffer
	uint64_t to_copy = source_size - offset;
	// if there are more bytes remaining than "size", only copy "size" bytes
	if(to_copy > *size) {
		to_copy = *size;
	}

	memcpy(buffer, source, to_copy); // nosemgrep - the copy length is less than or equal to the destination buffer size
	*size = to_copy;
}

RecordMessage::RecordMessage(
	const std::string& sessionId,
	const std::string& nonce,
	const enum jaln_record_type paramType,
	const bool paramExpectDigestChallenge,
	const uint8_t* paramSysMeta,
	const uint64_t paramSysMetaLen,
	const uint8_t* paramAppMeta,
	const uint64_t paramAppMetaLen,
	const bool paramPayloadOnDisk,
	const uint64_t paramPayloadLen,
	const int paramPayloadFd,
	const uint8_t* paramPayload,
	const uint64_t paramResumeOffset,
	struct jal_digest_ctx* paramDigestContext) {

	if(paramType != JALN_RTYPE_JOURNAL && paramType != JALN_RTYPE_AUDIT && paramType != JALN_RTYPE_LOG) {
		std::string reason = std::string("Invalid record type enum: ") + std::to_string(paramType) + ".";
		throw InvalidMessage(reason);
	}
	type = paramType;

	// system metadata must always be provided
	if(NULL == paramSysMeta) {
		std::string reason = std::string("System Metadata was NULL.");
		throw InvalidMessage(reason);
	}

	if(0 == paramSysMetaLen) {
		std::string reason = std::string("System Metadata had length 0.");
		throw InvalidMessage(reason);
	}
	sysMeta = paramSysMeta;
	sysMetaLen = paramSysMetaLen;

	if(!(NULL == paramAppMeta && 0 == paramAppMetaLen)
		&& !(NULL != paramAppMeta && 0 != paramAppMetaLen)) {
		std::string reason = std::string("App Metadata length inconsistent with App Metadata pointer.");
		throw InvalidMessage(reason);
	}
	appMeta = paramAppMeta;
	appMetaLen = paramAppMetaLen;

	// Option 1: no payload, Len=0, fd=-1, payload* is NULL
	if(!(0 == paramPayloadLen && NULL == paramPayload && -1 == paramPayloadFd)
		// Option 2: payload is on disk, len!=0, fd!=-1, payload* is a don't care
		// When receiving from the filter, we don't actually have the payload (i.e. filename) available
		// and payload will be NULL
		// When not using the filter, payload will have the filename, but we already have an open
		// file descriptor, so we don't need it at this point
		&& !(paramPayloadOnDisk && 0 != paramPayloadLen && -1 != paramPayloadFd)
		// Option 3: payload is not on disk, len!=0, fd=-1, payload* is not NULL
		&& !(!paramPayloadOnDisk && 0 != paramPayloadLen && NULL != paramPayload && -1 == paramPayloadFd)) {
		// All other combinations are invalid
		std::string reason = std::string("Payload length/OnDisk indicator inconsistent with Payload pointer/file-descriptor.");
		throw InvalidMessage(reason);
	}
	payload = paramPayload;
	payloadLen = paramPayloadLen;
	payloadFd = paramPayloadFd;
	payloadOnDisk = paramPayloadOnDisk;

	if(0 != resumeOffset && type != JALN_RTYPE_JOURNAL) {
		std::string reason = std::string("Resume offset provided for non-journal Record.");
		throw InvalidMessage(reason);
	}
	resumeOffset = paramResumeOffset;

	if(paramExpectDigestChallenge && NULL == paramDigestContext) {
		std::string reason = std::string("DigestChallenge is required, but the provided Digest Context was NULL.");
		throw InvalidMessage(reason);
	}

	if(paramExpectDigestChallenge && !jal_digest_ctx_is_valid(paramDigestContext)) {
		std::string reason = std::string("DigestChallenge is required, but the provided Digest Context was invalid.");
		throw InvalidMessage(reason);
	}

	expectDigestChallenge = paramExpectDigestChallenge;
	digestContext = paramDigestContext;

	// Parameter validation complete
	// If we're doing a digest challenge, initialize the digest instance
	// Note - the destructor for RecordMessage only runs if the constructor succesfully executes
	// If we're going to throw out of this constructor, we're responsible for cleaning up anything we
	// allocate within it
	if(expectDigestChallenge) {
		digestInstance = digestContext->create();
		if(NULL == digestInstance) {
			std::string reason = std::string("Failed to create the instance for digest algorithm: ")
				+ digestContext->algorithm_uri + ".";
			throw InvalidMessage(reason);
		}

		if(JAL_OK != digestContext->init(digestInstance)) {
			digestContext->destroy(digestInstance);
			std::string reason = std::string("Failed to init the instance for digest algorithm: ")
				+ digestContext->algorithm_uri + ".";
			throw InvalidMessage(reason);
		}

		// Process the system metadata through our digest instance
		if(JAL_OK != digestContext->update(digestInstance, sysMeta, sysMetaLen)) {
			digestContext->destroy(digestInstance);
			std::string reason = std::string("Failed to process system metadata with digest algorithm: ")
				+ digestContext->algorithm_uri + ".";
			throw InvalidMessage(reason);
		}

		// Process the application metadata through our digest instance
		if(JAL_OK != digestContext->update(digestInstance, appMeta, appMetaLen)) {
			digestContext->destroy(digestInstance);
			std::string reason = std::string("Failed to process application metadata with digest algorithm: ")
				+ digestContext->algorithm_uri + ".";
			throw InvalidMessage(reason);
		}

		// If we're doing a journal resume, pre-process the bytes we aren't re-sending
		constexpr size_t BUF_SIZE = 4*1024;
		uint8_t buf[BUF_SIZE];
		uint64_t currentOffset = 0;
		// Proceed until we have processed resumeOffset bytes
		while(currentOffset < resumeOffset) {
			// Determine how many bytes are left to process
			uint64_t remaining = resumeOffset - currentOffset;
			// Process either BUF_SIZE or remaining, whichever is smaller
			uint64_t to_process;
			if(remaining > BUF_SIZE) {
				to_process = BUF_SIZE;
			} else {
				to_process = remaining;
			}

			// Fetch the bytes
			if(payloadOnDisk) {
				if(!get_bytes_on_disk(currentOffset, buf, &to_process, payloadFd)) {
					digestContext->destroy(digestInstance);
					std::string reason = std::string("Failed to fetch bytes for resume payload processing.");
					throw InvalidMessage(reason);
				}
			} else {
				// Infallible
				get_bytes_in_memory(currentOffset, buf, &to_process, payload, payloadLen);
			}

			// Process the bytes from buf
			if(JAL_OK != digestContext->update(digestInstance, buf, to_process)) {
				digestContext->destroy(digestInstance);
				std::string reason = std::string("Failed to fetch process resume payload with digest algorithm: .")
					+ digestContext->algorithm_uri + ".";
				throw InvalidMessage(reason);
			}
			currentOffset += to_process;
		}
	}

	// Calculate the size of the data we're actually going to send after accounting for the resumeOffset, if any
	postSize = sysMetaLen;
	if(appMetaLen > UINT64_MAX - postSize) {
		throw SendFailure("Record size exceeds UINT64_MAX.");
	}
	postSize += appMetaLen;
	uint64_t realPayloadLen = payloadLen - resumeOffset;
	if(realPayloadLen > UINT64_MAX - postSize) {
		throw SendFailure("Record size exceeds UINT64_MAX.");
	}
	postSize += realPayloadLen;
	if(3*strlen(JALN_STR_BREAK) > UINT64_MAX - postSize) {
		throw SendFailure("Record size exceeds UINT64_MAX.");
	}
	postSize += 3*strlen(JALN_STR_BREAK);


	// We have a record to send, form up the headers
	headers[JALN_HDRS_SESSION_ID] = sessionId;
	headers[JALN_HDRS_ID] = nonce;
	headers[JALN_HDRS_SYS_META_LEN] = std::to_string(sysMetaLen);
	headers[JALN_HDRS_APP_META_LEN] = std::to_string(appMetaLen);
	switch(type) {
		case JALN_RTYPE_LOG:
			headers[JALN_HDRS_MESSAGE] = std::string(JALN_MSG_LOG);
			headers[JALN_HDRS_LOG_LEN] = std::to_string(realPayloadLen);
			break;
		case JALN_RTYPE_AUDIT:
			headers[JALN_HDRS_MESSAGE] = std::string(JALN_MSG_AUDIT);
			headers[JALN_HDRS_AUDIT_LEN] = std::to_string(realPayloadLen);
			break;
		case JALN_RTYPE_JOURNAL:
			headers[JALN_HDRS_MESSAGE] = std::string(JALN_MSG_JOURNAL);
			headers[JALN_HDRS_JOURNAL_LEN] = std::to_string(realPayloadLen);
			break;
		default:
			// Shouldn't be possible, checked above
			digestContext->destroy(digestInstance);
			std::string reason = std::string("Invalid record type enum: ") + std::to_string(type) + ".";
			throw InvalidMessage(reason);
	}
	if(JALN_RTYPE_AUDIT == type) {
		headers[JALN_HDRS_AUDIT_FORMAT] = "xml";
	}
	// TODO - We don't do anything wtih Priority right now
}

RecordMessage::~RecordMessage() {
	// We own the instance, not the context. Use the context to clean up the instances
	// but do not destroy the context
	if(NULL != digestInstance && NULL != digestContext) {
		digestContext->destroy(digestInstance);
	}
	free(calculatedDigest);
}

class ReadFunctionFault : public std::runtime_error {
	public:
	ReadFunctionFault(const std::string& reason) : std::runtime_error(reason) {}
};

struct ReadFunctionState {
	enum class ReadState {
		SysMeta,
		Break1,
		AppMeta,
		Break2,
		Payload,
		Break3,
		Done,
	};

	const uint8_t* sysMeta;
	const uint64_t sysMetaLen;
	const uint8_t* appMeta;
	const uint64_t appMetaLen;
	const bool payloadOnDisk;
	const uint64_t payloadLen;
	const uint8_t* payload;
	const int payloadFd;

	static constexpr uint64_t BREAK_SIZE = 5;
	static constexpr uint8_t breakBytes[BREAK_SIZE] = { 'B', 'R', 'E', 'A', 'K' };

	uint64_t resumeOffset;
	uint64_t progress = 0;
	ReadState readState = ReadState::SysMeta;
	struct jal_digest_ctx* digestContext;
	void* digestInstance;

	uint8_t* calculatedDigest = NULL;

	ReadFunctionState(
		const uint8_t* paramSysMeta,
		const uint64_t paramSysMetaLen,
		const uint8_t* paramAppMeta,
		const uint64_t paramAppMetaLen,
		const bool paramPayloadOnDisk,
		const uint64_t paramPayloadLen,
		const uint8_t* paramPayload,
		const int paramPayloadFd,
		const uint64_t paramResumeOffset,
		struct jal_digest_ctx* paramDigestContext,
		void* paramDigestInstance) : 
			sysMeta(paramSysMeta),
			sysMetaLen(paramSysMetaLen), 
			appMeta(paramAppMeta),
			appMetaLen(paramAppMetaLen),
			payloadOnDisk(paramPayloadOnDisk),
			payloadLen(paramPayloadLen),
			payload(paramPayload),
			payloadFd(paramPayloadFd),
			resumeOffset(paramResumeOffset),
			digestContext(paramDigestContext),
			digestInstance(paramDigestInstance) {}

	const uint8_t* readFrom() {
		switch(readState) {
			case ReadState::SysMeta:
				return sysMeta + progress;
			case ReadState::Break1:
			case ReadState::Break2:
			case ReadState::Break3:
				return (const uint8_t*)(&breakBytes) + progress;
			case ReadState::AppMeta:
				return appMeta + progress;
			case ReadState::Payload:
				if(payloadOnDisk) {
					return NULL;
				} else {
					return payload + progress;
				}
			case ReadState::Done:
			default:
				std::string reason = std::string("ReadFunction attempt to read with invalid state or no more data.");
				throw ReadFunctionFault(reason);
		}
	}

	uint64_t readMax() {
		switch(readState) {
			case ReadState::SysMeta:
				return sysMetaLen - progress;
			case ReadState::Break1:
			case ReadState::Break2:
			case ReadState::Break3:
				return BREAK_SIZE - progress;
			case ReadState::AppMeta:
				return appMetaLen - progress;
			case ReadState::Payload:
				return payloadLen - progress;
			case ReadState::Done:
			default:
				std::string reason = std::string("ReadFunction attempt to read with invalid state or no more data.");
				throw ReadFunctionFault(reason);
		}
	}

	void advance(uint64_t readAmount) {
		progress += readAmount;
		ReadState next;
		uint64_t currentLen;
		switch(readState) {
			case ReadState::SysMeta:
				next = ReadState::Break1;
				currentLen = sysMetaLen;
				break;
			case ReadState::Break1:
				next = ReadState::AppMeta;
				currentLen = BREAK_SIZE;
				break;
			case ReadState::AppMeta:
				next = ReadState::Break2;
				currentLen = appMetaLen;
				break;
			case ReadState::Break2:
				next = ReadState::Payload;
				currentLen = BREAK_SIZE;
				break;
			case ReadState::Payload:
				next = ReadState::Break3;
				currentLen = payloadLen;
				break;
			case ReadState::Break3:
				next = ReadState::Done;
				currentLen = BREAK_SIZE;
			break;
			case ReadState::Done:
			default:
				std::string reason = std::string("ReadFunction attempt to advance with invalid state.");
				throw ReadFunctionFault(reason);
		}
		if(currentLen < progress) {
				std::string reason = std::string("ReadFunction attempt to advance beyond bounds of current segment");
				throw ReadFunctionFault(reason);
		} else if(currentLen == progress) {
			// If we're done with the current segment, and that segment is Payload, we're done calculating the
			// digest value. Finalize and capture the digest value.
			if(digestContext
					&& digestInstance
					&& ReadState::Payload == readState) {
				// Use malloc, not new, this may be passed up to a C context and freed there
				calculatedDigest = (uint8_t*)malloc(digestContext->len);
				if(JAL_OK != digestContext->final(digestInstance, calculatedDigest, (unsigned int*)&digestContext->len)) {
					std::string reason = std::string("Failed to calculate digest of outgoing record.");
					throw ReadFunctionFault(reason);
				}
			}
			progress = 0;
			readState = next;
			// If we're about to start with the payload segment and ResumeOffset is not 0,
			// set progress to resumeOffset so we skip the bytes which have already been
			// transmitted.
			if(ReadState::Payload == readState) {
				progress = resumeOffset;
			}
		} else {
			// State remains unchanged, progress already set, nothing to do here
		}
	}

	~ReadFunctionState() {
		free(calculatedDigest);
	}

	uint8_t* takeCalculatedDigest() {
		uint8_t* tmp = calculatedDigest;
		calculatedDigest = NULL;
		return tmp;
	}
};

size_t readFunction(void *b, size_t size, size_t nmemb, void* userdata) {
	uint64_t destSize = size*nmemb;
	if(NULL == b || NULL == userdata || 0 == destSize) {
		fprintf(stderr, "CURL readfunction passed bad arguments.\n");
		return CURL_READFUNC_ABORT;
	}

	uint64_t writeOffset = 0;
	uint8_t* writeBuffer = (uint8_t*)b;
	try {
		ReadFunctionState* readFunctionState = (ReadFunctionState*)userdata;

		while(writeOffset < destSize && ReadFunctionState::ReadState::Done != readFunctionState->readState) {
			uint64_t writeMax = destSize - writeOffset;
			uint8_t* writeTo = writeBuffer + writeOffset;
			uint64_t readMax = readFunctionState->readMax();
			const uint8_t* readFrom = readFunctionState->readFrom();

			uint64_t readAmount = readMax;
			if(writeMax < readMax) {
				readAmount = writeMax;
			}

			// The payload and app meta segments can legally be length 0
			// Skip processing and move straight to advance() for these segments
			if(0 != readAmount) {
				if(NULL != readFrom) {
					memcpy(writeTo, readFrom, readAmount); // nosemgrep - the copy length is less than or equal to the destination buffer size
				} else {
					// Need to read the payload from disk
					off64_t err = lseek64(readFunctionState->payloadFd, readFunctionState->progress, SEEK_SET);
					if(-1 == err) {
						fprintf(stderr, "CURL readfunction failed to seek in payload file.\n");
						return CURL_READFUNC_ABORT;
					}
					ssize_t bytes_read = read(readFunctionState->payloadFd, writeTo, readAmount);
					if(0 > bytes_read) {
						fprintf(stderr, "CURL readfunction read from payload file.\n");
						return CURL_READFUNC_ABORT;
					}
				}
				
				// If this was a chunk of payload and the digestContext/Instance are available,
				// run the digest calculation over it in the destination buffer
				if(readFunctionState->digestContext
						&& readFunctionState->digestInstance
						&& ReadFunctionState::ReadState::Payload == readFunctionState->readState) {
					if(JAL_OK!= readFunctionState->digestContext->update(
							readFunctionState->digestInstance, writeTo, readAmount)) {
						// TODO - add some specific error return state to the readFunctionState so we can
						// disambiguate failure reasons
						fprintf(stderr, "CURL readfunction failed to update digest.\n");
						return CURL_READFUNC_ABORT;
					}
				}
			}

			readFunctionState->advance(readAmount);
			writeOffset += readAmount;
		}
	} catch(const ReadFunctionFault& e) {
		fprintf(stderr, "Internal fault in curl readFunction: %s\n", e.what());
		return CURL_READFUNC_ABORT;
	}
	return writeOffset;
}

JalopResponse RecordMessage::sendMessage(
	CURL* curl,
	const long curl_timeout_period,
	const long curl_retry_count) {
	if(NULL == curl) {
		throw SendFailure("CURL context invalid when attempting to send message");
	}

	// What to do with incoming payload - we don't expect any, so we drop it
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, jaln_noop_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
	// How big our outgoing payload is
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, postSize);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	ReadFunctionState sendState(
			sysMeta,
			sysMetaLen,
			appMeta,
			appMetaLen,
			payloadOnDisk,
			payloadLen,
			payload,
			payloadFd,
			resumeOffset,
			digestContext,
			digestInstance);

	// Where to get the outgoing payload
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, readFunction);
	curl_easy_setopt(curl, CURLOPT_READDATA, (void*)&sendState);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_handler);
	JalopResponse response;
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void*)&response);

	// All messages need headers
	struct curl_slist *curl_headers = NULL;
	for(const auto& [key, value] : headers) {
		add_header(key.c_str(), value.c_str(), &curl_headers);
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);

	// All messages may return errors during sending
	char buf[CURL_ERROR_SIZE];
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, &buf);

	// Configure the optional timeout for all messages
	if(curl_timeout_period > 0) {
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, curl_timeout_period);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	}

	// Do the send, retrying a configurable number of times if necessary
	CURLcode rc = CURLE_OK;
	int retry_count = 0;
	do {
		retry_count++;
		rc = curl_easy_perform(curl);
	} while(CURLE_COULDNT_CONNECT == rc && retry_count < curl_retry_count);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, NULL);
	curl_slist_free_all(curl_headers);

	// If the final result is not OK, throw an exception with the appropriate error message
	if(CURLE_OK != rc) {
		std::string errMsg = std::string("Curl error: (")
			+ std::to_string(rc) + std::string("): ") + std::string(buf);
		throw SendFailure(errMsg);
	}

	// Send succesful, steal the calculated digest from the readFunctionState before returning
	calculatedDigest = sendState.takeCalculatedDigest();
	return response;
}

uint8_t* RecordMessage::takeCalculatedDigest() {
	uint8_t* tmp = calculatedDigest;
	calculatedDigest = NULL;
	return tmp;
}
