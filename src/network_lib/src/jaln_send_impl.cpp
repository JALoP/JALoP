/**
 * @file
 *
 * @brief This file contains function
 * definitions for internal library functions related to sending a JALoP
 * record from the publisher to the subscriber.
 *
 * ### LICENSE
 *
 * Copyright (C) 2018-2026 Concurrent Technologies Corporation.
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
#include "jalop_protocol.hpp"
#include "jaln_send_impl.h"
#include <string>
extern "C" {
	#include <jalop/jaln_network_types.h>
	#include "jaln_string_utils.h"
	#include <jalop/jal_status.h>
	#include "jaln_session.h"
	#include "jaldb_record.h"
	#include "jaldb_segment.h"
}
enum jal_status jaln_send_record_impl(
	jaln_session* sess,
	struct jaldb_record* rec,
	uint8_t** digestOut,
	uint32_t* digestLenOut,
	uint8_t** peerDigestOut,
	uint32_t* peerDigestLenOut) {

	if(NULL == digestOut
		|| NULL == digestLenOut
		|| NULL == peerDigestOut
		|| NULL == peerDigestLenOut
		|| NULL == sess
		|| NULL == sess->ch_info
		|| NULL == rec
		|| NULL == rec->sys_meta
		|| NULL == rec->app_meta
		|| NULL == rec->payload) {
		return JAL_E_INVAL_PARAM;
	}
	*digestOut = NULL;
	*peerDigestOut = NULL;
	*digestLenOut = 0;
	*peerDigestLenOut = 0;
	std::string nonce = std::string(rec->network_nonce);
	std::string sessionId = std::string(sess->id);
	bool expectDigestChallenge = 0 != sess->dgst_on;
	// Used for constructing friendlier error messages
	std::string recordType;
	switch(sess->ch_info->type) {
		case JALN_RTYPE_JOURNAL:
			recordType = std::string("journal");
			break;
		case JALN_RTYPE_AUDIT:
			recordType = std::string("audit");
			break;
		case JALN_RTYPE_LOG:
			recordType = std::string("log");
			break;
		default:
			recordType = std::string("unknown record type");
			break;
	}

	// Special Case - Journal Resume
	// If we are doing a journal resume and we're using the filter,
	// the network nonce on the record we received may not match
	// the nonce in pub_data.
	// This is the first point at which we can know if the record we
	// requested to resume via the filter was actually present.
	// If the sesss->pub_data->nonce is not NULL and doesn't match
	// the nonce of the record we actually received, we need to emit
	// journal-missing before going ahed with the record we received
	if(NULL != sess->pub_data->resume_nonce && 0 != strcmp(sess->pub_data->resume_nonce, rec->network_nonce)) {
		try {
			// Whatever the result of sending journal-missing, we will not resume
			// this record, wipe out the resume data.
			std::string resumeNonce(sess->pub_data->resume_nonce);
			free(sess->pub_data->resume_nonce);
			sess->pub_data->resume_nonce = NULL;
			sess->pub_data->resume_off = 0;

			// May throw InvalidMessage
			JournalMissingMessage journalMissingMessage(
				sessionId,
				resumeNonce);

			// May throw SendFailure
			JalopResponse response = journalMissingMessage.sendMessage(
				sess->curl_ctx,
				sess->jaln_ctx->network_timeout * 60L,
				sess->jaln_ctx->http_client_retry_count);

			// Valid responses to Journal Missing
			// JournalMissingResponse - succes, no action
			// SessionFailure - session is bad, return failure, do not subscribe
			// RecordFailure - warn, no action
			// May throw MalformedResponse
			ResponseType responseType = response.getResponseType();

			switch(responseType) {
				case ResponseType::JournalMissingResponse:
				{
					// No action - all is well
					//
					// May throw InvalidResponse
					JournalMissingResponse journalMissingResponse(response);
					// If this doesn't throw, this exchange was succesful, do nothing
					break;
				}
				case ResponseType::RecordFailure:
				{
					// Warn, the subscriber apparently forgot about the record
					// it requested to resume, but that means it no longer exists, which
					// is the desired result
					//
					// May throw InvalidResponse
					RecordFailure recordFailure(
						response,
						resumeNonce);
					fprintf(stderr, "Received Record Failure from Subscriber in response to journal-missing for session: %s, id: %s\n",
							sess->id, recordFailure.id.c_str());
					for(const auto& err : recordFailure.errors) {
						fprintf(stderr, "  %s\n", err.c_str());
					}
					break;
				}
				case ResponseType::SessionFailure:
				{
					// The session is broken, signal an error and bail out early
					SessionFailure sessionFailure(response,
						resumeNonce,
						std::string(sess->id));
					fprintf(stderr, "Received Session Failure from Subscriber in response to journal-missing for session: %s\n",
						sess->id);
						for(const auto& err : sessionFailure.errors) {
							fprintf(stderr, "  %s\n", err.c_str());
						}
						jaln_session_set_errored(sess);
						return JAL_E_SESSION_FAILURE;
					break;
				}
				default:
				{
					std::string messageTypeString = response.getResponseTypeString();
					throw InvalidResponseType(messageTypeString);
				}
			}
		} catch(InvalidMessage& e) {
			fprintf(stderr, "Failed to construct journal-missing: %s\n", e.what());
			jaln_session_set_errored(sess);
			return JAL_E_INVAL_PARAM;
		} catch(SendFailure& e) {
			fprintf(stderr, "Failed to send journal-missing: %s\n", e.what());
			jaln_session_set_errored(sess);
			return JAL_E_SESSION_FAILURE;
		} catch(MalformedResponse &e) {
			fprintf(stderr, "Malformed Response: %s\n", e.what());
			jaln_session_set_errored(sess);
			return JAL_E_SESSION_FAILURE;
		} catch(InvalidResponseType &e) {
			fprintf(stderr, "Invalid response to journal-missing: %s\n", e.what());
			jaln_session_set_errored(sess);
			return JAL_E_SESSION_FAILURE;
		} catch(InvalidResponse &e) {
			fprintf(stderr, "Response message of type: %s is invalid. Reason: %s\n",
				e.responseType.c_str(),
				e.reason.c_str());
			jaln_session_set_errored(sess);
			return JAL_E_SESSION_FAILURE;
		}
	}

	try {
		// Latch the resume offset, if any, and clear it from the pub_data
		uint64_t resumeOff = sess->pub_data->resume_off;
		sess->pub_data->resume_off = 0;
		// Clear the resume_nonce from pub_data. If we reach this point
		// we're either doing the resume, or journal-missing has already been
		// sent
		free(sess->pub_data->resume_nonce);
		sess->pub_data->resume_nonce = NULL;

		// May throw InvalidMessage
		RecordMessage recordMsg(
			sessionId,
			nonce,
			sess->ch_info->type,
			expectDigestChallenge,
			rec->sys_meta->payload,
			rec->sys_meta->length,
			rec->app_meta->payload,
			rec->app_meta->length,
			0 != rec->payload->on_disk,
			rec->payload->length,
			rec->payload->fd,
			rec->payload->payload,
			resumeOff,
			sess->dgst);

		// May throw SendFailure
		JalopResponse response = recordMsg.sendMessage(
			sess->curl_ctx,
			sess->jaln_ctx->network_timeout * 60L,
			sess->jaln_ctx->http_client_retry_count);

		// Set the digest out param
		*digestOut = recordMsg.takeCalculatedDigest();
		*digestLenOut = sess->dgst->len;

		// Valid responses to RecordMessage are
		// Sync - when digest challenge is disbled
		// SyncFailure - when digest challenge is disabled
		// DigestChallenge - when digest challenge in enabled
		// RecordFailure
		// SessionFailure
		// May throw MalformedResponse
		ResponseType responseType = response.getResponseType();

		switch(responseType) {
			case ResponseType::DigestChallenge:
			{
				if(!expectDigestChallenge) {
					std::string messageTypeString = response.getResponseTypeString();
					throw InvalidResponseType(messageTypeString);
				}

				// May throw InvalidResponse
				DigestChallenge digestChallenge(response,
					nonce);

				// digest-value is a stringified hex number
				// Convert it to a binary buffer that the rest of the publisher expects
				uint64_t outLenTmp;
				// jaln_hex_str_to_bit_buf wants uint64_t lengths, but our digest objects
				// want uint32_t so some type wiggling is required
				if(JAL_OK != jaln_hex_str_to_bin_buf(
						digestChallenge.digestValue.c_str(),
						(uint64_t)digestChallenge.digestValue.length(),
						peerDigestOut,
						&outLenTmp)) {
					free(*peerDigestOut);
					std::string reason = std::string("Failed to convert digest-value string: ") + digestChallenge.digestValue
						+ " to binary representation.";
					throw InvalidResponse("DigestChallenge", reason);
				}
				if(UINT32_MAX < outLenTmp) {
					std::string reason = std::string("Peer digest length is larger than UIN32_MAX");
					throw InvalidResponse("DigestChallenge", reason);
				}
				*peerDigestLenOut = (uint32_t) outLenTmp;
				// The digests have been placed in the out-value locations
				return JAL_OK;
			}
			case ResponseType::Sync:
			{
				if(expectDigestChallenge) {
					std::string messageTypeString = response.getResponseTypeString();
					throw InvalidResponseType(messageTypeString);
				}
				// May throw InvalidResponse
				Sync sync(response,
					nonce);

				// No additional checks
				return JAL_OK;
			}
			case ResponseType::SyncFailure:
			{
				if(expectDigestChallenge) {
					std::string messageTypeString = response.getResponseTypeString();
					throw InvalidResponseType(messageTypeString);
				}
				// May throw InvalidResponse
				SyncFailure syncFailure(response, nonce);
				fprintf(stderr, "Received Sync Failure from Subscriber in response to %s-record for session: %s, id: %s\n",
						recordType.c_str(), sessionId.c_str(), syncFailure.id.c_str());
				for(const auto& err : syncFailure.errors) {
					fprintf(stderr, "  %s\n", err.c_str());
				}
				return JAL_E_RECORD_FAILURE;
			}
			case ResponseType::RecordFailure:
			{
				// May throw InvalidResponse
				RecordFailure recordFailure(
					response,
					nonce);
				fprintf(stderr, "Received Record Failure from Subscriber in response to %s-record for session: %s, id: %s\n",
						recordType.c_str(), sessionId.c_str(), recordFailure.id.c_str());
				for(const auto& err : recordFailure.errors) {
					fprintf(stderr, "  %s\n", err.c_str());
				}
				return JAL_E_RECORD_FAILURE;
			}
			case ResponseType::SessionFailure:
			{
				// The session is broken, signal an error and bail out early
				SessionFailure sessionFailure(response,
					nonce,
					sessionId);
				fprintf(stderr, "Received Session Failure from Subscriber in response to %s-record for session: %s, id: %s\n",
					recordType.c_str(), sessionId.c_str(), sessionFailure.id.c_str());
					for(const auto& err : sessionFailure.errors) {
						fprintf(stderr, "  %s\n", err.c_str());
					}
					return JAL_E_SESSION_FAILURE;
			}
			default:
			{
				std::string messageTypeString = response.getResponseTypeString();
				throw InvalidResponseType(messageTypeString);
			}
		}
	} catch(InvalidMessage& e) {
		fprintf(stderr, "Failed to construct %s-record: %s\n", recordType.c_str(), e.what());
		return JAL_E_INVAL_PARAM;
	} catch(SendFailure& e) {
		fprintf(stderr, "Failed to send %s-record: %s\n", recordType.c_str(), e.what());
		return JAL_E_SESSION_FAILURE;
	} catch(MalformedResponse &e) {
		fprintf(stderr, "Malformed Response: %s\n", e.what());
		return JAL_E_SESSION_FAILURE;
	} catch(InvalidResponseType &e) {
		fprintf(stderr, "Invalid response to %s-record: %s\n", recordType.c_str(), e.what());
		return JAL_E_SESSION_FAILURE;
	} catch(InvalidResponse &e) {
		fprintf(stderr, "Response message of type: %s is invalid. Reason: %s\n",
			e.responseType.c_str(),
			e.reason.c_str());
		return JAL_E_SESSION_FAILURE;
	}
}

enum jal_status jaln_send_digest_response_impl(
	jaln_session* sess,
	const char* paramNonce,
	const uint8_t* localDigest,
	const uint32_t localLen,
	const uint8_t* peerDigest,
	const int32_t peerLen) {
	if(NULL == sess
		|| NULL == sess->id
		|| NULL == paramNonce
		|| NULL == localDigest
		|| NULL == peerDigest) {
		return JAL_E_INVAL_PARAM;
	}
	std::string nonce = std::string(paramNonce);
	std::string sessionId = std::string(sess->id);
	// Used for constructing friendlier error messages
	try {
		// May throw InvalidMessage
		DigestResponseMessage digestResponseMessage(
			sessionId,
			nonce,
			localDigest,
			localLen,
			peerDigest,
			peerLen);

		// May throw SendFailure
		JalopResponse response = digestResponseMessage.sendMessage(
			sess->curl_ctx,
			sess->jaln_ctx->network_timeout * 60L,
			sess->jaln_ctx->http_client_retry_count);

		// Valid responses to DigestResponseMEssage are
		// Sync
		// SyncFailure
		// RecordFailure
		// SessionFailure
		// May throw MalformedResponse
		ResponseType responseType = response.getResponseType();

		switch(responseType) {
			case ResponseType::Sync:
			{
				// May throw InvalidResponse
				Sync sync(response,
					nonce);

				// No additional checks
				return JAL_OK;
			}
			case ResponseType::SyncFailure:
			{
				// May throw InvalidResponse
				SyncFailure syncFailure(response, nonce);
				fprintf(stderr, "Received Sync Failure from Subscriber in response to digest-response for session: %s, id: %s\n",
					sessionId.c_str(), syncFailure.id.c_str());
				for(const auto& err : syncFailure.errors) {
					fprintf(stderr, "  %s\n", err.c_str());
				}
				return JAL_E_RECORD_FAILURE;
			}
			case ResponseType::RecordFailure:
			{
				// May throw InvalidResponse
				RecordFailure recordFailure(
					response,
					nonce);
				fprintf(stderr, "Received Record Failure from Subscriber in response to digest-response for session: %s, id: %s\n",
					sessionId.c_str(), recordFailure.id.c_str());
				for(const auto& err : recordFailure.errors) {
					fprintf(stderr, "  %s\n", err.c_str());
				}
				return JAL_E_RECORD_FAILURE;
			}
			case ResponseType::SessionFailure:
			{
				// The session is broken, signal an error and bail out early
				SessionFailure sessionFailure(response,
					nonce,
					sessionId);
				fprintf(stderr, "Received Session Failure from Subscriber in response to digest-responase for session: %s, id: %s\n",
					sessionId.c_str(), sessionFailure.id.c_str());
				for(const auto& err : sessionFailure.errors) {
					fprintf(stderr, "  %s\n", err.c_str());
				}
				return JAL_E_SESSION_FAILURE;
			}
			default:
			{
				std::string messageTypeString = response.getResponseTypeString();
				throw InvalidResponseType(messageTypeString);
			}
		}
	} catch(InvalidMessage& e) {
		fprintf(stderr, "Failed to construct digest-response: %s\n", e.what());
		return JAL_E_INVAL_PARAM;
	} catch(SendFailure& e) {
		fprintf(stderr, "Failed to send digest-response: %s\n", e.what());
		return JAL_E_SESSION_FAILURE;
	} catch(MalformedResponse &e) {
		fprintf(stderr, "Malformed Response: %s\n", e.what());
		return JAL_E_SESSION_FAILURE;
	} catch(InvalidResponseType &e) {
		fprintf(stderr, "Invalid response to digest-response: %s\n", e.what());
		return JAL_E_SESSION_FAILURE;
	} catch(InvalidResponse &e) {
		fprintf(stderr, "Response message of type: %s is invalid. Reason: %s\n",
			e.responseType.c_str(),
			e.reason.c_str());
		return JAL_E_SESSION_FAILURE;
	}
}
