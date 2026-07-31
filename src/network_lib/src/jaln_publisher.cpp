/**
 * @file
 *
 * @brief This file contains function
 * definitions related to the jal publisher.
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
#include <stdexcept>
#include "jalop_protocol.hpp"

extern "C" {
#include <jalop/jaln_publisher_callbacks.h>
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#include "jaln_context.h"
#include "jaln_connection.h"
#include "jaln_connection_callbacks_internal.h"
#include "jaln_digest_info.h"
#include "jaln_digest_resp_info.h"
#include "jaln_message_helpers.h"
#include "jaln_publisher.h"
#include "jaln_publisher_callbacks_internal.h"
#include "jaln_session.h"
}

static void jaln_split_errors(char *errors, int *error_cnt, char ***error_list);

enum jal_status jaln_publisher_send_init(jaln_session *session)
{
	if (!session || !session->ch_info || !session->jaln_ctx || !session->curl_ctx || !session->pub_data) {
		// shouldn't ever happen
		return JAL_E_INVAL;
	}

	const long curl_timeout_period = session->jaln_ctx->network_timeout * 60L;
	CURL* curl = session->curl_ctx;

	// We want to latch resume info - if any - received in the init-ack response for later use
	std::string resumeNonce;
	uint64_t resumeOffset = 0;
	try {
		// May throw InvalidMessage
		InitMessage initMsg(
			session->mode,
			session->ch_info->type,
			std::string(session->jaln_ctx->pub_id),
			session->jaln_ctx->digest_challenge,
			session->jaln_ctx->dgst_algs,
			session->jaln_ctx->xml_compressions);

		// May throw SendFailure
		JalopResponse response = initMsg.sendMessage(
			curl,
			curl_timeout_period,
			session->jaln_ctx->http_client_retry_count);

		// Valid responses to Init are
		// InitAck
		// InitNack
		// May throw MalformedResponse
		ResponseType responseType = response.getResponseType();

		switch(responseType) {
			case ResponseType::InitAck:
			{
				// May throw InvalidResponse
				InitAck initAck(response,
					session->jaln_ctx->dgst_algs,
					session->jaln_ctx->xml_compressions,
					session->jaln_ctx->digest_challenge,
					session->mode,
					session->ch_info->type);

				// extract InitAck values and store them in the session
				session->ch_info->compression = strdup(initAck.xmlCompression.c_str());
				// For some reason, jald's pub_sync callback uses the NULLness of
				// ch_info->digest_method to decide whether it should sync records in the
				// DB, so it needs to be NULL if digest challenge is disabled.
				if(initAck.challengeDigest) {
					session->dgst_on = 1;
					free(session->ch_info->digest_method);
					session->ch_info->digest_method = strdup(initAck.digestAlgorithmUri.c_str());
				} else {
					session->dgst_on = 0;
					free(session->ch_info->digest_method);
					session->ch_info->digest_method = NULL;
				}
				session->dgst = jal_digest_ctx_create(initAck.digestAlgorithm);
				session->id = strdup(initAck.sessionId.c_str());
				// latch the resume info for later use
				resumeNonce = initAck.id;
				resumeOffset = initAck.offset;

				// connection ack callback
				struct jaln_connect_ack ack;
				memset(&ack, 0, sizeof(ack));
				ack.hostname = session->ch_info->hostname;
				ack.addr = session->ch_info->addr;
				ack.jaln_version = JALN_JALOP_VERSION_TWO;

				session->jaln_ctx->conn_callbacks->connect_ack(&ack, session->jaln_ctx->user_data);

				break;
			}
			case ResponseType::InitNack:
			{
				// May throw InvalidResponse
				InitNack initNack(response);
				// The callback on_connect_nack expects this nack structure, keeping it
				// for api consistency.
				struct jaln_connect_nack nack;
				memset(&nack, 0, sizeof(nack));
				nack.ch_info = session->ch_info;
				// strtok in jaln_split_errors can't operate on .c_str()'s const char*
				char* errorMessageCopy = strdup(initNack.errorMessage.c_str());
				jaln_split_errors(errorMessageCopy, &nack.error_cnt, &nack.error_list);
				session->jaln_ctx->conn_callbacks->connect_nack(&nack, session->jaln_ctx->user_data);
				// Note: jaln_split_errors leaves the tokens in the original string, do not free
				// until after the nack callback
				free(errorMessageCopy);
				// also free the error list, which is an allocated list of pointers back into the original
				// string
				// TODO: Do this in a way that isn't a cleverly disguised landmine for future maintainers
				free(nack.error_list);
				return JAL_E_INVAL;
				break;
			}
			default:
			{
				std::string messageTypeString = response.getResponseTypeString();
				throw InvalidResponseType(messageTypeString);
			}
		}
	} catch(InvalidMessage& e) {
		fprintf(stderr, "Failed to construct initialize: %s\n", e.what());
		jaln_session_set_errored(session);
		return JAL_E_INVAL;
	} catch(SendFailure& e) {
		fprintf(stderr, "Failed to send initialize: %s\n", e.what());
		jaln_session_set_errored(session);
		return JAL_E_COMM;
	} catch(MalformedResponse &e) {
		fprintf(stderr, "Malformed Response: %s\n", e.what());
		jaln_session_set_errored(session);
		return JAL_E_INVAL;
	} catch(InvalidResponseType &e) {
		fprintf(stderr, "Invalid response to initialize: %s\n", e.what());
		jaln_session_set_errored(session);
		return JAL_E_INVAL;
	} catch(InvalidResponse &e) {
		fprintf(stderr, "Response message of type: %s is invalid. Reason: %s\n",
			e.responseType.c_str(),
			e.reason.c_str());
		jaln_session_set_errored(session);
		return JAL_E_INVAL;
	}

	// The init ack or nack has been fully handled
	// In the case of an error or nack, we've already returned
	// Check if a resume is necessary
	if (!resumeNonce.empty()) {
		// The use of rec_info here to give the nonce to on_journal_resume is an old legacy
		// used here only to keep the API from changing. The nonce has to be strdup'd in because
		// jaln_record_info holds a non-const pointer to non-const data
		// Immediately free it after use to avoid a leak
		struct jaln_record_info rec_info;
		memset(&rec_info, 0, sizeof(rec_info));
		rec_info.type = session->ch_info->type;
		rec_info.nonce = jal_strdup(resumeNonce.c_str());
		enum jal_status ret = session->jaln_ctx->pub_callbacks->on_journal_resume(
			session,
			session->ch_info,
			&rec_info,
			resumeOffset,
			NULL,
			NULL,
			NULL, // TODO: headers? Never set in 1.x
			session->jaln_ctx->user_data);
		
		if(JAL_OK == ret) {
			// A resume is necessary and the matching record was found.
			// Stage the metadata info for later use
			// We held the offset/nonce outside the pub_data until we knew they were needed to
			// avoid needing to clear/free them in early return cases. Assign them now
			session->pub_data->resume_off = resumeOffset;
			// steal the rec_info.nonce pointer so we don't need to make another copy
			session->pub_data->resume_nonce = rec_info.nonce;
			rec_info.nonce = NULL;
		} else {
			// No resume is happening, free the nonce and 0 the offset
			free(rec_info.nonce);
			rec_info.nonce = NULL;
			session->pub_data->resume_off = 0;
		}

		if(JAL_OK != ret && JAL_E_JOURNAL_MISSING != ret) {
			// on_journal_resume returned an unexpected failure
			// session is compromised
			return ret;
		}


		if(JAL_E_JOURNAL_MISSING == ret) {
			// Send a Journal Missing indicator to the subscriber
			try {
				// May throw InvalidMessage
				JournalMissingMessage journalMissing(
						std::string(session->id),
						resumeNonce);

				// May throw SendFailure
				JalopResponse response = journalMissing.sendMessage(
					curl,
					curl_timeout_period,
					session->jaln_ctx->http_client_retry_count);

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
						fprintf(stderr, "Received JournalMissingResponse from Subscriber in response to journal-missing for session: %s, id: %s\n",
							session->id, resumeNonce.c_str());
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
								session->id, recordFailure.id.c_str());
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
							std::string(session->id));
						fprintf(stderr, "Received Session Failure from Subscriber in response to journal-missing for session: %s\n",
							session->id);
							for(const auto& err : sessionFailure.errors) {
								fprintf(stderr, "  %s\n", err.c_str());
							}
							jaln_session_set_errored(session);
							return JAL_E_INVAL;
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
				jaln_session_set_errored(session);
				return JAL_E_INVAL;
			} catch(SendFailure& e) {
				fprintf(stderr, "Failed to send journal-missing: %s\n", e.what());
				jaln_session_set_errored(session);
				return JAL_E_COMM;
			} catch(MalformedResponse &e) {
				fprintf(stderr, "Malformed Response: %s\n", e.what());
				jaln_session_set_errored(session);
				return JAL_E_INVAL;
			} catch(InvalidResponseType &e) {
				fprintf(stderr, "Invalid response to journal-missing: %s\n", e.what());
				jaln_session_set_errored(session);
				return JAL_E_INVAL;
			} catch(InvalidResponse &e) {
				fprintf(stderr, "Response message of type: %s is invalid. Reason: %s\n",
					e.responseType.c_str(),
					e.reason.c_str());
				jaln_session_set_errored(session);
				return JAL_E_INVAL;
			}
		}
	}

	// Subscription complete, inform jald
	return session->jaln_ctx->pub_callbacks->on_subscribe(
			session,
			session->ch_info,
			session->ch_info->type,
			session->mode,
			NULL, // TODO: headers? Never set in 1.x
			session->jaln_ctx->user_data);
}

static const char *jaln_rtype_str(const int record_type)
{
	switch(record_type) {
	case JALN_RTYPE_JOURNAL: return JALN_STR_JOURNAL;
	case JALN_RTYPE_AUDIT: return JALN_STR_AUDIT;
	case JALN_RTYPE_LOG: return JALN_STR_LOG;
	default: return NULL;
	}
}

// Set the URL and TLS information
static enum jal_status jaln_setup_session(
		jaln_session *sess,
		const char *host,
		const char *port,
		const int record_type)
{
	CURL *curl_ctx = curl_easy_init();
	if (!curl_ctx) {
		return JAL_E_COMM;
	}
	const char *class_str = jaln_rtype_str(record_type);
	jaln_context *ctx = sess->jaln_ctx;
	const int tls = ctx->private_key && ctx->public_cert && ctx->peer_certs;
	char *url;
	jal_asprintf(&url, "http%s://%s:%s/%s", tls? "s" : "", host, port, class_str);
	if (CURLE_OK != curl_easy_setopt(curl_ctx, CURLOPT_URL, url)) {
		curl_easy_cleanup(curl_ctx);
		free(url);
		return JAL_E_NO_MEM;
	}
	curl_easy_setopt(curl_ctx, CURLOPT_FAILONERROR, 1L);
	if (tls)
	{
		//JAL-1000 - disable cert validity check and allow self signed certs if enabled
		//in allow_self_signed_certs config setting in the jald config file.
		if (1 == ctx->allow_self_signed_certs)
		{
			curl_easy_setopt(curl_ctx, CURLOPT_SSL_VERIFYPEER, 0);
		}

		if (CURLE_OK != curl_easy_setopt(curl_ctx, CURLOPT_SSLKEY, ctx->private_key) ||
			CURLE_OK != curl_easy_setopt(curl_ctx, CURLOPT_SSLCERT, ctx->public_cert) ||
			CURLE_OK != curl_easy_setopt(curl_ctx, CURLOPT_CAPATH, ctx->peer_certs)) {
			curl_easy_cleanup(curl_ctx);
			return JAL_E_NO_MEM;
		}
	}
	sess->curl_ctx = curl_ctx;
	free(url);
	return JAL_OK;
}

enum jal_status jaln_initialize_session(
		jaln_session **session,
		jaln_context *ctx,
		const char *host,
		const char *port,
		const enum jaln_publish_mode mode,
		const int rtype)
{
	*session = jaln_publisher_create_session(ctx, host, (jaln_record_type)rtype);
	if (!*session) {
		return JAL_E_INVAL;
	}
	(*session)->mode = mode;
	enum jal_status rc;
	if (JAL_OK != (rc = jaln_setup_session(*session, host, port, rtype)) ||
		JAL_OK != (rc = jaln_publisher_send_init(*session))) {
		jaln_session_destroy(session);
		return rc;
	}
	pthread_mutex_lock(&ctx->lock);
	++ctx->sess_cnt;
	pthread_mutex_unlock(&ctx->lock);
	return rc;
}

struct jaln_connection *jaln_publish(
		jaln_context *ctx,
		const char *host,
		const char *port,
		const int record_types,
		enum jaln_publish_mode mode,
		void *user_data)
{
	if (!ctx || !host || !port) {
		return NULL;
	}

	if (!record_types || record_types & ~JALN_RTYPE_ALL) {
		return NULL;
	}

	if (mode != JALN_ARCHIVE_MODE && mode != JALN_LIVE_MODE) {
		return NULL;
	}

	if (!jaln_publisher_callbacks_is_valid(ctx->pub_callbacks) ||
		!jaln_connection_callbacks_is_valid(ctx->conn_callbacks) ||
		ctx->is_connected) {
		return NULL;
	}

	ctx->is_connected = true;
	ctx->user_data = user_data;


	struct jaln_connection *jconn = jaln_connection_create();
	jconn->jaln_ctx = ctx;
	ctx->conn = jconn;

	if (record_types & JALN_RTYPE_JOURNAL) {
		if (JAL_OK != jaln_initialize_session(&jconn->journal_sess, ctx, host, port, mode, JALN_RTYPE_JOURNAL)) {
			jaln_connection_destroy(&jconn);
			return NULL;
		}
	}
	if (record_types & JALN_RTYPE_AUDIT) {
		if (JAL_OK != jaln_initialize_session(&jconn->audit_sess, ctx, host, port, mode, JALN_RTYPE_AUDIT)) {
			jaln_connection_destroy(&jconn);
			return NULL;
		}
	}
	if(record_types & JALN_RTYPE_LOG) {
		if (JAL_OK != jaln_initialize_session(&jconn->log_sess, ctx, host, port, mode, JALN_RTYPE_LOG)) {
			jaln_connection_destroy(&jconn);
			return NULL;
		}
	}

	return jconn;
}

jaln_session *jaln_publisher_create_session(jaln_context *ctx, const char *host, enum jaln_record_type type)
{
	if (!ctx || !host) {
		return NULL;
	}
	switch(type) {
	case JALN_RTYPE_JOURNAL:
	case JALN_RTYPE_AUDIT:
	case JALN_RTYPE_LOG:
		break;
	default:
		return NULL;
	}
	jaln_session *sess = NULL;
	sess = jaln_session_create();
	jaln_ctx_ref(ctx);
	sess->jaln_ctx = ctx;

	struct jaln_channel_info *ch_info = sess->ch_info;
	sess->pub_data = jaln_pub_data_create();
	ch_info->hostname = jal_strdup(host);
	ch_info->type = type;

	return sess;
}

// Duplicated from jaln_message_helpers.c for now
// Used only for the init_ack callback which wants the errors in this form
// Note: error_list will point to tokens within a single string. Free only error_list[0].
static void jaln_split_errors(char *errors, int *error_cnt, char ***error_list)
{
	char *cur_err;
	char *saveptr;
	const char *delim = "|";
	size_t list_len = 4;  // Initial size of the list. It will grow as needed.
	int total_errs = 0;
	char **tmp_list = (char **)malloc(list_len * sizeof(char*));
	cur_err = strtok_r(errors, delim, &saveptr);
	while (cur_err){
		if (total_errs >= (int)list_len) {
			list_len *= 2;
			tmp_list = (char **)jal_realloc(tmp_list, list_len * sizeof(char *));
		}
		tmp_list[total_errs++] = cur_err;
		cur_err = strtok_r(NULL, delim, &saveptr);
	}
	*error_list = (char**)realloc(tmp_list, total_errs * sizeof(char *));
	*error_cnt = total_errs;
}
