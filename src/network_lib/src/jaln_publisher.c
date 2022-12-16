/**
 * @file jaln_publisher.c  This file contains function
 * definitions related to the jal publisher.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
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
#include "jaln_pub_feeder.h"
#include "jaln_session.h"

void jaln_pub_notify_digests_and_create_digest_response(
		jaln_session *sess,
		axlList *calc_dgsts,
		struct jaln_digest_info *peer_dgst,
		struct jaln_digest_resp_info **dgst_resp_info)
{
	if (!sess || !sess->jaln_ctx || !sess->ch_info || !sess->jaln_ctx->pub_callbacks ||
			!sess->jaln_ctx->pub_callbacks->peer_digest ||
			!calc_dgsts || !peer_dgst || !dgst_resp_info ||
			*dgst_resp_info) {
		return;
	}

	axlListCursor *calc_cursor = axl_list_cursor_new(calc_dgsts);

	struct jaln_digest_info *calc_di = NULL;

	axl_list_cursor_first(calc_cursor);
	while(axl_list_cursor_has_item(calc_cursor)) {
		struct jaln_digest_info *tmp = (struct jaln_digest_info*) axl_list_cursor_get(calc_cursor);
		if (tmp && (0 == strcmp(peer_dgst->nonce, tmp->nonce))) {
			calc_di = tmp;
			axl_list_cursor_unlink(calc_cursor);
			break;
		}
		axl_list_cursor_next(calc_cursor);
	}

	if (!calc_di) {
		sess->jaln_ctx->pub_callbacks->peer_digest(sess,
				sess->ch_info,
				sess->ch_info->type,
				peer_dgst->nonce,
				NULL, 0,
				peer_dgst->digest, peer_dgst->digest_len,
				sess->jaln_ctx->user_data);

		*dgst_resp_info = jaln_digest_resp_info_create(peer_dgst->nonce, JALN_DIGEST_STATUS_UNKNOWN);
	} else {
		if (jaln_digests_are_equal(peer_dgst, calc_di)) {
			*dgst_resp_info = jaln_digest_resp_info_create(peer_dgst->nonce, JALN_DIGEST_STATUS_CONFIRMED);
		} else {
			*dgst_resp_info = jaln_digest_resp_info_create(peer_dgst->nonce, JALN_DIGEST_STATUS_INVALID);
		}

		sess->jaln_ctx->pub_callbacks->peer_digest(sess,
				sess->ch_info,
				sess->ch_info->type,
				peer_dgst->nonce,
				calc_di->digest, calc_di->digest_len,
				peer_dgst->digest, peer_dgst->digest_len,
				sess->jaln_ctx->user_data);
	}

	jaln_digest_info_destroy(&calc_di);

	axl_list_cursor_free(calc_cursor);
}

static size_t jaln_noop_write(
                __attribute__((unused)) char *ptr,
                __attribute__((unused)) size_t size,
                size_t nmemb,
                __attribute__((unused)) void *user_data)
{
        return nmemb;
}

enum jal_status jaln_publisher_send_init(jaln_session *session)
{
	struct curl_slist *headers = NULL;
	const long curl_timeout_period = session->jaln_ctx->network_timeout * 60L;
	enum jal_status ret = JAL_E_INVAL;
	struct jaln_response_header_info *header_info = NULL;
	CURL *curl = NULL;
	if (!session || !session->ch_info || !session->jaln_ctx || !session->curl_ctx || !session->pub_data) {
		// shouldn't ever happen
		ret = JAL_E_INVAL;
		goto err_out;
	}

	curl = session->curl_ctx;
	header_info = jaln_response_header_info_create(session);

	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, jaln_noop_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);

	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, jaln_publisher_init_reply_frame_handler);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, header_info);

	ret = jaln_create_init_msg(session->mode, session->ch_info->type,
			session->jaln_ctx, &headers);
	if (JAL_OK != ret) {
		goto err_out;
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	char buf[CURL_ERROR_SIZE];

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, &buf);

	if (curl_timeout_period > 0) {
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, curl_timeout_period);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	}

	CURLcode rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		fprintf(stderr, "%s(): Failed: %d: %s\n", __func__, rc, buf);
		fprintf(stderr, "Failed to send initialize: %s\n",
			curl_easy_strerror(rc));
		(void)fflush(stderr);
		// Set a failing return code
		jaln_session_set_errored(session);
		ret = JAL_E_COMM;
		goto err_out;
	}
	if (session->errored) {
		ret = JAL_E_INVAL;
	} else if (header_info->error_cnt) {
		// connection nack callback
		struct jaln_connect_nack nack;
		memset(&nack, 0, sizeof(nack));
		nack.ch_info = session->ch_info;
		nack.error_cnt = header_info->error_cnt;
		nack.error_list = header_info->error_list;
		// TODO: headers? Never set in 1.x
		jaln_context *ctx = session->jaln_ctx;
		ctx->conn_callbacks->connect_nack(&nack, ctx->user_data);
		// Set a failing return code
		ret = JAL_E_INVAL;
	} else {
		ret = jaln_verify_init_ack_headers(header_info);
		if (JAL_OK != ret) {
			goto err_out;
		}

		// if digesting is disabled, don't report an algo in callbacks
		if (!session->dgst_on && session->ch_info->digest_method) {
			free(session->ch_info->digest_method);
			session->ch_info->digest_method = NULL;
		}

		// connection ack callback
		struct jaln_connect_ack ack;
		memset(&ack, 0, sizeof(ack));
		ack.hostname = session->ch_info->hostname;
		ack.addr = session->ch_info->addr;
		ack.jaln_version = JALN_JALOP_VERSION_TWO;
		ack.mode = session->role;
		session->dgst = jal_sha256_ctx_create();
		// TODO: agent and headers?
		// Agent unused by subscriber, but was supported in 1.x.
		// Headers never set in 1.x.
		jaln_context *ctx = session->jaln_ctx;
		ctx->conn_callbacks->connect_ack(&ack, ctx->user_data);
		if (session->pub_data->nonce) {
			// on journal resume callback
			// this was called before on subscribe in 1.x
			struct jaln_record_info rec_info;
			memset(&rec_info, 0, sizeof(rec_info));
			rec_info.type = session->ch_info->type;
			rec_info.nonce = jal_strdup(session->pub_data->nonce);
			ret = ctx->pub_callbacks->on_journal_resume(
					session,
					session->ch_info,
					&rec_info,
					session->pub_data->payload_off,
					&session->pub_data->sys_meta,
					&session->pub_data->app_meta,
					NULL, // TODO: headers? Never set in 1.x
					ctx->user_data);
			if (JAL_OK != ret) {
				if (JAL_E_JOURNAL_MISSING == ret) {
					jaln_publisher_send_journal_missing(session, rec_info.nonce);
					free(session->pub_data->nonce);
					session->pub_data->nonce = NULL;
					session->pub_data->payload_off = 0;
				} else {
					goto err_out;
				}
			} else {
				session->pub_data->sys_meta_sz = rec_info.sys_meta_len;
				session->pub_data->app_meta_sz = rec_info.app_meta_len;
			}
			free(rec_info.nonce);
		}
		// on subscribe callback
		ret = ctx->pub_callbacks->on_subscribe(
				session,
				session->ch_info,
				session->ch_info->type,
				session->mode,
				NULL, // TODO: headers? Never set in 1.x
				ctx->user_data);
	}

err_out:
	curl_slist_free_all(headers);
	jaln_response_header_info_destroy(&header_info);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, NULL);
	return ret;
}

enum jal_status jaln_publisher_send_journal_missing(jaln_session *session, char *nonce)
{
	struct curl_slist *headers = NULL;
	const long curl_timeout_period = session->jaln_ctx->network_timeout * 60L;
	enum jal_status ret = JAL_E_INVAL;
	CURL *curl = NULL;
	if (!session || !session->ch_info || !session->jaln_ctx || !session->curl_ctx) {
		// shouldn't ever happen
		return JAL_E_INVAL;
	}
	curl = session->curl_ctx;
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, jaln_noop_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);

	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, jaln_publisher_journal_missing_response_handler);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, session);

	ret = jaln_create_journal_missing_msg(session->id, nonce, &headers);
	if (JAL_OK != ret) {
		return ret;
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	char buf[CURL_ERROR_SIZE];

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, &buf);

	if (curl_timeout_period > 0) {
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, curl_timeout_period);
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	}

	CURLcode rc = curl_easy_perform(curl);
	curl_slist_free_all(headers);
	if (rc != CURLE_OK) {
		fprintf(stderr, "%s(): Failed: %d: %s\n", __func__, rc, buf);
		(void)fflush(stderr);
		jaln_session_set_errored(session);
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, NULL);
		return JAL_E_COMM;
	}

	if (session->errored)
	{
		ret = JAL_E_INVAL;
	}

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, NULL);
	return ret;
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
	*session = jaln_publisher_create_session(ctx, host, rtype);
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

	ctx->is_connected = axl_true;
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

size_t jaln_publisher_init_reply_frame_handler(char *ptr, size_t size, size_t nmemb, void *user_data)
{

	const size_t bytes = size * nmemb;
	jaln_parse_init_ack_header(ptr, bytes, (struct jaln_response_header_info *)user_data);
	return bytes;
}

size_t jaln_publisher_journal_missing_response_handler(char *ptr, size_t size, size_t nmemb, void *user_data)
{
	jaln_session *sess = (jaln_session*) user_data;
	const size_t bytes = size * nmemb;
	enum jal_status ret = jaln_parse_journal_missing_response(ptr, bytes, sess);
	if (ret != JAL_OK) {
		return 0;
	}
	return bytes;
}

size_t jaln_publisher_digest_challenge_handler(char *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct jaln_response_header_info *info = (struct jaln_response_header_info *) user_data;
	const size_t bytes = size * nmemb;
	enum jal_status ret = jaln_parse_digest_challenge_header(ptr, bytes, info);
	if (ret != JAL_OK) {
		return 0;
	}
	return bytes;
}

size_t jaln_publisher_sync_handler(char *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct jaln_response_header_info *info = (struct jaln_response_header_info *) user_data;
	const size_t bytes = size * nmemb;
	enum jal_status ret = jaln_parse_sync_header(ptr, bytes, info);
	if (ret != JAL_OK) {
		return 0;
	}
	return bytes;
}

size_t jaln_publisher_failed_digest_handler(char *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct jaln_response_header_info *info = (struct jaln_response_header_info *) user_data;
	const size_t bytes = size * nmemb;
	enum jal_status ret = jaln_parse_record_failure_header(ptr, bytes, info);
	if (ret != JAL_OK) {
		return 0;
	}
	return bytes;
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
	sess->role = JALN_ROLE_PUBLISHER;

	struct jaln_channel_info *ch_info = sess->ch_info;
	sess->pub_data = jaln_pub_data_create();
	ch_info->hostname = jal_strdup(host);
	ch_info->type = type;

	return sess;
}
