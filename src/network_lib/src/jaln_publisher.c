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
#include <vortex.h>
#include <vortex_tls.h>
#include <jalop/jaln_publisher_callbacks.h>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#include "jaln_context.h"
#include "jaln_connection.h"
#include "jaln_connection_callbacks_internal.h"
#include "jaln_digest_info.h"
#include "jaln_digest_msg_handler.h"
#include "jaln_digest_resp_info.h"
#include "jaln_handle_init_replies.h"
#include "jaln_journal_resume_msg_handler.h"
#include "jaln_message_helpers.h"
#include "jaln_publisher.h"
#include "jaln_publisher_callbacks_internal.h"
#include "jaln_pub_feeder.h"
#include "jaln_session.h"
#include "jaln_sync_msg_handler.h"
#include "jaln_subscribe_msg_handler.h"

void jaln_pub_notify_digests_and_create_digest_response(
		jaln_session *sess,
		axlList *calc_dgsts,
		axlList *peer_dgsts,
		axlList **dgst_resp_infos)
{
	if (!sess || !sess->jaln_ctx || !sess->ch_info || !sess->jaln_ctx->pub_callbacks ||
			!sess->jaln_ctx->pub_callbacks->peer_digest ||
			!calc_dgsts || !peer_dgsts || !dgst_resp_infos ||
			*dgst_resp_infos) {
		return;
	}

	axlList *resps = jaln_digest_resp_list_create();

	axlListCursor *calc_cursor = axl_list_cursor_new(calc_dgsts);
	axlListCursor *peer_cursor = axl_list_cursor_new(peer_dgsts);

	axl_list_cursor_first(peer_cursor);
	while(axl_list_cursor_has_item(peer_cursor)) {
		struct jaln_digest_info *peer_di = (struct jaln_digest_info*) axl_list_cursor_get(peer_cursor);
		struct jaln_digest_info *calc_di = NULL;

		axl_list_cursor_first(calc_cursor);
		while(axl_list_cursor_has_item(calc_cursor)) {
			struct jaln_digest_info *tmp = (struct jaln_digest_info*) axl_list_cursor_get(calc_cursor);
			if (tmp && (0 == strcmp(peer_di->nonce, tmp->nonce))) {
				calc_di = tmp;
				axl_list_cursor_unlink(calc_cursor);
				break;
			}
			axl_list_cursor_next(calc_cursor);
		}

		struct jaln_digest_resp_info *resp_info = NULL;
		if (!calc_di) {
			sess->jaln_ctx->pub_callbacks->peer_digest(sess,
					sess->ch_info,
					sess->ch_info->type,
					peer_di->nonce,
					NULL, 0,
					peer_di->digest, peer_di->digest_len,
					sess->jaln_ctx->user_data);

			resp_info = jaln_digest_resp_info_create(peer_di->nonce, JALN_DIGEST_STATUS_UNKNOWN);
		} else {
			if (jaln_digests_are_equal(peer_di, calc_di)) {
				resp_info = jaln_digest_resp_info_create(peer_di->nonce, JALN_DIGEST_STATUS_CONFIRMED);
			} else {
				resp_info = jaln_digest_resp_info_create(peer_di->nonce, JALN_DIGEST_STATUS_INVALID);
			}

			sess->jaln_ctx->pub_callbacks->peer_digest(sess,
					sess->ch_info,
					sess->ch_info->type,
					peer_di->nonce,
					calc_di->digest, calc_di->digest_len,
					peer_di->digest, peer_di->digest_len,
					sess->jaln_ctx->user_data);
		}
		axl_list_append(resps, resp_info);

		jaln_digest_info_destroy(&calc_di);

		axl_list_cursor_next(peer_cursor);
	}
	axl_list_cursor_free(peer_cursor);
	axl_list_cursor_free(calc_cursor);
	*dgst_resp_infos = resps;
}

enum jal_status jaln_publisher_handle_sync(jaln_session *sess,
		VortexChannel *chan,
		VortexFrame *frame,
		int msg_no)
{
	axl_bool ans_rpy_sent = vortex_channel_finalize_ans_rpy(chan, msg_no);
	char *nonce = NULL;
	enum jal_status ret = JAL_E_INVAL;
	if (!sess || !sess->jaln_ctx || !sess->jaln_ctx->pub_callbacks || 
			!sess->jaln_ctx->pub_callbacks->sync || !sess->ch_info) {
		goto out;
	}
	ret = jaln_process_sync(frame, &nonce);
	if (ret != JAL_OK) {
		goto out;
	}
	sess->jaln_ctx->pub_callbacks->sync(sess, sess->ch_info, sess->ch_info->type, sess->mode, nonce, NULL, sess->jaln_ctx->user_data);
	free(nonce);
out:
	if (!ans_rpy_sent) {
		ret = JAL_E_COMM;
	}
	return ret;
}

enum jal_status jaln_publisher_handle_digest(jaln_session *sess, VortexChannel *chan, VortexFrame *frame, int msg_no)
{
	axlList *calc_dgsts = NULL;
	axlList *dgst_from_remote = NULL;
	axlList *resps = NULL;
	char *msg = NULL;
	uint64_t len = 0;

	enum jal_status ret;
	ret = jaln_process_digest(frame, &dgst_from_remote);
	if (JAL_OK != ret) {
		goto err_out;
	}

	vortex_mutex_lock(&sess->lock);
	calc_dgsts = sess->dgst_list;
	sess->dgst_list = jaln_digest_info_list_create();

	jaln_pub_notify_digests_and_create_digest_response(sess, calc_dgsts, dgst_from_remote, &resps);

	axlListCursor *cursor = axl_list_cursor_new(sess->dgst_list);
	axl_list_cursor_first(cursor);
	while(axl_list_cursor_has_item(cursor)) {
		axlPointer from_sess = axl_list_cursor_get(cursor);
		axl_list_append(calc_dgsts, from_sess);
		axl_list_cursor_unlink(cursor);
		axl_list_cursor_next(cursor);
	}
	axl_list_cursor_free(cursor);
	axlList *tmp_list = sess->dgst_list;
	sess->dgst_list = calc_dgsts;
	vortex_mutex_unlock(&sess->lock);

	axl_list_free(tmp_list);
	tmp_list = NULL;
	calc_dgsts = NULL;

	axl_list_free(dgst_from_remote);
	dgst_from_remote = NULL;

	ret = jaln_create_digest_response_msg(resps, &msg, &len);
	axl_list_free(resps);
	resps = NULL;
	vortex_channel_send_rpy(chan, msg, len, msg_no);
	free(msg);
	goto out;
err_out:
	vortex_channel_close_full(chan, jaln_session_notify_close, sess);
out:
	return ret;
}

void jaln_publisher_digest_and_sync_frame_handler(VortexChannel *chan, VortexConnection *conn,
		VortexFrame *frame, axlPointer user_data)
{
	jaln_session *sess = (jaln_session*) user_data;
	int msg_no = -1;
	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		goto err_out;
	}
	msg_no = vortex_frame_get_msgno(frame);
	if (msg_no < 0) {
		goto err_out;
	}
	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (!msg) {
		goto err_out;
	}
	if (0 == strcmp(msg, JALN_MSG_DIGEST)) {
		if (JAL_OK != jaln_publisher_handle_digest(sess, chan, frame, msg_no)) {
			goto err_out;
		}
	} else if (0 == strcmp(msg, JALN_MSG_SYNC)) {
		if (JAL_OK != jaln_publisher_handle_sync(sess, chan, frame, msg_no)) {
			goto err_out;
		}
	} else {
		goto err_out;
	}
	return;
err_out:
	vortex_connection_shutdown(conn);
}

void jaln_pub_channel_frame_handler(
		VortexChannel *chan,
		VortexConnection *conn,
		VortexFrame *frame,
		axlPointer user_data)
{
	enum jal_status ret = JAL_E_INVAL;

	jaln_session *sess = (jaln_session*) user_data;
	if (!sess || !sess->ch_info) {
		goto err_out;
	}
	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		goto err_out;
	}
	int msg_no = vortex_frame_get_msgno(frame);
	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (0 == strcasecmp(msg, JALN_MSG_SUBSCRIBE)) {
		ret = jaln_pub_handle_subscribe(sess, chan, frame, msg_no);
		if (JAL_OK != ret && JAL_E_NOT_CONNECTED != ret) {
			goto err_out;
		}
	} else if (0 == strcasecmp(msg, JALN_MSG_JOURNAL_RESUME) && (JALN_RTYPE_JOURNAL == sess->ch_info->type)) {
		if (JAL_OK != jaln_pub_handle_journal_resume(sess, chan, frame, msg_no)) {
			goto err_out;
		}
	} else {
		goto err_out;
	}
	return;
err_out:
	vortex_connection_shutdown(conn);
	return;
}

enum jal_status jaln_pub_handle_journal_resume(jaln_session *sess, VortexChannel *chan, VortexFrame *frame, int msg_no)
{
	enum jal_status ret = JAL_E_INVAL;
	if (!sess || !sess->ch_info || !sess->jaln_ctx || !sess->jaln_ctx->pub_callbacks || !chan || !frame) {
		return ret;
	}
	struct jaln_channel_info *ch_info = sess->ch_info;
	enum jaln_record_type type = ch_info->type;
	if  (JALN_RTYPE_JOURNAL != type) {
		return JAL_E_INVAL;
	}
	struct jaln_publisher_callbacks *cbs = sess->jaln_ctx->pub_callbacks;
	struct jaln_pub_data *pd = sess->pub_data;
	void *ud = sess->jaln_ctx->user_data;
	char *nonce = NULL;
	uint64_t offset;
	ret = jaln_process_journal_resume(frame, &nonce, &offset);
	if (JAL_OK != ret) {
		goto err_out;
	}

	sess->pub_data->payload_off = offset;
	struct jaln_record_info rec_info;
	memset(&rec_info, 0, sizeof(rec_info));
	rec_info.type = type;
	rec_info.nonce = jal_strdup(nonce);

	ret = cbs->on_journal_resume(sess, ch_info, &rec_info, offset, &pd->sys_meta, &pd->app_meta, NULL, ud);
	if (JAL_E_JOURNAL_MISSING == ret) {
		jaln_publisher_send_journal_missing(sess, nonce);
	} else if (JAL_OK != ret) {
		goto err_out;
	}

	sess->pub_data->msg_no = msg_no;
	sess->pub_data->nonce = jal_strdup(nonce);

	ret = cbs->on_subscribe(sess, ch_info, type, sess->mode, NULL, ud);
	if (JAL_OK != ret) {
		goto err_out;
	}

	goto out;

err_out:
	vortex_channel_finalize_ans_rpy(chan, msg_no);
	jaln_session_set_errored(sess);
out:
	free(nonce);
	return ret;
}

enum jal_status jaln_pub_handle_subscribe(jaln_session *sess, VortexChannel *chan, VortexFrame *frame, int msg_no)
{
	if (!sess || !chan || !frame || !sess->jaln_ctx || !sess->jaln_ctx->pub_callbacks ||
			!sess->ch_info || !sess->pub_data) {
		return JAL_E_INVAL;
	}

	enum jal_status ret = JAL_E_INVAL;
	struct jaln_publisher_callbacks *cbs = sess->jaln_ctx->pub_callbacks;
	struct jaln_pub_data *pd = sess->pub_data;
	struct jaln_channel_info *ch_info = sess->ch_info;
	enum jaln_record_type type = ch_info->type;
	void *user_data = sess->jaln_ctx->user_data;

	ret = jaln_process_subscribe(frame);
	if (JAL_OK != ret) {
		goto err_out;
	}

	pd->msg_no = msg_no;
	ret = cbs->on_subscribe(sess, ch_info, type, sess->mode, NULL, user_data);
	if (JAL_OK != ret && JAL_E_NOT_CONNECTED != ret) {
		goto err_out;
	}

	goto out;

err_out:
	vortex_channel_finalize_ans_rpy(chan, msg_no);
	jaln_session_set_errored(sess);
out:
	return ret;
}

axl_bool jaln_finish_session_helper(__attribute__((unused)) axlPointer key,
				    axlPointer data,
				    axlPointer user_data)
{
	axlList *sessions = (axlList *) data;
	jaln_context *ctx = user_data;
	int i;
	jaln_session *sess = NULL;

	int sess_list_length = axl_list_length(sessions);

	for (i = 0; i < sess_list_length; i++) {
		sess = (jaln_session *) axl_list_get_nth(sessions, i);

		vortex_mutex_lock(&sess->lock);
		if (!sess || !sess->pub_data) {
			continue;
		}

		vortex_channel_finalize_ans_rpy(sess->rec_chan, sess->pub_data->msg_no);
		vortex_cond_signal(&sess->wait);
		jaln_session_set_errored_no_lock(sess);

		jaln_ctx_remove_session(ctx,sess);
		vortex_mutex_unlock(&sess->lock);
	}

	return axl_false;
}

void jaln_publisher_on_connection_close(__attribute__((unused)) VortexConnection *conn,
					axlPointer data)
{
	struct jaln_connection *jal_conn = (struct jaln_connection *) data;

	if (!jal_conn || !jal_conn->jaln_ctx || !jal_conn->jaln_ctx->conn_callbacks) {
		return;
	}

	jaln_context *ctx = jal_conn->jaln_ctx;

	axl_hash_foreach(ctx->sessions_by_conn, jaln_finish_session_helper, ctx);
	vortex_connection_shutdown(conn);

	vortex_mutex_lock(&ctx->lock);
	ctx->conn_callbacks->on_connection_close(jal_conn, ctx->user_data);
	jaln_connection_destroy(&jal_conn);
	vortex_mutex_unlock(&ctx->lock);
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
	enum jal_status ret = JAL_E_INVAL;
	struct jaln_init_ack_header_info *header_info = NULL;
	CURL *curl = NULL;
	if (!session || !session->ch_info || !session->jaln_ctx || !session->curl_ctx) {
		// shouldn't ever happen
		ret = JAL_E_INVAL;
		goto err_out;
	}

	curl = session->curl_ctx;
	header_info = jaln_init_ack_header_info_create(session);

	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, jaln_noop_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);

	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, jaln_publisher_init_reply_frame_handler);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, header_info);

	const char *pub_id = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"; // TODO: retrieve from context 

	ret = jaln_create_init_msg(pub_id, session->mode, session->ch_info->type,
			session->jaln_ctx, &headers);
	if (JAL_OK != ret) {
		goto err_out;
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	CURLcode rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		fprintf(stderr, "Failed to send initialize: %s\n",
			curl_easy_strerror(rc));
		ret = JAL_E_COMM;
	}

	ret = jaln_verify_init_ack_headers(header_info);
	if (JAL_OK != ret) {
		goto err_out;
	}

	curl_slist_free_all(headers);
	goto out;

err_out:
	curl_easy_cleanup(curl);
out:
	jaln_init_ack_header_info_destroy(&header_info);
	return ret;
}

enum jal_status jaln_publisher_send_journal_missing(jaln_session *session, char *nonce)
{
	struct curl_slist *headers = NULL;
	enum jal_status ret = JAL_E_INVAL;
	CURL *curl = NULL;
	if (!session || !session->ch_info || !session->jaln_ctx || !session->curl_ctx) {
		// shouldn't ever happen
		ret = JAL_E_INVAL;
		goto err_out;
	}
	curl = session->curl_ctx;
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, jaln_noop_write);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);

	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, jaln_publisher_journal_missing_response_handler);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, session);

	ret = jaln_create_journal_missing_msg(session->id, nonce, &headers);
	if (JAL_OK != ret) {
		goto err_out;
	}
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	CURLcode rc = curl_easy_perform(curl);
	if (rc != CURLE_OK) {
		ret = JAL_E_COMM;
		goto err_out;
	}

	if (NULL == session->last_message || 0 != strcmp(session->last_message, JALN_MSG_JOURNAL_MISSING)) {
		ret = JAL_E_INVAL;
		goto err_out;
	}

	curl_slist_free_all(headers);
	goto out;

err_out:
	curl_easy_cleanup(curl);
out:
	return ret;

}

static const char *jaln_rtype_str(const int data_class)
{
	switch(data_class) {
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
		const int data_class)
{
	CURL *curl_ctx = curl_easy_init();
	if (!curl_ctx) {
		return JAL_E_COMM;
	}
	const char *class_str = jaln_rtype_str(data_class);
	jaln_context *ctx = sess->jaln_ctx;
	const int tls = ctx->private_key && ctx->public_cert && ctx->peer_certs;
	char *url;
	jal_asprintf(&url, "http%s://%s:%s/%s", tls? "s" : "", host, port, class_str);
	if (CURLE_OK != curl_easy_setopt(curl_ctx, CURLOPT_URL, url)) {
		curl_easy_cleanup(curl_ctx);
		return JAL_E_NO_MEM;
	}
	if (tls)
	{
		// Disable cert verification for now.
		// TODO: verify against peer_certs
		curl_easy_setopt(curl_ctx, CURLOPT_SSL_VERIFYPEER, 0);
		if (CURLE_OK != curl_easy_setopt(curl_ctx, CURLOPT_SSLKEY, ctx->private_key) ||
			CURLE_OK != curl_easy_setopt(curl_ctx, CURLOPT_SSLCERT, ctx->public_cert)) {
			curl_easy_cleanup(curl_ctx);
			return JAL_E_NO_MEM;
		}
	}
	sess->curl_ctx = curl_ctx;
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
	}
	return rc;
}

struct jaln_connection *jaln_publish(
		jaln_context *ctx,
		const char *host,
		const char *port,
		const int data_classes,
		enum jaln_publish_mode mode,
		void *user_data)
{
	if (!ctx || !host || !port) {
		return NULL;
	}

	if (!data_classes || data_classes & ~JALN_RTYPE_ALL) {
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

	// TODO: Support multiple sessions per connection so we can connect to multiple endpoints.
	// According to the doxygen comments in jaln_network.h, one call to publish should set up
	// session for each type in data_classes, although it did not do this previously.
	jaln_session *session = NULL;

	if (data_classes & JALN_RTYPE_JOURNAL) {
		if (JAL_OK != jaln_initialize_session(&session, ctx, host, port, mode, JALN_RTYPE_JOURNAL)) {
			jaln_connection_destroy(&jconn);
			return NULL;
		}
		jconn->journal_sess = session;
	}
	if (data_classes & JALN_RTYPE_AUDIT) {
		if (JAL_OK != jaln_initialize_session(&session, ctx, host, port, mode, JALN_RTYPE_AUDIT)) {
			jaln_connection_destroy(&jconn);
			return NULL;
		}
		jconn->audit_sess = session;
	}
	if(data_classes & JALN_RTYPE_LOG) {
		if (JAL_OK != jaln_initialize_session(&session, ctx, host, port, mode, JALN_RTYPE_LOG)) {
			jaln_connection_destroy(&jconn);
			return NULL;
		}
		jconn->log_sess = session;
	}

	return jconn;
}

size_t jaln_publisher_init_reply_frame_handler(char *ptr, size_t size, size_t nmemb, void *user_data)
{

	jaln_session *sess = (jaln_session*) user_data;
	const size_t bytes = size * nmemb;
	enum jal_status ret = jaln_parse_init_ack_header(ptr, bytes, sess);
	if (ret != JAL_OK) {
		return 0;
	}
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

enum jal_status jaln_configure_pub_session_no_lock(VortexChannel *chan, jaln_session *session)
{
	if (!chan || !session || session->pub_data) {
		return JAL_E_INVAL;
	}
	session->rec_chan = chan;
	session->rec_chan_num = vortex_channel_get_number(chan);
	session->role = JALN_ROLE_PUBLISHER;
	session->pub_data = jaln_pub_data_create();
	vortex_channel_set_received_handler(chan, jaln_pub_channel_frame_handler, session);

	VortexConnection *v_conn = vortex_channel_get_connection(chan);

	struct jaln_connection *jconn = jaln_connection_create();
	jconn->jaln_ctx = session->jaln_ctx;
	jconn->v_conn = v_conn;

	vortex_connection_set_on_close_full(v_conn, jaln_publisher_on_connection_close, jconn);
	return JAL_OK;
}

enum jal_status jaln_configure_pub_session(VortexChannel *chan, jaln_session *session)
{
	vortex_mutex_lock(&session->lock);
	enum jal_status ret = jaln_configure_pub_session_no_lock(chan, session);
	vortex_mutex_unlock(&session->lock);
	return ret;
}

