/**
 * @file jaln_session.c This file contains function
 * definitions for internal library functions related to a jaln_session
 * structure. The jaln_session tracks the internal state for a peer that is
 * receiving jal records.
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
#include <axl.h>
#include <vortex.h>

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"

#include "jaln_channel_info.h"
#include "jaln_context.h"
#include "jaln_digest_info.h"
#include "jaln_publisher.h"
#include "jaln_session.h"
#include "jaln_sub_dgst_channel.h"
#include "jaln_subscriber_state_machine.h"

jaln_session *jaln_session_create()
{
	jaln_session *sess = jal_calloc(1, sizeof(*sess));
	if (!vortex_mutex_create(&sess->lock)) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	if (!vortex_mutex_create(&sess->wait_lock)) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	if (!vortex_cond_create(&sess->wait)) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	sess->mode = JALN_UNKNOWN_MODE;
	sess->ref_cnt = 1;
	sess->dgst_on = axl_true;  // digest challenge enabled by default
	sess->rec_chan_num = -1;
	sess->dgst_chan_num = -1; 
	sess->ch_info = jaln_channel_info_create();
	sess->dgst_list = axl_list_new(jaln_axl_equals_func_digest_info_nonce, jaln_axl_destroy_digest_info);
	if (!sess->dgst_list) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	sess->dgst_list_max = JALN_SESSION_DEFAULT_DGST_LIST_MAX;
	sess->dgst_timeout = JALN_SESSION_DEFAULT_DGST_TIMEOUT_MICROS;
	sess->errored = axl_false;
	return sess;
}

void jaln_session_ref(jaln_session *sess)
{
	if (!sess) {
		return;
	}
	vortex_mutex_lock(&sess->lock);
	if (0 >= sess->ref_cnt) {
		// already deleted?
		vortex_mutex_unlock(&sess->lock);
		return;
	}
	sess->ref_cnt++;
	vortex_mutex_unlock(&sess->lock);
}

void jaln_session_unref(jaln_session *sess)
{
	if (!sess) {
		return;
	}
	vortex_mutex_lock(&sess->lock);
	if (0 >= sess->ref_cnt) {
		// shouldn't happen
		vortex_mutex_unlock(&sess->lock);
		return;
	}
	sess->ref_cnt--;
	if (0 == sess->ref_cnt) {
		vortex_mutex_unlock(&sess->lock);
		jaln_session_destroy(&sess);
		return;
	}
	vortex_mutex_unlock(&sess->lock);
}

void jaln_session_set_errored_no_lock(jaln_session *sess)
{
	if (!sess) {
		return;
	}
	sess->errored = axl_true;
}

void jaln_session_set_errored(jaln_session *sess)
{
	if (!sess) {
		return;
	}
	vortex_mutex_lock(&sess->lock);
	jaln_session_set_errored_no_lock(sess);
	vortex_mutex_unlock(&sess->lock);
}

void jaln_session_set_dgst_timeout(jaln_session *sess, long timeout)
{
	if (!sess) {
		return;
	}
	vortex_mutex_lock(&sess->lock);
	sess->dgst_timeout = timeout;
	vortex_mutex_unlock(&sess->lock);
}

void jaln_session_set_dgst_max(jaln_session *sess, int max)
{
	if (!sess) {
		return;
	}
	vortex_mutex_lock(&sess->lock);
	sess->dgst_list_max = max;
	vortex_mutex_unlock(&sess->lock);
}

void jaln_session_destroy(jaln_session **psession) {
	if (!psession || !*psession) {
		return;
	}

	vortex_mutex_lock(&(*psession)->lock);

	jaln_session *sess = *psession;
	if (JALN_ROLE_SUBSCRIBER == sess->role ) {
		if (sess->dgst && sess->sub_data && sess->sub_data->sm && sess->sub_data->sm->dgst_inst) {
			sess->dgst->destroy(sess->sub_data->sm->dgst_inst);
		}
		jaln_sub_data_destroy(&sess->sub_data);
	} else {
		if (sess->pub_data && sess->pub_data->dgst_inst) {
			if (sess->dgst) {
				sess->dgst->destroy(sess->pub_data->dgst_inst);
			}
		}
		jaln_pub_data_destroy(&sess->pub_data);
	}
	if (sess->dgst_list) {
		axl_list_free(sess->dgst_list);
	}
	jaln_channel_info_destroy(&sess->ch_info);
	jaln_ctx_remove_session(sess->jaln_ctx, sess);
	jaln_ctx_unref(sess->jaln_ctx);
	free(sess->id);
	if (sess->curl_ctx) {
		curl_easy_cleanup(sess->curl_ctx);
	}
	vortex_mutex_unlock(&(*psession)->lock);
	vortex_mutex_destroy(&(*psession)->lock);
	free(sess);
	*psession = NULL;
}

struct jaln_sub_data *jaln_sub_data_create()
{
	struct jaln_sub_data *sub_data = jal_calloc(1, sizeof(*sub_data));
	vortex_cond_create(&sub_data->dgst_list_cond);
	return sub_data;
}

void jaln_sub_data_destroy(struct jaln_sub_data **psub_data) {
	if (!psub_data  || !*(psub_data)) {
		return;
	}
	struct jaln_sub_data *sub_data = *psub_data;
	jaln_sub_state_machine_destroy(&sub_data->sm);
	vortex_cond_destroy(&sub_data->dgst_list_cond);
	free(sub_data);
	*psub_data = NULL;
}

struct jaln_pub_data *jaln_pub_data_create()
{
	struct jaln_pub_data *pub_data = jal_calloc(1, sizeof(*pub_data));
	pub_data->msg_no = -1;
	return pub_data;
}

void jaln_pub_data_destroy(struct jaln_pub_data **ppub_data) {
	if (!ppub_data  || !*(ppub_data)) {
		return;
	}
	struct jaln_pub_data *pub_data = *ppub_data;
	free(pub_data->nonce);
	free(pub_data->dgst);
	free(pub_data);
	*ppub_data = NULL;
}

axl_bool jaln_session_on_close_channel(int channel_num,
		__attribute__((unused)) VortexConnection *connection,
		axlPointer user_data)
{
	jaln_session *sess = (jaln_session*) user_data;
	if (!sess) {
		// shouldn't happen, but if it does, there is no session
		// associated with the channel, so should be safe to close it.
		return axl_true;
	}
	vortex_mutex_lock(&sess->lock);
	if (channel_num == sess->rec_chan_num) {
		sess->closing = axl_true;
		sess->rec_chan = NULL;
		sess->rec_chan_num = -1;
	} else if (channel_num == sess->dgst_chan_num) {
		sess->closing = axl_true;
		sess->dgst_chan = NULL;
		sess->dgst_chan_num = -1;
	} else {
		vortex_mutex_unlock(&sess->lock);
		return axl_true;
	}
	if (!sess->rec_chan && !sess->dgst_chan) {
		jaln_context *ctx = sess->jaln_ctx;
		if (ctx && ctx->conn_callbacks) {
			vortex_mutex_lock(&ctx->lock);
			ctx->conn_callbacks->on_channel_close(sess->ch_info, ctx->user_data);
			vortex_mutex_unlock(&ctx->lock);
		}
	}
	vortex_mutex_unlock(&sess->lock);
	jaln_session_unref(sess);
	return axl_true;
}

void jaln_session_notify_close(
		__attribute__((unused)) VortexConnection *conn,
		int channel_num,
		axl_bool was_closed,
		__attribute__((unused)) const char *code,
		__attribute__((unused)) const char *msg,
		void *user_data)
{
	if (!was_closed) {
		return;
	}
	jaln_session *sess = (jaln_session*) user_data;
	if (!sess) {
		// shouldn't happen
		return;
	}
	vortex_mutex_lock(&sess->lock);
	if (channel_num == sess->rec_chan_num) {
		sess->closing = axl_true;
		sess->rec_chan = NULL;
		sess->rec_chan_num = -1;
	} else if (channel_num == sess->dgst_chan_num) {
		sess->closing = axl_true;
		sess->dgst_chan = NULL;
		sess->dgst_chan_num = -1;
	} else {
		vortex_mutex_unlock(&sess->lock);
		return;
	}
	if (!sess->rec_chan && !sess->dgst_chan) {
		jaln_context *ctx = sess->jaln_ctx;
		if (ctx && ctx->conn_callbacks) {
			vortex_mutex_lock(&ctx->lock);
			ctx->conn_callbacks->on_channel_close(sess->ch_info, ctx->user_data);
			vortex_mutex_unlock(&ctx->lock);
		}
	}
	vortex_mutex_unlock(&sess->lock);
	jaln_session_unref(sess);
}

void jaln_session_notify_unclean_channel_close(VortexChannel *channel,
		axlPointer user_data)
{
	jaln_session *sess = (jaln_session*) user_data;
	if (!sess) {
		// shouldn't happen
		return;
	}
	vortex_mutex_lock(&sess->lock);
	if (channel == sess->rec_chan) {
		sess->closing = axl_true;
		sess->rec_chan = NULL;
		sess->rec_chan_num = -1;
	} else if (channel == sess->dgst_chan) {
		sess->closing = axl_true;
		sess->dgst_chan = NULL;
		sess->dgst_chan_num = -1;
	} else {
		vortex_mutex_unlock(&sess->lock);
		return;
	}
	if (!sess->rec_chan && !sess->dgst_chan) {
		jaln_context *ctx = sess->jaln_ctx;
		if (ctx && ctx->conn_callbacks) {
			vortex_mutex_lock(&ctx->lock);
			ctx->conn_callbacks->on_channel_close(sess->ch_info, ctx->user_data);
			vortex_mutex_unlock(&ctx->lock);
		}
	}
	vortex_mutex_unlock(&sess->lock);
	jaln_session_unref(sess);
}

enum jal_status jaln_session_add_to_dgst_list(jaln_session *sess, char *nonce, uint8_t *dgst_buf, uint64_t dgst_len)
{
	if (!sess || !nonce || !dgst_buf || (0 == dgst_len)) {
		return JAL_E_INVAL;
	}
	struct jaln_digest_info *dgst_info = jaln_digest_info_create(nonce, dgst_buf, dgst_len);

	vortex_mutex_lock(&sess->lock);
	axl_list_append(sess->dgst_list, dgst_info);
	if (JALN_ROLE_SUBSCRIBER == sess->role) {
		axl_bool notify = axl_false;
		if (axl_list_length(sess->dgst_list) >= sess->dgst_list_max) {
			notify = axl_true;
		}
		if (notify) {
			// wake up the thread that is supposed to be sending
			// digest/sync messages
			vortex_cond_signal(&sess->sub_data->dgst_list_cond);
		}
	}
	vortex_mutex_unlock(&sess->lock);
	return JAL_OK;
}

int jaln_ptrs_equal(axlPointer a, axlPointer b)
{
	// this function is used only for storing jaln_session objects
	// in an axlHash. A comparison against the pointer value is sufficient.
	return a - b;
}

axlList *jaln_session_list_create()
{
	return axl_list_new(jaln_ptrs_equal, NULL);
}

axl_bool jaln_session_associate_digest_channel_no_lock(jaln_session *session, VortexChannel *chan, int chan_num)
{
	if (!session || session->dgst_chan != NULL || !chan) {
		return axl_false;
	}
	// setting '2' disables MIME generation completely.
	vortex_channel_set_automatic_mime(chan, 2);
	vortex_channel_set_serialize(chan, axl_true);
	session->dgst_chan = chan;
	session->dgst_chan_num = chan_num;
	vortex_channel_set_closed_handler(chan, jaln_session_notify_unclean_channel_close, session);
	vortex_channel_set_close_handler(chan, jaln_session_on_close_channel, session);
	if (JALN_ROLE_SUBSCRIBER == session->role) {
		jaln_create_sub_digest_channel_thread_no_lock(session);
		return axl_true;
	} else if (JALN_ROLE_PUBLISHER == session->role) {
		vortex_channel_set_received_handler(chan, jaln_publisher_digest_and_sync_frame_handler, session);
		return axl_true;
	}
	return axl_false;
}

void jaln_session_on_dgst_channel_create(
		int channel_num,
		VortexChannel *chan,
		__attribute__((unused)) VortexConnection *conn,
		axlPointer user_data)
{
	jaln_session *sess = (jaln_session*) user_data;
	if ((channel_num == -1) || !chan) {
		jaln_session_set_errored(sess);
		return;
	}
	jaln_session_ref(sess);
	vortex_mutex_lock(&sess->lock);
	jaln_session_associate_digest_channel_no_lock(sess, chan, channel_num);
	vortex_mutex_unlock(&sess->lock);
}

enum jal_status jaln_session_is_ok(jaln_session *sess)
{
	if (!sess) {
		return JAL_E_INVAL;
	}
	if (!sess->curl_ctx) {
		return JAL_E_NOT_CONNECTED;
	}
	if (sess->closing || sess->errored) {
		return JAL_E_INTERNAL_ERROR;
	}
	return JAL_OK;
}
