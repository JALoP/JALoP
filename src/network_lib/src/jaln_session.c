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

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"

#include "jaln_channel_info.h"
#include "jaln_context.h"
#include "jaln_digest_info.h"
#include "jaln_publisher.h"
#include "jaln_session.h"

jaln_session *jaln_session_create()
{
	jaln_session *sess = jal_calloc(1, sizeof(*sess));
	sess->mode = JALN_UNKNOWN_MODE;
	sess->ref_cnt = 1;
	sess->dgst_on = axl_true;  // digest challenge enabled by default
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
	if (0 >= sess->ref_cnt) {
		// already deleted?
		return;
	}
	sess->ref_cnt++;
}

void jaln_session_unref(jaln_session *sess)
{
	if (!sess) {
		return;
	}
	if (0 >= sess->ref_cnt) {
		// shouldn't happen
		return;
	}
	sess->ref_cnt--;
	if (0 == sess->ref_cnt) {
		jaln_session_destroy(&sess);
		return;
	}
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
	jaln_session_set_errored_no_lock(sess);
}

void jaln_session_set_dgst_timeout(jaln_session *sess, long timeout)
{
	if (!sess) {
		return;
	}
	sess->dgst_timeout = timeout;
}

void jaln_session_set_dgst_max(jaln_session *sess, int max)
{
	if (!sess) {
		return;
	}
	sess->dgst_list_max = max;
}

void jaln_session_destroy(jaln_session **psession) {
	if (!psession || !*psession) {
		return;
	}

	jaln_session *sess = *psession;
	if (sess->dgst_list) {
		axl_list_free(sess->dgst_list);
	}
	jaln_channel_info_destroy(&sess->ch_info);
	jaln_ctx_unref(sess->jaln_ctx);
	free(sess->id);
	if (sess->curl_ctx) {
		curl_easy_cleanup(sess->curl_ctx);
	}
	jal_digest_ctx_destroy(&(sess->dgst));
	jaln_pub_data_destroy(&(sess->pub_data));
	free(sess->pub_data);
	free(sess);
	*psession = NULL;
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
	if(pub_data->headers) {
		curl_slist_free_all(pub_data->headers);
		pub_data->headers = NULL;
	}
	free(pub_data->nonce);
	free(pub_data->dgst);
	free(pub_data->dgst_inst);
	free(pub_data);
	*ppub_data = NULL;
}

enum jal_status jaln_session_add_to_dgst_list(jaln_session *sess, char *nonce, uint8_t *dgst_buf, uint64_t dgst_len)
{
	if (!sess || !nonce || !dgst_buf || (0 == dgst_len)) {
		return JAL_E_INVAL;
	}
	struct jaln_digest_info *dgst_info = jaln_digest_info_create(nonce, dgst_buf, dgst_len);

	axl_list_append(sess->dgst_list, dgst_info);
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
