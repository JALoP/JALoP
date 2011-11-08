/**
 * @file jaln_session.c This file contains function
 * definitions for internal library functions related to a jaln_session
 * structure. The jaln_session tracks the internal state for a peer that is
 * receiving jal records.
 *
 * @section LICENSE
 *
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
#include <axl.h>
#include <vortex.h>

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"

#include "jaln_channel_info.h"
#include "jaln_context.h"
#include "jaln_digest_info.h"
#include "jaln_session.h"

struct jaln_session *jaln_session_create()
{
	struct jaln_session *sess = jal_calloc(1, sizeof(*sess));
	if (!vortex_mutex_create(&sess->lock)) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	sess->ref_cnt = 1;
	sess->rec_chan_num = -1;
	sess->dgst_chan_num = -1;
	sess->ch_info = jaln_channel_info_create();
	sess->dgst_list = axl_list_new(jaln_axl_equals_func_digest_info_serial_id, jaln_axl_destroy_digest_info);
	if (!sess->dgst_list) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	sess->dgst_list_max = 100;
	sess->dgst_timeout = 30 * 60 * 1000000;
	sess->errored = axl_false;
	return sess;
}

void jaln_session_ref(struct jaln_session *sess)
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

void jaln_session_unref(struct jaln_session *sess)
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

void jaln_session_set_errored_no_lock(struct jaln_session *sess)
{
	if (!sess) {
		return;
	}
	sess->errored = axl_true;
}

void jaln_session_set_errored(struct jaln_session *sess)
{
	if (!sess) {
		return;
	}
	vortex_mutex_lock(&sess->lock);
	jaln_session_set_errored_no_lock(sess);
	vortex_mutex_unlock(&sess->lock);
}

void jaln_session_destroy(struct jaln_session **psession) {
	if (!psession || !*psession) {
		return;
	}
	struct jaln_session *sess = *psession;
	// TODO: remove this session from the context.
	// jaln_ctx_remove_session(sess->jaln_ctx, sess);
	jaln_ctx_unref(sess->jaln_ctx);
	if (JALN_ROLE_SUBSCRIBER == sess->role ) {
		jaln_sub_data_destroy(&sess->sub_data);
	} else {
		jaln_pub_data_destroy(&sess->pub_data);
	}
	if (sess->dgst_list) {
		axl_list_free(sess->dgst_list);
	}

	jaln_channel_info_destroy(&sess->ch_info);
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
	// TODO: destroy the sub_data->sm.
	// jaln_sub_state_machine_destroy(&sub_data->sm);
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
	free(pub_data);
	*ppub_data = NULL;
}

