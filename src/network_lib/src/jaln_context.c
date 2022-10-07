/**
 * @file jaln_context.c This file contains functions related to a jaln_context
 *
 * Public functions for creating and configuring a jaln_context.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
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

#include <stdlib.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>
#include <jalop/jaln_publisher_callbacks.h>
#include <jalop/jaln_subscriber_callbacks.h>
#include <jalop/jaln_connection_callbacks.h>
#include "jal_alloc.h"
#include "jal_error_callback_internal.h"
#include "jaln_context.h"
#include "jaln_encoding.h"
#include "jaln_digest.h"
#include "jaln_strings.h"
#include "jaln_session.h"

jaln_context *jaln_context_create(void)
{
	jaln_context *ctx = jal_calloc(1, sizeof(*ctx));

	if (!vortex_mutex_create(&ctx->lock)) {
		jal_error_handler(JAL_E_NO_MEM);
	}

	ctx->ref_cnt = 1;
	ctx->sha256_digest = jal_sha256_ctx_create();
	free(ctx->sha256_digest->algorithm_uri);
	ctx->sha256_digest->algorithm_uri = jal_strdup(JALN_DGST_SHA256);

	ctx->dgst_algs = axl_list_new(jaln_digest_list_equal_func, jaln_digest_list_destroy);
	if (!ctx->dgst_algs) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	ctx->xml_encodings = axl_list_new(jaln_string_list_case_insensitive_func, free);
	if (!ctx->xml_encodings) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	ctx->sessions_by_conn = axl_hash_new(axl_hash_string, axl_hash_equal_string);
	if (!ctx->sessions_by_conn) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	ctx->vortex_ctx = vortex_ctx_new();
	if (!ctx->vortex_ctx) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	if (!vortex_init_ctx(ctx->vortex_ctx)) {
		jaln_context_destroy(&ctx);
		jal_error_handler(JAL_E_UNINITIALIZED);
	}

	// Configure the vortex thread pool
	// Set the maximum possible number of threads to 50
	// When an additional thread is needed, create 1 at a time
	// Set the delay between creation of new threads to 0 (no delay)
	// Do not prune threads after their tasks are complete
	vortex_thread_pool_setup(ctx->vortex_ctx, 50, 1, 0, axl_false);
	return ctx;
}

enum jal_status jaln_context_destroy(jaln_context **jaln_ctx)
{
	if (!jaln_ctx || !(*jaln_ctx)) {
		return JAL_E_INVAL;
	}

	jaln_publisher_callbacks_destroy(&(*jaln_ctx)->pub_callbacks);
	jaln_subscriber_callbacks_destroy(&(*jaln_ctx)->sub_callbacks);
	jaln_connection_callbacks_destroy(&(*jaln_ctx)->conn_callbacks);
	jal_digest_ctx_destroy(&(*jaln_ctx)->sha256_digest);
	if ((*jaln_ctx)->dgst_algs) {
		axl_list_free((*jaln_ctx)->dgst_algs);
	}
	if ((*jaln_ctx)->xml_encodings) {
		axl_list_free((*jaln_ctx)->xml_encodings);
	}
	vortex_mutex_destroy(&(*jaln_ctx)->lock);
	if ((*jaln_ctx)->vortex_ctx) {
		vortex_exit_ctx((*jaln_ctx)->vortex_ctx, axl_true);
	}
	if ((*jaln_ctx)->sessions_by_conn) {
		axl_hash_free((*jaln_ctx)->sessions_by_conn);
	}

	free((*jaln_ctx)->peer_certs);
	free((*jaln_ctx)->public_cert);
	free((*jaln_ctx)->private_key);

	free(*jaln_ctx);
	*jaln_ctx = NULL;

	return JAL_OK;
}

void jaln_ctx_remove_session(jaln_context *ctx, jaln_session *sess)
{
	if (!ctx) {
		return;
	}
	vortex_mutex_lock(&ctx->lock);
	jaln_ctx_remove_session_no_lock(ctx, sess);
	vortex_mutex_unlock(&ctx->lock);
}

void jaln_ctx_remove_session_no_lock(jaln_context *ctx, jaln_session *sess)
{
	if (!ctx || !ctx->sessions_by_conn || !sess || !sess->ch_info || !sess->ch_info->hostname) {
		return;
	}
	axlList *sessions = axl_hash_get(ctx->sessions_by_conn, sess->ch_info->hostname);
	if (!sessions) {
		return;
	}
	axl_list_remove(sessions, sess);
	if (0 == axl_list_length(sessions)) {
		axl_hash_remove(ctx->sessions_by_conn, sess->ch_info->hostname);
	}
}

enum jal_status jaln_ctx_add_session_no_lock(jaln_context *ctx, jaln_session *sess)
{
	if (!ctx || !ctx->sessions_by_conn || !sess || !sess->ch_info || !sess->ch_info->hostname) {
		return JAL_E_INVAL;
	}
	jaln_session *exists =
		jaln_ctx_find_session_by_rec_channel_no_lock(ctx, sess->ch_info->hostname, sess->rec_chan_num);
	if (exists) {
		return JAL_E_EXISTS;
	}
	axlList *sessions = axl_hash_get(ctx->sessions_by_conn, sess->ch_info->hostname);
	if (!sessions) {
		sessions = jaln_session_list_create();
		char *key = jal_strdup(sess->ch_info->hostname);
		axl_hash_insert_full(ctx->sessions_by_conn, key, free, sessions, jaln_axl_list_destroy_wrapper);
	}
	axl_list_append(sessions, sess);
	return JAL_OK;
}

axl_bool jaln_ctx_cmp_session_rec_channel_to_channel(axlPointer ptr, axlPointer data)
{
	if (!ptr || !data) {
		return axl_false;
	}
	int chan_num = *((int*) data);
	if (0 >= chan_num) {
		return axl_false;
	}
	jaln_session *sess = (jaln_session*) ptr;
	return (sess->rec_chan_num == chan_num);
}

jaln_session *jaln_ctx_find_session_by_rec_channel_no_lock(jaln_context *ctx, char *server_name, int rec_channel_num)
{
	axlList *sessions = axl_hash_get(ctx->sessions_by_conn, server_name);
	if (!sessions) {
		return NULL;
	}
	return (jaln_session*)
		axl_list_lookup(sessions, jaln_ctx_cmp_session_rec_channel_to_channel, &rec_channel_num);
}


enum jal_status jaln_register_digest_algorithm(jaln_context *ctx,
				struct jal_digest_ctx *dgst_ctx)
{
	if (!ctx || !ctx->dgst_algs || !dgst_ctx || !jal_digest_ctx_is_valid(dgst_ctx)) {
		return JAL_E_INVAL;
	}

	axl_list_remove(ctx->dgst_algs, dgst_ctx);
	axl_list_append(ctx->dgst_algs, dgst_ctx);

	return JAL_OK;
}

void jaln_ctx_ref(jaln_context *ctx)
{
	if (!ctx) {
		return;
	}
	vortex_mutex_lock(&ctx->lock);
	if (0 >= ctx->ref_cnt) {
		// this would be bad, already deleted
		vortex_mutex_unlock(&ctx->lock);
		return;
	}
	ctx->ref_cnt++;
	vortex_mutex_unlock(&ctx->lock);
}

void jaln_ctx_unref(jaln_context *ctx)
{
	if (!ctx) {
		return;
	}
	vortex_mutex_lock(&ctx->lock);
	if (0 >= ctx->ref_cnt) {
		vortex_mutex_unlock(&ctx->lock);
		// shouldn't happen, already deleted
		return;
	}
	ctx->ref_cnt--;
	if (0 == ctx->ref_cnt) {
		vortex_mutex_unlock(&ctx->lock);
		jaln_context_destroy(&ctx);
		return;
	}
	vortex_mutex_unlock(&ctx->lock);
}

void jaln_axl_list_destroy_wrapper(axlPointer ptr) {
	axlList *l = (axlList*) ptr;
	axl_list_free(l);
}
