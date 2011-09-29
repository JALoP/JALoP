/**
 * @file jaln_context.c
 *
 * Public functions for creating and configuring a jaln_context.
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

jaln_context *jaln_context_create(void)
{
	jaln_context *ctx = jal_calloc(1, sizeof(*ctx));
	ctx->dgst_algs = axl_list_new(jaln_digest_list_equal_func, jaln_digest_list_destroy);
	if (!ctx->dgst_algs) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	ctx->xml_encodings = axl_list_new(jaln_string_list_case_insensitive_func, free);
	if (!ctx->xml_encodings) {
		jal_error_handler(JAL_E_NO_MEM);
	}
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
	if ((*jaln_ctx)->dgst_algs) {
		axl_list_free((*jaln_ctx)->dgst_algs);
	}
	if ((*jaln_ctx)->xml_encodings) {
		axl_list_free((*jaln_ctx)->xml_encodings);
	}
	free(*jaln_ctx);
	*jaln_ctx = NULL;

	return JAL_OK;
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
