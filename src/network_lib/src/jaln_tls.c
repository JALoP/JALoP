/**
 * @file jaln_tls.c This file contains function definitions for code related to tls.
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

#include <axl.h>
#include <vortex.h>
#include <vortex_tls.h>
#include <openssl/ssl.h>

#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>
#include "jaln_context.h"
#include "jaln_tls.h"
#include "jal_alloc.h"

axl_bool jaln_profile_mask (VortexConnection *connection,
				int channel_num,
				const char *uri,
				__attribute__((unused)) const char *profile_content,
				__attribute__((unused)) VortexEncoding encoding,
				__attribute__((unused)) const char *server_name,
				__attribute__((unused)) VortexFrame *frame,
				char **error_msg,
				__attribute__((unused)) axlPointer user_data)
{
	if (0 == strcmp(uri, VORTEX_TLS_PROFILE_URI)) {
		return axl_false;
	} else if (channel_num > 0 && !vortex_connection_is_tlsficated(connection)) {
		*error_msg = axl_strdup("Profile not accepted due to an insecure connection");
		return axl_true;
	}

	return axl_false;
}

axl_bool jaln_tls_on_connection_accepted(VortexConnection *connection, axlPointer user_data)
{
	vortex_connection_set_profile_mask(connection, jaln_profile_mask, user_data);
	return axl_true;
}

axlPointer jaln_ssl_ctx_creation(__attribute__((unused))VortexConnection *connection, axlPointer user_data)
{
	SSL_CTX *ssl_ctx;
	jaln_context *jaln_ctx = (jaln_context *)user_data;

	ssl_ctx = SSL_CTX_new(TLSv1_method());

	if (!SSL_CTX_load_verify_locations(ssl_ctx, NULL, jaln_ctx->peer_certs)) {
		goto out;
	}
	if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, jaln_ctx->public_cert)) {
		goto out;
	}
	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, jaln_ctx->private_key, SSL_FILETYPE_PEM)) {
		goto out;
	}

	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	return ssl_ctx;
out:
	SSL_CTX_free(ssl_ctx);
	return NULL;
}

enum jal_status jaln_register_tls(jaln_context *ctx,
				const char *private_key,
				const char *public_cert,
				const char *peer_certs)
{
	if (!ctx) {
		return JAL_E_INVAL;
	}

	vortex_mutex_lock(&ctx->lock);

	if (!ctx->vortex_ctx || !private_key || !public_cert || !peer_certs) {
		return JAL_E_INVAL;
	}

	if (ctx->private_key || ctx->public_cert || ctx->peer_certs) {
		return JAL_E_INVAL;
	}

	ctx->private_key = jal_strdup(private_key);
	ctx->public_cert = jal_strdup(public_cert);
	ctx->peer_certs = jal_strdup(peer_certs);

	if (!vortex_tls_init(ctx->vortex_ctx)) {
		return JAL_E_INVAL;
	}

	vortex_tls_set_default_ctx_creation(ctx->vortex_ctx, jaln_ssl_ctx_creation, ctx);
	vortex_tls_accept_negotiation(ctx->vortex_ctx, NULL, NULL, NULL);

	vortex_mutex_unlock(&ctx->lock);

	return JAL_OK;
}
