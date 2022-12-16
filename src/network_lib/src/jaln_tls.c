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

#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>
#include "jaln_context.h"
#include "jaln_tls.h"
#include "jal_alloc.h"

enum jal_status jaln_register_tls(jaln_context *ctx,
				const char *private_key,
				const char *public_cert,
				const char *peer_certs)
{
	if (!ctx || !private_key || !public_cert || !peer_certs) {
		return JAL_E_INVAL;
	}

	if (ctx->private_key || ctx->public_cert || ctx->peer_certs) {
		return JAL_E_INVAL;
	}

	ctx->private_key = jal_strdup(private_key);
	ctx->public_cert = jal_strdup(public_cert);
	ctx->peer_certs = jal_strdup(peer_certs);

	return JAL_OK;
}
