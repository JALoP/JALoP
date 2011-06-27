/**
 * @file jalp_logger_metadata.h This file defines functions for calculating
 * digests.
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

#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include "jal_error_callback_internal.h"
#include "jal_alloc.h"
#include "jalp_digest_internal.h"

enum jal_status jalp_digest_buffer(struct jal_digest_ctx *digest_ctx,
		const uint8_t *data, size_t len, uint8_t **digest)
{
	if(!digest_ctx || !data || !digest || *digest) {
		return JAL_E_INVAL;
	}

	if(!digest_ctx->create || !digest_ctx->init || !digest_ctx->update
		|| !digest_ctx->final || !digest_ctx->destroy) {
		return JAL_E_INVAL;
	}

	void *instance = digest_ctx->create();
	if(!instance) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	*digest = jal_malloc(digest_ctx->len);

	enum jal_status ret = JAL_E_INVAL;
	ret = digest_ctx->init(instance);
	if(ret != JAL_OK) {
		goto err_out;
	}

	ret = digest_ctx->update(instance, data, len);
	if(ret != JAL_OK) {
		goto err_out;
	}

	size_t digest_length = digest_ctx->len;
	ret = digest_ctx->final(instance, *digest, &digest_length);
	if(ret != JAL_OK) {
		goto err_out;
	}

	digest_ctx->destroy(instance);
	return JAL_OK;

err_out:
	digest_ctx->destroy(instance);
	free(*digest);
	*digest = NULL;
	return ret;

}
