/**
 * @file jal_digest.c This file contains functions for dealing with the
 * jal_digest_ctx struct.
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

#include <openssl/sha.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include "jal_alloc.h"

static const char* JAL_SHA256_ALGORITHM_URI = "http://www.w3.org/2001/04/xmlenc#sha256";

static void *jal_sha256_create(void)
{
	SHA256_CTX * new_sha256 = jal_calloc(1, sizeof(*new_sha256));
	return new_sha256;
}

static enum jal_status jal_sha256_init(void *instance)
{
	int ret = SHA256_Init((SHA256_CTX *)instance);

	if (ret == 1) {
		return JAL_OK;
	} else {
		return JAL_E_INVAL;
	}
}

static enum jal_status jal_sha256_update(void *instance, const uint8_t *data, size_t len)
{
	int ret = SHA256_Update((SHA256_CTX *)instance, data, len);

	if (ret == 1) {
		return JAL_OK;
	} else {
		return JAL_E_INVAL;
	}
}

static enum jal_status jal_sha256_final(void *instance, uint8_t *data, size_t *len)
{
	if (*len < SHA256_DIGEST_LENGTH) {
		return JAL_E_INVAL;
	}

	int ret = SHA256_Final((unsigned char *)data, (SHA256_CTX *)instance);

	if (ret == 1) {
		*len = ((SHA256_CTX *)instance)->md_len;
		return JAL_OK;
	} else {
		return JAL_E_INVAL;
	}
}

static void jal_sha256_destroy(void *instance)
{
	free(instance);
}

struct jal_digest_ctx *jal_digest_ctx_create()
{
	struct jal_digest_ctx *new_digest_ctx;
	new_digest_ctx = jal_calloc(1, sizeof(*new_digest_ctx));
	return new_digest_ctx;
}

void jal_digest_ctx_destroy(struct jal_digest_ctx **digest_ctx)
{
	if (!digest_ctx || !*digest_ctx) {
		return;
	}
	free ((*digest_ctx)->algorithm_uri);
	free(*digest_ctx);
	*digest_ctx = 0;
}

struct jal_digest_ctx *jal_sha256_ctx_create()
{
	struct jal_digest_ctx *new_sha256 = jal_digest_ctx_create();

	new_sha256->algorithm_uri = jal_strdup(JAL_SHA256_ALGORITHM_URI);
	new_sha256->len = SHA256_DIGEST_LENGTH;
	new_sha256->create = jal_sha256_create;
	new_sha256->init = jal_sha256_init;
	new_sha256->update = jal_sha256_update;
	new_sha256->final = jal_sha256_final;
	new_sha256->destroy = jal_sha256_destroy;

	return new_sha256;
}

