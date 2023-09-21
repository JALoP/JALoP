/** 
 * @file jal_digest.c This file contains functions for dealing with the
 * jal_digest_ctx struct.
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

#include <unistd.h>
#include <errno.h>
#include <openssl/sha.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include "jal_alloc.h"
#include "jal_error_callback_internal.h"

#define DIGEST_BUF_SIZE 8192

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

static void *jal_sha384_create(void)
{
	SHA512_CTX * new_sha384 = jal_calloc(1, sizeof(*new_sha384));
	return new_sha384;
}

static enum jal_status jal_sha384_init(void *instance)
{
	int ret = SHA384_Init((SHA512_CTX *)instance);

	if (ret == 1) {
		return JAL_OK;
	} else {
		return JAL_E_INVAL;
	}
}

static enum jal_status jal_sha384_update(void *instance, const uint8_t *data, size_t len)
{
	int ret = SHA384_Update((SHA512_CTX *)instance, data, len);

	if (ret == 1) {
		return JAL_OK;
	} else {
		return JAL_E_INVAL;
	}
}

static enum jal_status jal_sha384_final(void *instance, uint8_t *data, size_t *len)
{
	if (*len < SHA384_DIGEST_LENGTH) {
		return JAL_E_INVAL;
	}

	int ret = SHA384_Final((unsigned char *)data, (SHA512_CTX *)instance);

	if (ret == 1) {
		*len = ((SHA512_CTX *)instance)->md_len;
		return JAL_OK;
	} else {
		return JAL_E_INVAL;
	}
}

static void jal_sha384_destroy(void *instance)
{
	free(instance);
}

static void *jal_sha512_create(void)
{
	SHA512_CTX * new_sha512 = jal_calloc(1, sizeof(*new_sha512));
	return new_sha512;
}

static enum jal_status jal_sha512_init(void *instance)
{
	int ret = SHA512_Init((SHA512_CTX *)instance);

	if (ret == 1) {
		return JAL_OK;
	} else {
		return JAL_E_INVAL;
	}
}

static enum jal_status jal_sha512_update(void *instance, const uint8_t *data, size_t len)
{
	int ret = SHA512_Update((SHA512_CTX *)instance, data, len);

	if (ret == 1) {
		return JAL_OK;
	} else {
		return JAL_E_INVAL;
	}
}

static enum jal_status jal_sha512_final(void *instance, uint8_t *data, size_t *len)
{
	if (*len < SHA512_DIGEST_LENGTH) {
		return JAL_E_INVAL;
	}

	int ret = SHA512_Final((unsigned char *)data, (SHA512_CTX *)instance);

	if (ret == 1) {
		*len = ((SHA512_CTX *)instance)->md_len;
		return JAL_OK;
	} else {
		return JAL_E_INVAL;
	}
}

static void jal_sha512_destroy(void *instance)
{
	free(instance);
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

static struct jal_digest_ctx *jal_sha256_ctx_create()
{
	struct jal_digest_ctx *new_sha256 = jal_calloc(1, sizeof(*new_sha256));

	new_sha256->algorithm_uri = jal_strdup(JAL_SHA256_ALGORITHM_URI);
	new_sha256->len = SHA256_DIGEST_LENGTH;
	new_sha256->create = jal_sha256_create;
	new_sha256->init = jal_sha256_init;
	new_sha256->update = jal_sha256_update;
	new_sha256->final = jal_sha256_final;
	new_sha256->destroy = jal_sha256_destroy;

	return new_sha256;
}

static struct jal_digest_ctx *jal_sha384_ctx_create()
{
	struct jal_digest_ctx *new_sha384 = jal_calloc(1, sizeof(*new_sha384));

	new_sha384->algorithm_uri = jal_strdup(JAL_SHA384_ALGORITHM_URI);
	new_sha384->len = SHA384_DIGEST_LENGTH;
	new_sha384->create = jal_sha384_create;
	new_sha384->init = jal_sha384_init;
	new_sha384->update = jal_sha384_update;
	new_sha384->final = jal_sha384_final;
	new_sha384->destroy = jal_sha384_destroy;

	return new_sha384;
}

static struct jal_digest_ctx *jal_sha512_ctx_create()
{
	struct jal_digest_ctx *new_sha512 = jal_calloc(1, sizeof(*new_sha512));

	new_sha512->algorithm_uri = jal_strdup(JAL_SHA512_ALGORITHM_URI);
	new_sha512->len = SHA512_DIGEST_LENGTH;
	new_sha512->create = jal_sha512_create;
	new_sha512->init = jal_sha512_init;
	new_sha512->update = jal_sha512_update;
	new_sha512->final = jal_sha512_final;
	new_sha512->destroy = jal_sha512_destroy;

	return new_sha512;
}

struct jal_digest_ctx *jal_digest_ctx_create(enum jal_digest_algorithm algorithm)
{
	switch(algorithm)
	{
		case JAL_DIGEST_ALGORITHM_SHA384:
			return jal_sha384_ctx_create();
		case JAL_DIGEST_ALGORITHM_SHA512:
			return jal_sha512_ctx_create();
		case JAL_DIGEST_ALGORITHM_SHA256:
		default:
			return jal_sha256_ctx_create();
	}
}

int jal_digest_ctx_is_valid(const struct jal_digest_ctx *ctx)
{
	return ctx && ctx->len > 0 && ctx->create && ctx->init && ctx->update &&
		ctx->final && ctx->destroy && ctx->algorithm_uri;
}

enum jal_status jal_digest_buffer(struct jal_digest_ctx *digest_ctx,
		const uint8_t *data, size_t len, uint8_t **digest)
{
	if(!data || !digest || *digest) {
		return JAL_E_INVAL;
	}

	if (!jal_digest_ctx_is_valid(digest_ctx)) {
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

enum jal_status jal_digest_fd(struct jal_digest_ctx *digest_ctx,
                int fd, uint8_t **digest)
{
	if(!digest || *digest || fd < 0) {
		return JAL_E_INVAL;
	}

	if(!jal_digest_ctx_is_valid(digest_ctx)) {
		return JAL_E_INVAL;
	}

	enum jal_status ret;
	*digest = jal_malloc(digest_ctx->len);

	void *instance = digest_ctx->create();
	if (!instance) {
		jal_error_handler(JAL_E_NO_MEM);
	}

	void *buf = jal_malloc(DIGEST_BUF_SIZE);

	ret = digest_ctx->init(instance);
	if(ret != JAL_OK) {
		goto err_out;
	}


	int bytes_read;
	int seek_ret = lseek(fd, 0, SEEK_SET);
	if (seek_ret == -1) {
		ret = JAL_E_FILE_IO;
		goto err_out;
	}


	while ((bytes_read = read(fd, buf, DIGEST_BUF_SIZE)) > 0) {
		ret = digest_ctx->update(instance, buf, bytes_read);
		if(ret != JAL_OK) {
			goto err_out;
		}
	}
	if (bytes_read == -1) {
		ret = JAL_E_FILE_IO;
		goto err_out;
	}

	size_t digest_length = digest_ctx->len;
	ret = digest_ctx->final(instance, *digest, &digest_length);
	if(ret != JAL_OK) {
		goto err_out;
	}

	free(buf);
	digest_ctx->destroy(instance);
	return JAL_OK;

err_out:
	free(buf);
	digest_ctx->destroy(instance);
	free(*digest);
	*digest = NULL;
	return ret;

}

enum jal_status jal_get_digest_from_str(const char *str, enum jal_digest_algorithm *digest) {
	for (unsigned long int i = 0; i < sizeof(conversion) / sizeof(conversion[0]); i++) {
		if (!strcasecmp(str, conversion[i].str)) {
			*digest = conversion[i].val;
			return JAL_OK;
		}
	}

	// If the incoming string doesn't match any of the strings for a digest enum
	return JAL_E_INVAL;
}

enum jal_status jal_get_digest_from_uri(const char *uri, enum jal_digest_algorithm *digest) {
	for (unsigned long int i = 0; i < sizeof(conversion) / sizeof(conversion[0]); i++) {
		if (!strcmp(uri, uri_conversion[i].str)) {
			*digest = uri_conversion[i].val;
			return JAL_OK;
		}
	}

	// If the incoming string doesn't match any of the URIs for a digest enum
	return JAL_E_INVAL;
}

enum jal_status jal_parse_digest_algorithm_str(const char *str, enum jal_digest_algorithm **digest_list, size_t *num_digests) {
	enum jal_digest_algorithm cur_enum = JAL_DIGEST_ALGORITHM_DEFAULT;
	char *cur_str = NULL;
	char *saveptr = NULL; 
	size_t list_len = 0;
	char *str_cpy = strdup(str);

	cur_str = strtok_r(str_cpy, JAL_DIGEST_ALGORITHM_DELIMETER, &saveptr);

	while(cur_str) {
		char isDuplicate = 0;
		if (JAL_OK != jal_get_digest_from_str(cur_str, &cur_enum)) {
			free(str_cpy);
			return JAL_E_INVAL;
		}

		for(size_t i = 0; i < list_len; i++) {
			if ((*digest_list)[i] == cur_enum) {
				isDuplicate = 1;
				break;
			}
		}

		if (!isDuplicate) {
			list_len++;
			*digest_list = (enum jal_digest_algorithm *) jal_realloc(*digest_list, list_len * sizeof(enum jal_digest_algorithm));
			(*digest_list)[list_len - 1] = cur_enum;
		}

		cur_str = strtok_r(NULL, JAL_DIGEST_ALGORITHM_DELIMETER, &saveptr);
	}

	*num_digests = list_len;
	free(str_cpy);
	return JAL_OK;
}

enum jal_status jal_get_digest_algorithm_list(const char *config, const char *cli, enum jal_digest_algorithm **digest_list, size_t *num_digests) {
	if (cli && 0 != strlen(cli)) {
		return jal_parse_digest_algorithm_str(cli, digest_list, num_digests);
	}
	else if (config && 0 != strlen(config)) {
		return jal_parse_digest_algorithm_str(config, digest_list, num_digests);
	}
	else {
		*digest_list = (enum jal_digest_algorithm *) jal_realloc(*digest_list, sizeof(enum jal_digest_algorithm));
		(*digest_list)[0] = JAL_DIGEST_ALGORITHM_DEFAULT;
		*num_digests = 1;
		return JAL_OK;
	}
}
