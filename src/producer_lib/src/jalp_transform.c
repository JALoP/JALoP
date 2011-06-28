/**
 * @file jalp_transform.c This file has functions for creating and destroying
 * jalp_transform structures.
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

#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include <jalop/jalp_journal_metadata.h>
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jalp_base64_internal.h"

void jalp_transform_append_internal(struct jalp_transform *prev, struct jalp_transform *transform)
{
	if (prev) {
		transform->next = prev->next;
		prev->next = transform;
	} else {
		transform->next = NULL;
	}
}


struct jalp_transform *jalp_transform_append_other(struct jalp_transform *prev,
		const char *uri, const char *xml_snippet)
{
	struct jalp_transform_other_info *other_info = NULL;
	other_info = jalp_transform_other_info_create(uri, xml_snippet);
	if (!other_info) {
		return NULL;
	}

	struct jalp_transform *transform = NULL;
	transform = (struct jalp_transform*) jal_malloc(sizeof(*transform));
	transform->type = JALP_TRANSFORM_OTHER;
	transform->other_info = other_info;
	jalp_transform_append_internal(prev, transform);
	return transform;
}
struct jalp_transform_other_info *jalp_transform_other_info_create(const char *uri, const char *xml_snippet)
{
	if (!uri) {
		return NULL;
	}
	struct jalp_transform_other_info *info = (struct jalp_transform_other_info *)jal_malloc(sizeof(*info));

	info->uri = jal_strdup(uri);
	info->xml = jal_strdup(xml_snippet);

	return info;
}
void jalp_transform_other_info_destroy(struct jalp_transform_other_info **other_info)
{
	if (!other_info || !*other_info) {
		return;
	}
	free((*other_info)->uri);
	free((*other_info)->xml);
	free(*other_info);
	*other_info = NULL;
}
struct jalp_transform_encryption_info *jalp_transform_encryption_info_create(const uint8_t *key, const size_t key_len, const uint8_t *iv, const size_t iv_len)
{
	int have_key = key && key_len;
	int have_iv = iv && iv_len;
	if (!have_key && !have_iv) {
		return NULL;
	}
	struct jalp_transform_encryption_info *info =
		(struct jalp_transform_encryption_info *) jal_calloc(1, sizeof(*info));
	if (have_key) {
		info->key = (uint8_t*) jal_malloc(key_len);
		memcpy(info->key, key, key_len);
	}
	if (have_iv) {
		info->iv = (uint8_t*) jal_malloc(iv_len);
		memcpy(info->iv, iv, iv_len);
	}
	return info;
}

void jalp_transform_encryption_info_destroy(struct jalp_transform_encryption_info **enc_info)
{
	if (!enc_info || !*enc_info) {
		return;
	}
	free((*enc_info)->key);
	free((*enc_info)->iv);
	free(*enc_info);
	*enc_info = NULL;
}
void jalp_transform_destroy_one(struct jalp_transform *transform)
{
	switch (transform->type) {
	case JALP_TRANSFORM_AES128:
		// fall through 
	case JALP_TRANSFORM_AES192:
		// fall through 
	case JALP_TRANSFORM_AES256:
		// fall through 
	case JALP_TRANSFORM_XOR:
		jalp_transform_encryption_info_destroy(&transform->enc_info);
		break;
	case JALP_TRANSFORM_OTHER:
		jalp_transform_other_info_destroy(&transform->other_info);
		break;
	case JALP_TRANSFORM_DEFLATE:
		// no sub elements for deflate, fall through
	default:
			break;
	}
	free(transform);
}

void jalp_transform_destroy(struct jalp_transform **transform)
{
	if (!transform || !(*transform)) {
		return;
	}

	struct jalp_transform *cur = *transform;
	while(cur) {
		struct jalp_transform *next = cur->next;
		jalp_transform_destroy_one(cur);
		cur = next;
	}

	*transform = NULL;
}

struct jalp_transform *jalp_transform_append_deflate(struct jalp_transform *prev)
{
	struct jalp_transform *transform = (struct jalp_transform *)jal_malloc(sizeof(*transform));
	transform->type = JALP_TRANSFORM_DEFLATE;
	transform->enc_info = NULL;
	jalp_transform_append_internal(prev, transform);
	return transform;
}

struct jalp_transform *jalp_transform_append_xor(struct jalp_transform *prev,
		const uint32_t key)
{
	if (!key) {
		return NULL;
	}
	uint32_t net_order_key = htonl(key);
	struct jalp_transform *transform = (struct jalp_transform*) jal_malloc(sizeof(*transform));
	transform->type = JALP_TRANSFORM_XOR;
	transform->enc_info = jalp_transform_encryption_info_create((void*) &net_order_key, sizeof(net_order_key), NULL, 0);
	jalp_transform_append_internal(prev, transform);
	return transform;
}

struct jalp_transform *jalp_transform_append_aes(struct jalp_transform *prev,
		const enum jalp_aes_key_size key_size, const uint8_t *key, const uint8_t *iv)
{
	size_t key_length;
	enum jalp_transform_type type;
	switch (key_size) {
	case JALP_AES128:
		type = JALP_TRANSFORM_AES128;
		key_length = JALP_TRANSFORM_AES128_KEYSIZE;
		break;
	case JALP_AES192:
		type = JALP_TRANSFORM_AES192;
		key_length = JALP_TRANSFORM_AES192_KEYSIZE;
		break;
	case JALP_AES256:
		type = JALP_TRANSFORM_AES256;
		key_length = JALP_TRANSFORM_AES256_KEYSIZE;
		break;
	default:
		return NULL;
	}
	struct jalp_transform *transform = (struct jalp_transform*) jal_malloc(sizeof(*transform));
	transform->type = type;
	transform->enc_info = jalp_transform_encryption_info_create(key, key_length, iv, JALP_TRANSFORM_AES_IVSIZE);
	jalp_transform_append_internal(prev, transform);
	return transform;
}
