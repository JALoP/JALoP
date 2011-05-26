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


struct jalp_transform *jalp_transform_append(struct jalp_transform *prev,
		char *uri, char *xml_snippet)
{
	if (!uri) {
		return NULL;
	}

	struct jalp_transform *transform = NULL;
	transform = jal_malloc(sizeof(*transform));

	transform->uri = jal_strdup(uri);
	transform->xml = jal_strdup(xml_snippet);

	if (prev) {
		transform->next = prev->next;
		prev->next = transform;
	} else {
		transform->next = NULL;
	}

	return transform;
}

void jalp_transform_destroy_one(struct jalp_transform *transform)
{
	free(transform->uri);
	free(transform->xml);
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
	return jalp_transform_append(prev,
			"http://www.dod.mil/algorithms/compression#deflate", NULL);
}

struct jalp_transform *jalp_transform_append_xor(struct jalp_transform *prev,
		uint32_t key)
{
	char char_key[sizeof(key)];
	char *b64_key = NULL;
	char *xml = NULL;
	struct jalp_transform * transform = NULL;

	// convert key to network byte order
	key = htonl(key);
	memcpy(char_key, &key, sizeof(key));
	b64_key = jalp_base64_enc((unsigned char *)char_key, sizeof(key));
	if (!b64_key) {
		return NULL;
	}

	jal_asprintf(&xml, "<Key32>%s</Key32>", b64_key);
	transform = jalp_transform_append(prev,
			"http://www.dod.mil/algorithms/encryption#xor32-ecb", xml);

	free(b64_key);
	free(xml);
	return transform;
}

struct jalp_transform *jalp_transform_append_aes(struct jalp_transform *prev,
		enum jalp_aes_key_size key_size, uint8_t *key, uint8_t *iv)
{
	unsigned char *char_key = NULL;
	unsigned char *char_iv = NULL;
	char *b64_key = NULL;
	char *b64_iv = NULL;
	char *xml = NULL;
	char *algorithm = NULL;
	int key_length;
	struct jalp_transform * transform = NULL;

	switch (key_size) {
	case JALP_AES128:
		key_length = 128;
		break;
	case JALP_AES192:
		key_length = 192;
		break;
	case JALP_AES256:
		key_length = 256;
		break;
	default:
		goto aes_out;
	}

	if (key) {
		char_key = jal_malloc(key_length);
		memcpy(char_key, key, key_length);
		b64_key = jalp_base64_enc(char_key, key_length);
		if (!b64_key) {
			goto aes_out;
		}
	}

	if (iv) {
		char_iv = jal_malloc(128); // IVs are always 128 bytes
		memcpy(char_iv, iv, 128);
		b64_iv = jalp_base64_enc(char_iv, 128);
		if (!b64_iv) {
			goto aes_out;
		}
	}

	if (key && iv) {
		jal_asprintf(&xml, "<Key%d>%s</Key%d><IV128>%s</IV128>",
				key_length, b64_key, key_length, b64_iv);
	} else if (key) {
		jal_asprintf(&xml, "<Key%d>%s</Key%d>", key_length, b64_key, key_length);
	} else if (iv) {
		jal_asprintf(&xml, "<IV128>%s</IV128>", b64_iv);
	}

	jal_asprintf(&algorithm, "http://www.w3.org/2001/04/xmlenc#aes%d-cbc", key_length);
	transform = jalp_transform_append(prev, algorithm, xml);

aes_out:
	free(char_key);
	free(char_iv);
	free(b64_key);
	free(b64_iv);
	free(xml);
	free(algorithm);

	return transform;
}
