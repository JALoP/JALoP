/**
 * @file test_jalp_transform.c This file contains tests for jalp_transform functions.
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
#include <stdio.h>
#include <limits.h>
#include <test-dept.h>
#include <jalop/jalp_journal_metadata.h>
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

void test_jalp_transform_append_other_return_new_transform_when_prev_is_null()
{
	struct jalp_transform *transform;
	transform = jalp_transform_append_other(NULL, "uri", "snippet");

	assert_not_equals(NULL, transform);
	assert_equals(JALP_TRANSFORM_OTHER, transform->type);
	assert_not_equals(NULL, transform->other_info);
	assert_string_equals("uri", transform->other_info->uri);
	assert_string_equals("snippet", transform->other_info->xml);
	assert_equals((struct jalp_transform *)NULL, transform->next);

	jalp_transform_destroy(&transform);
}

void test_jalp_transform_append_other_returns_null_when_uri_is_null()
{
	assert_equals((struct jalp_transform *)NULL, jalp_transform_append_other(NULL, NULL, "value"));
}

void test_jalp_transform_append_other_return_new_transform_when_xml_snippet_is_null()
{
	struct jalp_transform *transform;
	transform = jalp_transform_append_other(NULL, "uri", NULL);
	assert_not_equals(NULL, transform);
	assert_equals(JALP_TRANSFORM_OTHER, transform->type);

	jalp_transform_destroy(&transform);
}

void test_jalp_transform_append_other_return_list_when_prev_is_not_null()
{
	struct jalp_transform *prev_transform;
	prev_transform = jalp_transform_append_other(NULL, "uri", "snippet");
	struct jalp_transform *transform;
	transform = jalp_transform_append_other(prev_transform, "uri2", "snippet2");
	assert_not_equals(NULL, prev_transform);
	assert_not_equals(NULL, transform);
	assert_equals(JALP_TRANSFORM_OTHER, prev_transform->type);
	assert_equals(JALP_TRANSFORM_OTHER, transform->type);
	assert_string_equals("uri2", transform->other_info->uri);
	assert_string_equals("snippet2", transform->other_info->xml);
	assert_string_equals("uri2", prev_transform->next->other_info->uri);
	assert_string_equals("snippet2", prev_transform->next->other_info->xml);
	assert_equals((struct jalp_transform *)NULL, transform->next);

	jalp_transform_destroy(&prev_transform);
}

void test_jalp_transform_append_other_return_list_with_transform_inserted_center()
{
	struct jalp_transform *frst_transform;
	struct jalp_transform *scnd_transform;
	struct jalp_transform *new_scnd;

	frst_transform = jalp_transform_append_other(NULL, "uri", "snippet");
	scnd_transform = jalp_transform_append_other(frst_transform, "uri2", "snippet2");
	new_scnd = jalp_transform_append_other(frst_transform, "uri1", "snippet1");

	assert_not_equals(NULL, frst_transform);
	assert_equals(JALP_TRANSFORM_OTHER, frst_transform->type);
	assert_not_equals(NULL, frst_transform->other_info);
	assert_not_equals(NULL, scnd_transform);
	assert_equals(JALP_TRANSFORM_OTHER, scnd_transform->type);
	assert_not_equals(NULL, scnd_transform->other_info);
	assert_not_equals(NULL, new_scnd);
	assert_equals(JALP_TRANSFORM_OTHER, new_scnd->type);
	assert_not_equals(NULL, new_scnd->other_info);
	assert_string_equals("uri", frst_transform->other_info->uri);
	assert_string_equals("snippet", frst_transform->other_info->xml);
	assert_string_equals("uri1", new_scnd->other_info->uri);
	assert_string_equals("snippet1", new_scnd->other_info->xml);
	assert_string_equals("uri2", scnd_transform->other_info->uri);
	assert_string_equals("snippet2", scnd_transform->other_info->xml);
	assert_string_equals("uri1", frst_transform->next->other_info->uri);
	assert_string_equals("snippet1", frst_transform->next->other_info->xml);
	assert_equals(frst_transform->next, new_scnd);
	assert_string_equals("uri2", new_scnd->next->other_info->uri);
	assert_string_equals("snippet2", new_scnd->next->other_info->xml);
	assert_equals(new_scnd->next, scnd_transform);

	jalp_transform_destroy(&frst_transform);
}

void test_jalp_transform_destroy_transform_list_is_null()
{
	struct jalp_transform *null_transform = NULL;
	jalp_transform_destroy(&null_transform);
}

void test_jalp_transform_destroy_destroys_single_node_transform_list()
{
	struct jalp_transform *transform;
	transform = jalp_transform_append_other(NULL, "uri", "snippet");

	jalp_transform_destroy(&transform);
	assert_equals((struct jalp_transform *)NULL, transform);
}

void test_jalp_transform_destroy_destroys_multinode_transform_list()
{
	struct jalp_transform *frst_transform;
	struct jalp_transform *scnd_transform;
	struct jalp_transform *thrd_transform;
	frst_transform = jalp_transform_append_other(NULL, "uri", "snippet");
	scnd_transform = jalp_transform_append_other(frst_transform, "uri2", "snippet2");
	thrd_transform = jalp_transform_append_other(scnd_transform, "uri3", "snippet3");

	jalp_transform_destroy(&frst_transform);
	assert_equals((struct jalp_transform *)NULL, frst_transform);
}

void test_jalp_transform_append_deflate_appends_deflate()
{
	struct jalp_transform *deflate_transform;
	struct jalp_transform *deflate_transform2;
	deflate_transform = jalp_transform_append_deflate(NULL);

	assert_not_equals(NULL, deflate_transform);
	assert_equals(JALP_TRANSFORM_DEFLATE, deflate_transform->type);
	assert_equals((void*)NULL, deflate_transform->enc_info);

	deflate_transform2 = jalp_transform_append_deflate(deflate_transform);
	assert_equals(deflate_transform->next, deflate_transform2);
	assert_not_equals(NULL, deflate_transform2);
	assert_equals(JALP_TRANSFORM_DEFLATE, deflate_transform2->type);
	assert_equals((struct jalp_transform *)NULL, deflate_transform2->next);
	assert_equals((void*)NULL, deflate_transform2->enc_info);

	jalp_transform_destroy(&deflate_transform);
}

void test_jalp_transform_append_aes_inval_key_size()
{
	struct jalp_transform *invalid_aes_transform;
	invalid_aes_transform = jalp_transform_append_aes(NULL, -50, NULL, NULL);
	assert_equals((struct jalp_transform *)NULL, invalid_aes_transform);
}

void test_jalp_transform_append_aes_null_key_and_iv()
{
	struct jalp_transform *valid_aes_transform;
	valid_aes_transform = jalp_transform_append_aes(NULL, JALP_AES128, NULL, NULL);
	assert_not_equals(NULL, valid_aes_transform);
	assert_equals((void*)NULL, valid_aes_transform->enc_info);
	assert_equals(JALP_TRANSFORM_AES128, valid_aes_transform->type);
	jalp_transform_destroy(&valid_aes_transform);
}

void test_jalp_transform_append_aes_appends_to_null()
{
	uint8_t *key;
	uint8_t *iv;
	unsigned int i[32];
	unsigned int j[32];
	key = (uint8_t *)i;
	iv = (uint8_t *)j;
	struct jalp_transform *aes_transform;
	aes_transform = jalp_transform_append_aes(NULL, JALP_AES128, key, iv);
	assert_not_equals(NULL, aes_transform);
	assert_equals(JALP_TRANSFORM_AES128, aes_transform->type);
	jalp_transform_destroy(&aes_transform);
}

void test_jalp_transform_append_aes_appends_to_prev()
{
	struct jalp_transform *first = jalp_transform_append_other(NULL, "uri", "xml");
	uint8_t *key;
	uint8_t *iv;
	unsigned int i[32];
	unsigned int j[32];
	key = (uint8_t *)i;
	iv = (uint8_t *)j;
	struct jalp_transform *aes_transform;
	aes_transform = jalp_transform_append_aes(first, JALP_AES128, key, iv);
	assert_not_equals(NULL, aes_transform);
	assert_equals(first->next, aes_transform);
	assert_equals(JALP_TRANSFORM_OTHER, first->type);
	assert_equals(JALP_TRANSFORM_AES128, first->next->type);
	jalp_transform_destroy(&first);
}

void test_jalp_transform_append_aes_correctly_copies_data()
{
	int i;
	struct jalp_transform *aes_transform;
	uint8_t key[16];
	uint8_t iv[16];

	/* fill key and iv with arbitrary data */
	for(i = 0; i < 16; i++) {
		key[i] = (uint8_t)i;
		iv[i] = (uint8_t)(16 - i);
	}

	aes_transform = jalp_transform_append_aes(NULL, JALP_AES128, key, iv);
	assert_not_equals(NULL, aes_transform);
	assert_equals(JALP_TRANSFORM_AES128, aes_transform->type);

	// 128 bit key/iv == 16 bytes
	assert_equals(0, memcmp(key, aes_transform->enc_info->key, 16));
	assert_equals(0, memcmp(iv, aes_transform->enc_info->iv, 16));

	jalp_transform_destroy(&aes_transform);
}

void test_jalp_transform_append_aes_works_with_different_keysizes()
{
	int i;
	struct jalp_transform *aes_transform_128;
	struct jalp_transform *aes_transform_192;
	struct jalp_transform *aes_transform_256;
	uint8_t key[256];

	/* fill key and iv with arbitrary data */
	for(i = 0; i < 32; i++) {
		key[i] = (uint8_t)i;
	}

	aes_transform_128 = jalp_transform_append_aes(NULL, JALP_AES128, key, NULL);
	aes_transform_192 = jalp_transform_append_aes(NULL, JALP_AES192, key, NULL);
	aes_transform_256 = jalp_transform_append_aes(NULL, JALP_AES256, key, NULL);

	assert_not_equals(NULL, aes_transform_128);
	assert_not_equals(NULL, aes_transform_192);
	assert_not_equals(NULL, aes_transform_256);

	assert_equals(JALP_TRANSFORM_AES128, aes_transform_128->type);
	assert_equals(JALP_TRANSFORM_AES192, aes_transform_192->type);
	assert_equals(JALP_TRANSFORM_AES256, aes_transform_256->type);

	// 128 bits == 16 bytes
	assert_equals(0, memcmp(key, aes_transform_128->enc_info->key, 16));
	// 192 bits == 24 bytes
	assert_equals(0, memcmp(key, aes_transform_192->enc_info->key, 24));
	// 256 bits == 32 bytes
	assert_equals(0, memcmp(key, aes_transform_256->enc_info->key, 32));

	assert_equals((void*)NULL, aes_transform_128->enc_info->iv);
	assert_equals((void*)NULL, aes_transform_192->enc_info->iv);
	assert_equals((void*)NULL, aes_transform_256->enc_info->iv);

	jalp_transform_destroy(&aes_transform_128);
	jalp_transform_destroy(&aes_transform_192);
	jalp_transform_destroy(&aes_transform_256);

}

void test_jalp_transform_append_xor_returns_new_transform_when_null_prev_transform()
{
	struct jalp_transform *new_transform = NULL;
	new_transform = jalp_transform_append_xor(NULL, 256);
	assert_not_equals(NULL, new_transform);
	assert_equals(JALP_TRANSFORM_XOR, new_transform->type);
	jalp_transform_destroy(&new_transform);
}

void test_jalp_transform_append_xor_returns_null_when_key_is_zero()
{
	struct jalp_transform *new_transform = NULL;
	new_transform = jalp_transform_append_xor(NULL, 0);
	assert_equals((void*)NULL, new_transform);
}

void test_jalp_transform_append_xor_returns_list_when_prev_not_null()
{
	struct jalp_transform *transform = NULL;
	struct jalp_transform *new_transform = NULL;
	uint8_t key_buf[] = {0xAA, 0xBB, 0x11, 0x22};

	transform = jalp_transform_append_other(NULL, "http://www.fake.uri/", "<fake>fake</fake>");
	assert_not_equals(NULL, transform);
	assert_equals(JALP_TRANSFORM_OTHER, transform->type);
	assert_not_equals(NULL, transform->other_info);
	assert_string_equals("<fake>fake</fake>", transform->other_info->xml);
	assert_string_equals("http://www.fake.uri/", transform->other_info->uri);

	new_transform = jalp_transform_append_xor(transform, 0xAABB1122);
	assert_not_equals(NULL, transform->next);
	assert_not_equals(NULL, new_transform);
	assert_not_equals(NULL, new_transform->enc_info);
	assert_not_equals(NULL, new_transform->enc_info->key);
	assert_equals((void*)NULL, new_transform->enc_info->iv);
	assert_equals(transform->next, new_transform);
	assert_equals(JALP_TRANSFORM_XOR, new_transform->type);
	assert_equals(0, memcmp(key_buf, new_transform->enc_info->key, sizeof(key_buf)));
	jalp_transform_destroy(&transform);
}


void test_jalp_transform_encryption_info_create_returns_null_with_bad_input()
{
	uint8_t fake[] = { 1, 2, 3, 4 };
	struct jalp_transform_encryption_info *new_info = NULL;
	new_info = jalp_transform_encryption_info_create(NULL, 0, NULL, 0);
	assert_equals((void*) NULL, new_info);
	new_info = jalp_transform_encryption_info_create(NULL, 1, NULL, 0);
	assert_equals((void*) NULL, new_info);
	new_info = jalp_transform_encryption_info_create(NULL, 0, NULL, 1);
	assert_equals((void*) NULL, new_info);
	new_info = jalp_transform_encryption_info_create(NULL, 1, NULL, 1);
	assert_equals((void*) NULL, new_info);

	new_info = jalp_transform_encryption_info_create(fake, 0, NULL, 0);
	assert_equals((void*) NULL, new_info);
	new_info = jalp_transform_encryption_info_create(NULL, 0, fake, 0);
	assert_equals((void*) NULL, new_info);
	new_info = jalp_transform_encryption_info_create(fake, 0, fake, 0);
	assert_equals((void*) NULL, new_info);
}

void test_jalp_transform_encryption_info_create_works_with_only_key()
{
	uint8_t fake[] = { 1, 2, 3, 4 };
	struct jalp_transform_encryption_info *new_info = NULL;
	new_info = jalp_transform_encryption_info_create(fake, sizeof(fake), NULL, 0);
	assert_not_equals(NULL, new_info);
	assert_not_equals((void*)NULL, new_info->key);
	assert_equals((void*)NULL, new_info->iv);
	assert_equals(0, memcmp(fake, new_info->key, sizeof(fake)));
	jalp_transform_encryption_info_destroy(&new_info);

	new_info = jalp_transform_encryption_info_create(fake, sizeof(fake), NULL, 0);
	assert_not_equals(NULL, new_info);
	assert_not_equals((void*)NULL, new_info->key);
	assert_equals((void*)NULL, new_info->iv);
	assert_equals(0, memcmp(fake, new_info->key, sizeof(fake)));
	jalp_transform_encryption_info_destroy(&new_info);

	new_info = jalp_transform_encryption_info_create(fake, sizeof(fake), NULL, 1);
	assert_not_equals(NULL, new_info);
	assert_not_equals((void*)NULL, new_info->key);
	assert_equals((void*)NULL, new_info->iv);
	assert_equals(0, memcmp(fake, new_info->key, sizeof(fake)));
	jalp_transform_encryption_info_destroy(&new_info);

	new_info = jalp_transform_encryption_info_create(fake, sizeof(fake), fake, 0);
	assert_not_equals(NULL, new_info);
	assert_not_equals((void*)NULL, new_info->key);
	assert_equals((void*)NULL, new_info->iv);
	assert_equals(0, memcmp(fake, new_info->key, sizeof(fake)));
	jalp_transform_encryption_info_destroy(&new_info);

}
void test_jalp_transform_encryption_info_create_works_with_only_iv()
{
	uint8_t fake[] = { 1, 2, 3, 4 };
	struct jalp_transform_encryption_info *new_info = NULL;
	new_info = jalp_transform_encryption_info_create(NULL, 0, fake, sizeof(fake));
	assert_not_equals(NULL, new_info);
	assert_equals((void*)NULL, new_info->key);
	assert_not_equals((void*)NULL, new_info->iv);
	assert_equals(0, memcmp(fake, new_info->iv, sizeof(fake)));
	jalp_transform_encryption_info_destroy(&new_info);

	new_info = jalp_transform_encryption_info_create(NULL, 0, fake, sizeof(fake));
	assert_not_equals(NULL, new_info);
	assert_equals((void*)NULL, new_info->key);
	assert_not_equals((void*)NULL, new_info->iv);
	assert_equals(0, memcmp(fake, new_info->iv, sizeof(fake)));
	jalp_transform_encryption_info_destroy(&new_info);

	new_info = jalp_transform_encryption_info_create(NULL, 0, fake, sizeof(fake));
	assert_not_equals(NULL, new_info);
	assert_equals((void*)NULL, new_info->key);
	assert_not_equals((void*)NULL, new_info->iv);
	assert_equals(0, memcmp(fake, new_info->iv, sizeof(fake)));
	jalp_transform_encryption_info_destroy(&new_info);

	new_info = jalp_transform_encryption_info_create(NULL, 0, fake, sizeof(fake));
	assert_not_equals(NULL, new_info);
	assert_equals((void*)NULL, new_info->key);
	assert_not_equals((void*)NULL, new_info->iv);
	assert_equals(0, memcmp(fake, new_info->iv, sizeof(fake)));
	jalp_transform_encryption_info_destroy(&new_info);

}

