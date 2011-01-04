/**
 * @file test_jal_digest.c This file contains tests to for jal_digest functions.
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

#include <test-dept.h>
#include <openssl/sha.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include "jal_alloc.h"

#define HELLO_WORLD "Hello World"
#define HELLO_WORLD_SUM "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
#define JAL_SHA256_ALGORITHM_URI "http://www.w3.org/2001/04/xmlenc#sha256"

struct jal_digest_ctx *sha256_ctx;
SHA256_CTX *sha256;

int SHA256_Init_always_fails(__attribute__((unused)) SHA256_CTX *c)
{
	return 0;
}

int SHA256_Update_always_fails(__attribute__((unused)) SHA256_CTX *c,
				__attribute__((unused)) const void *data,
				__attribute__((unused)) size_t len)
{
	return 0;
}

int SHA256_Final_always_failes(__attribute__((unused)) const unsigned char *d,
				__attribute__((unused)) SHA256_CTX *c)
{
	return 0;
}

void setup()
{
	sha256_ctx = jal_sha256_ctx_create();
	sha256 = sha256_ctx->create();
}

void teardown()
{
	sha256_ctx->destroy(sha256);
	jal_digest_ctx_destroy(&sha256_ctx);
	assert_equals((void*)NULL, sha256_ctx);
	restore_function(SHA256_Init);
	restore_function(SHA256_Update);
	restore_function(SHA256_Final);
}

// Set of fake functions for a fake digest context.
void * fake_create(void)
{
	return NULL;
}
enum jal_status fake_init(__attribute__((unused)) void *instance)
{
	return JAL_OK;
}
enum jal_status fake_update(__attribute__((unused)) void *instance,
		__attribute__((unused)) const uint8_t *data,
		__attribute__((unused)) size_t len)
{
	return JAL_OK;
}
enum jal_status fake_final(__attribute__((unused)) void *instance,
		__attribute__((unused)) uint8_t *digest,
		__attribute__((unused)) size_t *len)
{
	return JAL_OK;
}
void fake_destroy(__attribute__((unused)) void *instance)
{
	// Do nothing.
}

void set_digest_context(struct jal_digest_ctx *digest_ctx)
{
	digest_ctx->len = 1;
	digest_ctx->algorithm_uri = jal_strdup("asdf");
	digest_ctx->create = fake_create;
	digest_ctx->init = fake_init;
	digest_ctx->update = fake_update;
	digest_ctx->final = fake_final;
	digest_ctx->destroy = fake_destroy;
}

void test_jal_digest_ctx_create_returns_struct_with_zeroed_fields()
{
	struct jal_digest_ctx *ptr = jal_digest_ctx_create();
	assert_not_equals(NULL, ptr);
	assert_equals(0, ptr->len);
	assert_equals((char*)NULL, ptr->algorithm_uri);
	assert_equals((void*)NULL, ptr->create);
	assert_equals((void*)NULL, ptr->init);
	assert_equals((void*)NULL, ptr->update);
	assert_equals((void*)NULL, ptr->final);
	assert_equals((void*)NULL, ptr->destroy);
	jal_digest_ctx_destroy(&ptr);
}

void test_jal_digest_ctx_destroy_does_not_crash_on_null()
{
	jal_digest_ctx_destroy(NULL);
	struct jal_digest_ctx *ptr = NULL;
	jal_digest_ctx_destroy(&ptr);
}

void test_jal_digest_destroy_frees_struct()
{
	// Run under valgrind to check for leaks.
	struct jal_digest_ctx *ptr = jal_digest_ctx_create();
	ptr->algorithm_uri = jal_strdup("asdf");
	assert_not_equals(NULL, ptr);
	jal_digest_ctx_destroy(&ptr);
	assert_equals((struct jal_digest_ctx *)NULL, ptr);
}

void test_jal_sha256_ctx_create_returns_full_struct()
{
	assert_not_equals(NULL, sha256_ctx);
	assert_string_equals(JAL_SHA256_ALGORITHM_URI, sha256_ctx->algorithm_uri);
	assert_equals(SHA256_DIGEST_LENGTH, sha256_ctx->len);
	assert_equals(32, SHA256_DIGEST_LENGTH);
	assert_not_equals(NULL, sha256_ctx->create);
	assert_not_equals(NULL, sha256_ctx->init);
	assert_not_equals(NULL, sha256_ctx->update);
	assert_not_equals(NULL, sha256_ctx->final);
	assert_not_equals(NULL, sha256_ctx->destroy);
}

void test_jal_sha256_create_returns_allocated_sha256()
{
	assert_not_equals(NULL, sha256);
}

void test_jal_sha256_init_returns_ok()
{
	enum jal_status ret = sha256_ctx->init(sha256);
	assert_equals(JAL_OK, ret);
}

void test_jal_sha256_init_handles_error()
{
	replace_function(SHA256_Init, SHA256_Init_always_fails);
	enum jal_status ret = sha256_ctx->init(sha256);
	assert_equals(JAL_E_INVAL, ret);
}

void test_jal_sha256_update_returns_ok()
{
	size_t len = strlen(HELLO_WORLD);
	enum jal_status ret = sha256_ctx->update(sha256, (uint8_t *)HELLO_WORLD, len);
	assert_equals(JAL_OK, ret);
}

void test_jal_sha256_update_handles_error()
{
	size_t len = strlen(HELLO_WORLD);
	replace_function(SHA256_Update, SHA256_Update_always_fails);
	enum jal_status ret = sha256_ctx->update(sha256, (uint8_t *)HELLO_WORLD, len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_jal_sha256_final_handles_error()
{
	size_t len = SHA256_DIGEST_LENGTH;
	replace_function(SHA256_Update, SHA256_Update_always_fails);
	enum jal_status ret = sha256_ctx->update(sha256, (uint8_t *)HELLO_WORLD, len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_jal_sha256_final_returns_invalid_when_len_lt_sha256_digest_length()
{
	size_t len = 0;
	uint8_t data[len];
	enum jal_status ret = sha256_ctx->final(sha256, data, &len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_jal_sha256_full()
{
	int i = 0;
	size_t len = SHA256_DIGEST_LENGTH;
	uint8_t data[len];
	char buf[65];
	sha256_ctx->init(sha256);
	sha256_ctx->update(sha256, (uint8_t *)HELLO_WORLD, strlen(HELLO_WORLD));
	sha256_ctx->final(sha256, data, &len);
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(buf + (i * 2), "%02x", data[i]);
	}
	buf[64] = 0;
	assert_string_equals(HELLO_WORLD_SUM, buf);
}

void test_jal_sha256_full_multiple_updates()
{
	int i = 0;
	size_t len = SHA256_DIGEST_LENGTH;
	uint8_t data[len];
	char buf[65];
	sha256_ctx->init(sha256);
	sha256_ctx->update(sha256, (uint8_t *)"Hel", 3);
	sha256_ctx->update(sha256, (uint8_t *)"lo ", 3);
	sha256_ctx->update(sha256, (uint8_t *)"Wor", 3);
	sha256_ctx->update(sha256, (uint8_t *)"ld", 2);
	sha256_ctx->final(sha256, data, &len);
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
		sprintf(buf  + (i * 2), "%02x", data[i]);
	}
	buf[64] = 0;
	assert_string_equals(HELLO_WORLD_SUM, buf);
}

void test_jal_digest_ctx_is_valid()
{
	struct jal_digest_ctx *ptr = jal_digest_ctx_create();
	assert_not_equals(NULL, ptr);
	set_digest_context(ptr);
	int ret_val = jal_digest_ctx_is_valid(ptr);
	assert_true(ret_val);
	jal_digest_ctx_destroy(&ptr);
}

void test_jal_digest_ctx_is_invalid()
{
	struct jal_digest_ctx *ptr = jal_digest_ctx_create();
	assert_not_equals(NULL, ptr);
	set_digest_context(ptr);
	ptr->len = 0;
	int ret_val = jal_digest_ctx_is_valid(ptr);
	assert_false(ret_val);
	free(ptr->algorithm_uri);
	set_digest_context(ptr);
	free(ptr->algorithm_uri);
	ptr->algorithm_uri = NULL;
	ret_val = jal_digest_ctx_is_valid(ptr);
	assert_false(ret_val);
	set_digest_context(ptr);
	ptr->create = NULL;
	ret_val = jal_digest_ctx_is_valid(ptr);
	assert_false(ret_val);
	free(ptr->algorithm_uri);
	set_digest_context(ptr);
	ptr->init = NULL;
	ret_val = jal_digest_ctx_is_valid(ptr);
	assert_false(ret_val);
	free(ptr->algorithm_uri);
	set_digest_context(ptr);
	ptr->update = NULL;
	ret_val = jal_digest_ctx_is_valid(ptr);
	assert_false(ret_val);
	free(ptr->algorithm_uri);
	set_digest_context(ptr);
	ptr->final = NULL;
	ret_val = jal_digest_ctx_is_valid(ptr);
	assert_false(ret_val);
	free(ptr->algorithm_uri);
	set_digest_context(ptr);
	ptr->destroy = NULL;
	ret_val = jal_digest_ctx_is_valid(ptr);
	assert_false(ret_val);
	jal_digest_ctx_destroy(&ptr);
}
