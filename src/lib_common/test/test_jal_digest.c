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

#include <unistd.h>
#include <test-dept.h>
#include <openssl/sha.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include "jal_alloc.h"

#define HELLO_WORLD "Hello World"
#define HELLO_WORLD_SHA256_SUM "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
#define HELLO_WORLD_SHA384_SUM "99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f"
#define HELLO_WORLD_SHA512_SUM "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b"
#define DIGEST_LEN 2
#define DATA_LEN 4
#define FAKEURI "fakeuri"

static const uint8_t gs_digest_input[DATA_LEN] = {0x0f, 0x1d, 0x2c, 0x3b};
static const uint8_t gs_digest_value[DIGEST_LEN] = {0x4a, 0x59};
static struct jal_digest_ctx *gs_ctx;

static uint8_t *gs_fake_file_buffer;
static size_t gs_fake_file_size;
static size_t gs_fake_file_offset;
static const int gs_fake_file_fd = 0x0eadbeef;
static uint8_t *dgst_ptr;
static size_t gs_update_offset;

static int abort_called;;
static int create_called;
static int init_called;
static int update_called;
static int final_called;
static int destroy_called;

static uint8_t *dgst_ptr;

static int lseek_called;

static jmp_buf env;
static size_t gs_expected_input_len;

static enum jal_digest_algorithm *digest_list;

__attribute__((noreturn)) static void abort_handler(__attribute__((unused))int sig)
{
	abort_called = 1;
	signal(SIGABRT, abort_handler);
	longjmp(env, 1);
}
static void *create_fails()
{
	create_called += 1;
	return NULL;
}
static enum jal_status  init_fails(__attribute__((unused)) void *ctx)
{
	init_called += 1;
	return JAL_E_INVAL;
}
static enum jal_status update_fails(__attribute__((unused)) void *ctx,
		__attribute__((unused)) const uint8_t *data,
		__attribute__((unused)) size_t len)
{
	update_called += 1;
	return JAL_E_INVAL;
}

static enum jal_status final_fails(__attribute__((unused)) void *ctx,
		__attribute__((unused)) uint8_t *buffer,
		__attribute__((unused)) size_t *len)
{
	final_called += 1;
	return JAL_E_INVAL;
}
static void *fake_create()
{
	create_called += 1;
	return (void*)0xaabbccdd;
}
static enum jal_status fake_init(void *ctx)
{
	init_called += 1;
	if (ctx != (void*)0xaabbccdd) {
		// jal_digest_buffer() is passing bad values into the
		// callback, so just abort.
		abort();
	}
	return JAL_OK;
}

static enum jal_status fake_update(__attribute__((unused)) void *ctx,
		const uint8_t *data, size_t len)
{
	update_called += 1;
	// This is not strictly an error, since it should be possible to call
	// 'update' as many times as needed. If the test fails here, it
	// probably means the implementation changed to send smaller buffers,
	// rather than all data at once. Rather then return an error, use the
	// assert here to check for this, and if it ever happens, this function
	// (and the ctx) will need to get updated to track state information.
	if (len != gs_expected_input_len) {
		abort();
	}
	if (0 != memcmp(data, gs_digest_input, len)) {
		// not strictly a failure, see the comment right above.
		abort();
	}
	return JAL_OK;
}

static enum jal_status fake_update_for_fd(void *ctx, const uint8_t *data, __attribute__((unused)) size_t len)
{
	if (ctx != (void*)0xaabbccdd || data == NULL) {
		// jal_digest_buffer() is passing bad values into the
		// callback, so just abort.
		abort();
	}
	if (gs_update_offset  + len > gs_fake_file_size) {
		// something went wrong, update called with more bytes than
		// were in the file.
		abort();
	}
	if (0 != memcmp(gs_fake_file_buffer + gs_update_offset, data, len)) {
		// something seems is out of sync?
		abort();
	}
	update_called += 1;
	gs_update_offset += len;;
	return JAL_OK;
}

static enum jal_status fake_final(void *ctx, uint8_t *digest_out, size_t *len)
{
	final_called += 1;
	if (ctx != (void*)0xaabbccdd || digest_out == NULL || len == NULL || *len != DIGEST_LEN) {
		// jal_digest_buffer() is passing bad values into the
		// callback, so just abort.
		abort();
	}
	memcpy(digest_out, gs_digest_value, *len);
	return JAL_OK;
}

static enum jal_status fake_final_for_fd(void *ctx, uint8_t *digest_out, size_t *len)
{
	final_called += 1;
	if (ctx != (void*)0xaabbccdd || digest_out == NULL || len == NULL || *len != DIGEST_LEN) {
		// jal_digest_buffer() is passing bad values into the
		// callback, so just abort.
		abort();
	}
	if (gs_update_offset != gs_fake_file_size) {
		// didn't digest the full contents of the file?
		abort();
	}
	memcpy(digest_out, gs_digest_value, *len);
	return JAL_OK;
}

static void fake_destroy(void *ctx)
{
	destroy_called += 1;
	if (ctx != (void*)0xaabbccdd) {
		// jal_digest_buffer() is passing bad values into the
		// callback, so just abort.
		abort();
	}
}

static off_t lseek_fails_as_pipe(__attribute__((unused)) int fd, __attribute__((unused)) off_t offset, __attribute__((unused)) int whence)
{
	lseek_called += 1;
	errno = EPIPE;
	return -1;
}

static off_t fake_lseek(int fd, off_t offset, int whence)
{
	lseek_called += 1;
	if (fd != gs_fake_file_fd) {
		errno = EBADF;
		return -1;
	}
	switch (whence) {
	case SEEK_SET:
		if (offset < 0 || (size_t) offset > gs_fake_file_size) {
			errno = EINVAL;
			return -1;
		}
		gs_fake_file_offset = offset;
		return offset;
		break;
	}
	// not bothering to handle any of the other 'whence' calls.
	abort();
	return -1;
}

static ssize_t fake_read(int fd, void *buf, size_t count)
{
	if (gs_fake_file_offset > gs_fake_file_size) {
		// something is wrong fail NOW!
		abort();
	}
	if (gs_fake_file_offset == gs_fake_file_size) {
		return 0;
	}
	if (fd != gs_fake_file_fd) {
		// something is wrong fail NOW!
		abort();
	}
	size_t bytes_left = gs_fake_file_size - gs_fake_file_offset;
	size_t to_copy = count < bytes_left ? count : bytes_left;
	memcpy(buf, gs_fake_file_buffer + gs_fake_file_offset, to_copy);
	gs_fake_file_offset += to_copy;
	return to_copy;
}

static ssize_t read_always_fails(int fd,
		__attribute__((unused)) void *buf,
		__attribute__((unused)) size_t count)
{
	ssize_t bytes_left = gs_fake_file_size - gs_fake_file_offset;
	if (fd != gs_fake_file_fd || bytes_left < 0) {
		// something is wrong fail NOW!
		abort();
	}
	errno = EINVAL;
	return -1;
}

static void use_ctx_for_fd()
{
	gs_ctx->update = fake_update_for_fd;
	gs_ctx->final = fake_final_for_fd;
}

struct jal_digest_ctx *digest_ctx_list[JAL_DIGEST_ALGORITHM_COUNT];
void *digest_inst_list[JAL_DIGEST_ALGORITHM_COUNT];

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

int SHA256_Final_always_fails(__attribute__((unused)) unsigned char *d,
				__attribute__((unused)) SHA256_CTX *c)
{
	return 0;
}

int SHA384_Init_always_fails(__attribute__((unused)) SHA512_CTX *c)
{
	return 0;
}

int SHA384_Update_always_fails(__attribute__((unused)) SHA512_CTX *c,
				__attribute__((unused)) const void *data,
				__attribute__((unused)) size_t len)
{
	return 0;
}

int SHA384_Final_always_fails(__attribute__((unused)) unsigned char *d,
				__attribute__((unused)) SHA512_CTX *c)
{
	return 0;
}

int SHA512_Init_always_fails(__attribute__((unused)) SHA512_CTX *c)
{
	return 0;
}

int SHA512_Update_always_fails(__attribute__((unused)) SHA512_CTX *c,
				__attribute__((unused)) const void *data,
				__attribute__((unused)) size_t len)
{
	return 0;
}

int SHA512_Final_always_fails(__attribute__((unused)) unsigned char *d,
				__attribute__((unused)) SHA512_CTX *c)
{
	return 0;
}

static const char *get_digest_algorithm(int algorithm)
{
	switch((enum jal_digest_algorithm) algorithm)
	{
		case JAL_DIGEST_ALGORITHM_SHA384:
			return JAL_SHA384_ALGORITHM_URI;
		case JAL_DIGEST_ALGORITHM_SHA512:
			return JAL_SHA512_ALGORITHM_URI;
		case JAL_DIGEST_ALGORITHM_SHA256:
		default:
			return JAL_SHA256_ALGORITHM_URI;
	}
}

static int get_digest_length(int algorithm)
{
	switch((enum jal_digest_algorithm) algorithm)
	{
		case JAL_DIGEST_ALGORITHM_SHA384:
			return SHA384_DIGEST_LENGTH;
		case JAL_DIGEST_ALGORITHM_SHA512:
			return SHA512_DIGEST_LENGTH;
		case JAL_DIGEST_ALGORITHM_SHA256:
		default:
			return SHA256_DIGEST_LENGTH;
	}
}

static char *get_digest_sum(int algorithm)
{
	switch((enum jal_digest_algorithm) algorithm)
	{
		case JAL_DIGEST_ALGORITHM_SHA384:
			return HELLO_WORLD_SHA384_SUM;
		case JAL_DIGEST_ALGORITHM_SHA512:
			return HELLO_WORLD_SHA512_SUM;
		case JAL_DIGEST_ALGORITHM_SHA256:
		default:
			return HELLO_WORLD_SHA256_SUM;
	}
}

static void replace_init_function(int algorithm)
{
	switch((enum jal_digest_algorithm) algorithm)
	{
		case JAL_DIGEST_ALGORITHM_SHA384:
			replace_function(SHA384_Init, SHA384_Init_always_fails);
		case JAL_DIGEST_ALGORITHM_SHA512:
			replace_function(SHA512_Init, SHA512_Init_always_fails);
		case JAL_DIGEST_ALGORITHM_SHA256:
		default:
			replace_function(SHA256_Init, SHA256_Init_always_fails);
	}
}

static void replace_update_function(int algorithm)
{
	switch((enum jal_digest_algorithm) algorithm)
	{
		case JAL_DIGEST_ALGORITHM_SHA384:
			replace_function(SHA384_Update, SHA384_Update_always_fails);
		case JAL_DIGEST_ALGORITHM_SHA512:
			replace_function(SHA512_Update, SHA512_Update_always_fails);
		case JAL_DIGEST_ALGORITHM_SHA256:
		default:
			replace_function(SHA256_Update, SHA256_Update_always_fails);
	}
}

static void replace_final_function(int algorithm)
{
	switch((enum jal_digest_algorithm) algorithm)
	{
		case JAL_DIGEST_ALGORITHM_SHA384:
			replace_function(SHA384_Final, SHA384_Final_always_fails);
		case JAL_DIGEST_ALGORITHM_SHA512:
			replace_function(SHA512_Final, SHA512_Final_always_fails);
		case JAL_DIGEST_ALGORITHM_SHA256:
		default:
			replace_function(SHA256_Final, SHA256_Final_always_fails);
	}
}

void setup()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		digest_ctx_list[i] = jal_digest_ctx_create((enum jal_digest_algorithm) i);
		digest_inst_list[i] = digest_ctx_list[i]->create();
	}

	abort_called = 0;
	create_called = 0;
	init_called = 0;
	update_called = 0;
	final_called = 0;
	destroy_called = 0;

	gs_expected_input_len = DATA_LEN;
	lseek_called = 0;
	gs_update_offset = 0;

	dgst_ptr = NULL;

	gs_ctx = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);
	gs_ctx->algorithm_uri = strdup(FAKEURI);
	gs_ctx->len = DIGEST_LEN;
	gs_ctx->create = fake_create;
	gs_ctx->init = fake_init;
	gs_ctx->update = fake_update;
	gs_ctx->final = fake_final;
	gs_ctx->destroy = fake_destroy;

	gs_fake_file_size = 4096 * 4;
	gs_fake_file_buffer = malloc(gs_fake_file_size);
	gs_fake_file_offset = 0;
	size_t cnt;
	for (cnt = 0; cnt < gs_fake_file_size; cnt++) {
		gs_fake_file_buffer[cnt] = cnt;
	}


	replace_function(read, fake_read);
	replace_function(lseek, fake_lseek);

	digest_list = (enum jal_digest_algorithm *) jal_malloc(sizeof(enum jal_digest_algorithm));
}

void teardown()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		digest_ctx_list[i]->destroy(digest_inst_list[i]);
		jal_digest_ctx_destroy(&digest_ctx_list[i]);
		assert_equals((void*)NULL, digest_ctx_list[i]);
	}

	restore_function(SHA256_Init);
	restore_function(SHA256_Update);
	restore_function(SHA256_Final);

	restore_function(SHA384_Init);
	restore_function(SHA384_Update);
	restore_function(SHA384_Final);

	restore_function(SHA512_Init);
	restore_function(SHA512_Update);
	restore_function(SHA512_Final);

	jal_digest_ctx_destroy(&gs_ctx);
	free(dgst_ptr);
	restore_function(read);
	restore_function(lseek);
	free(gs_fake_file_buffer);
	free(digest_list);
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

void test_jal_digest_ctx_destroy_does_not_crash_on_null()
{
	jal_digest_ctx_destroy(NULL);
	struct jal_digest_ctx *ptr = NULL;
	jal_digest_ctx_destroy(&ptr);
}

void test_jal_digest_destroy_frees_struct()
{
	// Run under valgrind to check for leaks.
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		struct jal_digest_ctx *ptr = jal_digest_ctx_create((enum jal_digest_algorithm) i);
		ptr->algorithm_uri = jal_strdup("asdf");
		assert_not_equals(NULL, ptr);
		jal_digest_ctx_destroy(&ptr);
		assert_equals((struct jal_digest_ctx *)NULL, ptr);
	}
}

void test_jal_digest_ctx_create_returns_full_struct()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		assert_not_equals(NULL, digest_ctx_list[i]);
		assert_string_equals(get_digest_algorithm(i), digest_ctx_list[i]->algorithm_uri);
		assert_equals(get_digest_length(i), digest_ctx_list[i]->len);
		assert_not_equals(NULL, digest_ctx_list[i]->create);
		assert_not_equals(NULL, digest_ctx_list[i]->init);
		assert_not_equals(NULL, digest_ctx_list[i]->update);
		assert_not_equals(NULL, digest_ctx_list[i]->final);
		assert_not_equals(NULL, digest_ctx_list[i]->destroy);
	}

	assert_equals(32, SHA256_DIGEST_LENGTH);
	assert_equals(48, SHA384_DIGEST_LENGTH);
	assert_equals(64, SHA512_DIGEST_LENGTH);
}

void test_jal_digest_create_returns_allocated_create()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		assert_not_equals(NULL, digest_inst_list[i]);
	}
}

void test_jal_digest_init_returns_ok()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		enum jal_status ret = digest_ctx_list[i]->init(digest_inst_list[i]);
		assert_equals(JAL_OK, ret);
	}
}

void test_jal_digest_init_handles_error()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		replace_init_function(i);
		enum jal_status ret = digest_ctx_list[i]->init(digest_inst_list[i]);
		assert_equals(JAL_E_INVAL, ret);
	}
}

void test_jal_digest_update_returns_ok()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		size_t len = strlen(HELLO_WORLD);
		enum jal_status ret = digest_ctx_list[i]->update(digest_inst_list[i], (uint8_t *)HELLO_WORLD, len);
		assert_equals(JAL_OK, ret);
	}
}

void test_jal_digest_update_handles_error()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		size_t len = strlen(HELLO_WORLD);
		replace_update_function(i);
		enum jal_status ret = digest_ctx_list[i]->update(digest_inst_list[i], (uint8_t *)HELLO_WORLD, len);
		assert_equals(JAL_E_INVAL, ret);
	}
}

void test_jal_digest_final_handles_error()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		size_t len = get_digest_length(i);
		uint8_t data[len];
		replace_final_function(i);
		enum jal_status ret = digest_ctx_list[i]->final(digest_inst_list[i], data, &len);
		assert_equals(JAL_E_INVAL, ret);
	}
}

void test_jal_digest_final_returns_invalid_when_len_lt_digest_length()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		size_t len = 0;
		uint8_t data[len];
		enum jal_status ret = digest_ctx_list[i]->final(digest_inst_list[i], data, &len);
		assert_equals(JAL_E_INVAL, ret);
	}
}

void test_jal_digest_full()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		void *ctx_inst = digest_inst_list[i];
		size_t len = digest_ctx_list[i]->len;
		uint8_t data[len];
		char buf[(len * 2) + 1];
		digest_ctx_list[i]->init(ctx_inst);
		digest_ctx_list[i]->update(ctx_inst, (uint8_t *)HELLO_WORLD, strlen(HELLO_WORLD));
		digest_ctx_list[i]->final(ctx_inst, data, &len);
		
		for (int j = 0; j < (int) len; j++) {
			sprintf(buf + (j * 2), "%02x", data[j]);
		}
		buf[(len * 2)] = 0;
		assert_string_equals(get_digest_sum(i), buf);
	}
}

void test_jal_digest_full_multiple_updates()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		size_t len = digest_ctx_list[i]->len;
		uint8_t data[len];
		char buf[(len * 2) + 1];
		digest_ctx_list[i]->init(digest_inst_list[i]);
		digest_ctx_list[i]->update(digest_inst_list[i], (uint8_t *)"Hel", 3);
		digest_ctx_list[i]->update(digest_inst_list[i], (uint8_t *)"lo ", 3);
		digest_ctx_list[i]->update(digest_inst_list[i], (uint8_t *)"Wor", 3);
		digest_ctx_list[i]->update(digest_inst_list[i], (uint8_t *)"ld", 2);
		digest_ctx_list[i]->final(digest_inst_list[i], data, &len);
		for (int j = 0; j < (int) len; j++) {
			sprintf(buf  + (j * 2), "%02x", data[j]);
		}
		buf[(len * 2)] = 0;
		assert_string_equals(get_digest_sum(i), buf);
	}
}

void test_jal_digest_ctx_is_valid()
{
	for (int i = 0; i < JAL_DIGEST_ALGORITHM_COUNT; i ++)
	{
		struct jal_digest_ctx *ptr = jal_digest_ctx_create((enum jal_digest_algorithm) i);
		assert_not_equals(NULL, ptr);
		set_digest_context(ptr);
		int ret_val = jal_digest_ctx_is_valid(ptr);
		assert_true(ret_val);
		jal_digest_ctx_destroy(&ptr);
	}
}

void test_jal_digest_ctx_is_invalid()
{
	struct jal_digest_ctx *ptr = jal_calloc(1, sizeof(*ptr));
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

void test_jal_digest_buffer_fails_with_bad_input()
{
	uint8_t *illegal_ptr = (void*)0xdeadbeef;
	enum jal_status ret;
	// although it seems somewhat useless, it should NOT be an
	// error to calculate a digest for a 0 length buffer, which is why
	// there are no permutations here that use 0 for the data len.
	ret = jal_digest_buffer(NULL,	NULL,			DATA_LEN,	NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_buffer(gs_ctx,NULL,			DATA_LEN,	NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_buffer(NULL,	gs_digest_input,	DATA_LEN,	NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_buffer(gs_ctx,gs_digest_input,	DATA_LEN,	NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_buffer(NULL,	NULL		,	DATA_LEN,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_buffer(gs_ctx,NULL,			DATA_LEN,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_buffer(NULL,	gs_digest_input,	DATA_LEN,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_buffer(gs_ctx,gs_digest_input,	DATA_LEN,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);

	ret = jal_digest_buffer(NULL,	NULL		,	DATA_LEN,	&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_buffer(gs_ctx,NULL,			DATA_LEN,	&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_buffer(NULL,	gs_digest_input,	DATA_LEN,	&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
}

void test_jal_digest_fd_fails_with_bad_input()
{
	use_ctx_for_fd();
	uint8_t *illegal_ptr = (void*)0xdeadbeef;
	enum jal_status ret;
	ret = jal_digest_fd(NULL,	-1,		NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_fd(gs_ctx,	-1,		NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_fd(NULL,	gs_fake_file_fd,	NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_fd(gs_ctx,	gs_fake_file_fd,	NULL);
	assert_not_equals(JAL_OK, ret);

	ret = jal_digest_fd(NULL,	-1,		&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_fd(gs_ctx,	-1,		&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_fd(NULL,	gs_fake_file_fd,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_fd(gs_ctx,	gs_fake_file_fd,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);

	ret = jal_digest_fd(NULL,	-1,		&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_fd(gs_ctx,	-1,		&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jal_digest_fd(NULL,	gs_fake_file_fd,	&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
}
void test_jal_digest_buffer_fails_when_create_fails()
{
	signal(SIGABRT, abort_handler);
	gs_ctx->create = create_fails;
	int jmp = setjmp(env);
	if (0 == jmp) {
		jal_digest_buffer(gs_ctx, gs_digest_input, DATA_LEN, &dgst_ptr);
		fail_test("Abort Should Have Been Called");
	}
	assert_equals(1, abort_called);
	assert_equals(1, create_called);
	assert_equals(0, init_called);
	assert_equals(0, update_called);
	assert_equals(0, final_called);
	assert_equals(0, destroy_called);
}

void test_jal_digest_fd_fails_when_create_fails()
{
	use_ctx_for_fd();
	signal(SIGABRT, abort_handler);
	gs_ctx->create = create_fails;
	int jmp = setjmp(env);
	if (0 == jmp) {
		jal_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
		fail_test("Abort Should Have Been Called");
	}
	assert_equals(1, abort_called);
	assert_equals(1, create_called);
	assert_equals(0, init_called);
	assert_equals(0, update_called);
	assert_equals(0, final_called);
	assert_equals(0, destroy_called);
}

void test_jal_digest_buffer_fails_when_init_fails()
{
	gs_ctx->init = init_fails;
	enum jal_status ret = jal_digest_buffer(gs_ctx, gs_digest_input, DATA_LEN, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_equals(0, update_called);
	assert_equals(0, final_called);
	assert_equals(1, destroy_called);
}

void test_jal_digest_fd_fails_when_init_fails()
{
	use_ctx_for_fd();
	gs_ctx->init = init_fails;
	enum jal_status ret = jal_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_equals(0, update_called);
	assert_equals(0, final_called);
	assert_equals(1, destroy_called);
}

void test_jal_digest_buffer_fails_when_update_fails()
{
	gs_ctx->update = update_fails;
	enum jal_status ret = jal_digest_buffer(gs_ctx, gs_digest_input, DATA_LEN, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_equals(1, update_called);
	assert_equals(0, final_called);
	assert_equals(1, destroy_called);
}

void test_jal_digest_buffer_fails_when_final_fails()
{
	gs_ctx->final = final_fails;
	enum jal_status ret = jal_digest_buffer(gs_ctx, gs_digest_input, DATA_LEN, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_equals(1, update_called);
	assert_equals(1, final_called);
	assert_equals(1, destroy_called);
}

void test_jal_digest_buffer_returns_correct_buffer()
{
	enum jal_status ret = jal_digest_buffer(gs_ctx, gs_digest_input, DATA_LEN, &dgst_ptr);
	assert_equals(JAL_OK, ret);
	assert_equals(0, memcmp(gs_digest_value, dgst_ptr, DIGEST_LEN));
}

void test_jal_digest_fd_fails_when_update_fails()
{
	use_ctx_for_fd();
	gs_ctx->update = update_fails;
	enum jal_status ret = jal_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_not_equals(0, update_called);
	assert_equals(0, final_called);
	assert_equals(1, destroy_called);
}

void test_jal_digest_fd_fails_when_final_fails()
{
	use_ctx_for_fd();
	gs_ctx->final = final_fails;
	enum jal_status ret = jal_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_not_equals(0, update_called);
	assert_equals(1, final_called);
	assert_equals(1, destroy_called);
}

void test_jal_digest_fd_fails_on_fatal_read_errors() {
	use_ctx_for_fd();
	replace_function(read, read_always_fails);
	enum jal_status ret = jal_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
}

void test_jal_digest_fd_fails_when_lseek_fails() {
	use_ctx_for_fd();
	replace_function(lseek, lseek_fails_as_pipe);
	enum jal_status ret = jal_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, lseek_called);
}

void test_jal_digest_fd_returns_correct_buffer()
{
	use_ctx_for_fd();
	enum jal_status ret = jal_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_equals(JAL_OK, ret);
	assert_equals(0, memcmp(gs_digest_value, dgst_ptr, DIGEST_LEN));
}

void test_jal_digest_buffer_returns_correct_buffer_when_len_is_null()
{
	gs_expected_input_len = 0;
	enum jal_status ret = jal_digest_buffer(gs_ctx, gs_digest_input, 0, &dgst_ptr);
	assert_equals(JAL_OK, ret);
	assert_equals(0, memcmp(gs_digest_value, dgst_ptr, DIGEST_LEN));
}

void test_jal_digest_fd_returns_correct_buffer_when_len_is_null()
{
	use_ctx_for_fd();
	gs_fake_file_size = 0;
	enum jal_status ret = jal_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_equals(JAL_OK, ret);
	assert_equals(0, memcmp(gs_digest_value, dgst_ptr, DIGEST_LEN));
}

void test_jal_digest_fd_returns_correct_buffer_with_short_len()
{
	use_ctx_for_fd();
	gs_fake_file_size = 256;
	enum jal_status ret = jal_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_equals(JAL_OK, ret);
	assert_equals(0, memcmp(gs_digest_value, dgst_ptr, DIGEST_LEN));
}

void test_jal_get_digest_algorithm_list_sha256()
{
	char *input = JAL_SHA256_ALGORITHM_STR;
	size_t num_digests = 0;
	jal_get_digest_algorithm_list(input, NULL, &digest_list, &num_digests);
	assert_equals(1, num_digests);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA256, digest_list[0]);
}

void test_jal_get_digest_algorithm_list_sha384()
{
	char *input = JAL_SHA384_ALGORITHM_STR;
	size_t num_digests = 0;
	jal_get_digest_algorithm_list(input, NULL, &digest_list, &num_digests);
	assert_equals(1, num_digests);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA384, digest_list[0]);
}

void test_jal_get_digest_algorithm_list_sha512()
{
	char *input = JAL_SHA512_ALGORITHM_STR;
	size_t num_digests = 0;
	jal_get_digest_algorithm_list(input, NULL, &digest_list, &num_digests);
	assert_equals(1, num_digests);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA512, digest_list[0]);
}

void test_jal_get_digest_algorithm_list_supports_multiple()
{
	// "sha256 sha384 sha512"
	char input[] = JAL_SHA256_ALGORITHM_STR JAL_DIGEST_ALGORITHM_DELIMETER JAL_SHA384_ALGORITHM_STR \
							   JAL_DIGEST_ALGORITHM_DELIMETER JAL_SHA512_ALGORITHM_STR;
	size_t num_digests = 0;
	jal_get_digest_algorithm_list(input, NULL, &digest_list, &num_digests);
	assert_equals(3, num_digests);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA256, digest_list[0]);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA384, digest_list[1]);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA512, digest_list[2]);
}

void test_jal_get_digest_algorithm_list_ignores_duplicates()
{
	// "sha256 sha256 sha256 sha256 sha384"
	char input[] = JAL_SHA256_ALGORITHM_STR JAL_DIGEST_ALGORITHM_DELIMETER JAL_SHA256_ALGORITHM_STR \
								 JAL_DIGEST_ALGORITHM_DELIMETER JAL_SHA256_ALGORITHM_STR JAL_DIGEST_ALGORITHM_DELIMETER \
								 JAL_SHA256_ALGORITHM_STR JAL_DIGEST_ALGORITHM_DELIMETER JAL_SHA384_ALGORITHM_STR;
	size_t num_digests = 0;
	jal_get_digest_algorithm_list(input, NULL, &digest_list, &num_digests);
	assert_equals(2, num_digests);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA256, digest_list[0]);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA384, digest_list[1]);
}

void test_jal_get_digest_algorithm_list_cli_overwrites_config()
{
	char *cfg_input = JAL_SHA256_ALGORITHM_STR;
	char *cli_input = JAL_SHA512_ALGORITHM_STR;
	size_t num_digests = 0;
	jal_get_digest_algorithm_list(cfg_input, cli_input, &digest_list, &num_digests);
	assert_equals(1, num_digests);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA512, digest_list[0]);
}

void test_jal_get_digest_algorithm_list_default_both_null()
{
	size_t num_digests = 0;
	jal_get_digest_algorithm_list(NULL, NULL, &digest_list, &num_digests);
	assert_equals(1, num_digests);
	assert_equals(JAL_DIGEST_ALGORITHM_DEFAULT, digest_list[0]);
}

void test_jal_get_digest_algorithm_list_default_both_empty()
{
	size_t num_digests = 0;
	jal_get_digest_algorithm_list("", "", &digest_list, &num_digests);
	assert_equals(1, num_digests);
	assert_equals(JAL_DIGEST_ALGORITHM_DEFAULT, digest_list[0]);
}

void test_jal_get_digest_algorithm_list_default_config_empty()
{
	size_t num_digests = 0;
	jal_get_digest_algorithm_list("", NULL, &digest_list, &num_digests);
	assert_equals(1, num_digests);
	assert_equals(JAL_DIGEST_ALGORITHM_DEFAULT, digest_list[0]);
}

void test_jal_get_digest_algorithm_list_default_cli_empty()
{
	size_t num_digests = 0;
	jal_get_digest_algorithm_list(NULL, "", &digest_list, &num_digests);
	assert_equals(1, num_digests);
	assert_equals(JAL_DIGEST_ALGORITHM_DEFAULT, digest_list[0]);
}

void test_jal_get_digest_from_str()
{
	enum jal_digest_algorithm digest_algorithm;
	jal_get_digest_from_str(JAL_SHA256_ALGORITHM_STR, &digest_algorithm);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA256, digest_algorithm);
	jal_get_digest_from_str(JAL_SHA384_ALGORITHM_STR, &digest_algorithm);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA384, digest_algorithm);
	jal_get_digest_from_str(JAL_SHA512_ALGORITHM_STR, &digest_algorithm);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA512, digest_algorithm);
}

void test_jal_get_digest_from_uri()
{
	enum jal_digest_algorithm digest_algorithm;
	jal_get_digest_from_uri(JAL_SHA256_ALGORITHM_URI, &digest_algorithm);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA256, digest_algorithm);
	jal_get_digest_from_uri(JAL_SHA384_ALGORITHM_URI, &digest_algorithm);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA384, digest_algorithm);
	jal_get_digest_from_uri(JAL_SHA512_ALGORITHM_URI, &digest_algorithm);
	assert_equals(JAL_DIGEST_ALGORITHM_SHA512, digest_algorithm);
}