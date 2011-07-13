/**
 * @file test_jalp_digest.c This file contains tests for jalp_digest functions.
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
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include "jalp_digest_internal.h"
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
		// jalp_digest_buffer() is passing bad values into the
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
		// jalp_digest_buffer() is passing bad values into the
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
		// jalp_digest_buffer() is passing bad values into the
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
		// jalp_digest_buffer() is passing bad values into the
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
		// jalp_digest_buffer() is passing bad values into the
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

void setup()
{
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

	gs_ctx = jal_digest_ctx_create();
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
}

void teardown()
{
	jal_digest_ctx_destroy(&gs_ctx);
	free(dgst_ptr);
	restore_function(read);
	restore_function(lseek);
	free(gs_fake_file_buffer);
}

void test_jalp_digest_buffer_fails_with_bad_input()
{
	uint8_t *illegal_ptr = (void*)0xdeadbeef;
	enum jal_status ret;
	// although it seems somewhat useless, it should NOT be an
	// error to calculate a digest for a 0 length buffer, which is why
	// there are no permutations here that use 0 for the data len.
	ret = jalp_digest_buffer(NULL,	NULL,			DATA_LEN,	NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_buffer(gs_ctx,NULL,			DATA_LEN,	NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_buffer(NULL,	gs_digest_input,	DATA_LEN,	NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_buffer(gs_ctx,gs_digest_input,	DATA_LEN,	NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_buffer(NULL,	NULL		,	DATA_LEN,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_buffer(gs_ctx,NULL,			DATA_LEN,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_buffer(NULL,	gs_digest_input,	DATA_LEN,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_buffer(gs_ctx,gs_digest_input,	DATA_LEN,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);

	ret = jalp_digest_buffer(NULL,	NULL		,	DATA_LEN,	&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_buffer(gs_ctx,NULL,			DATA_LEN,	&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_buffer(NULL,	gs_digest_input,	DATA_LEN,	&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
}

void test_jalp_digest_fd_fails_with_bad_input()
{
	use_ctx_for_fd();
	uint8_t *illegal_ptr = (void*)0xdeadbeef;
	enum jal_status ret;
	ret = jalp_digest_fd(NULL,	-1,		NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_fd(gs_ctx,	-1,		NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_fd(NULL,	gs_fake_file_fd,	NULL);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_fd(gs_ctx,	gs_fake_file_fd,	NULL);
	assert_not_equals(JAL_OK, ret);

	ret = jalp_digest_fd(NULL,	-1,		&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_fd(gs_ctx,	-1,		&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_fd(NULL,	gs_fake_file_fd,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_fd(gs_ctx,	gs_fake_file_fd,	&illegal_ptr);
	assert_not_equals(JAL_OK, ret);

	ret = jalp_digest_fd(NULL,	-1,		&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_fd(gs_ctx,	-1,		&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_digest_fd(NULL,	gs_fake_file_fd,	&dgst_ptr);
	assert_not_equals(JAL_OK, ret);
}
void test_jalp_digest_buffer_fails_when_create_fails()
{
	signal(SIGABRT, abort_handler);
	gs_ctx->create = create_fails;
	int jmp = setjmp(env);
	if (0 == jmp) {
		jalp_digest_buffer(gs_ctx, gs_digest_input, DATA_LEN, &dgst_ptr);
		fail_test("Abort Should Have Been Called");
	}
	assert_equals(1, abort_called);
	assert_equals(1, create_called);
	assert_equals(0, init_called);
	assert_equals(0, update_called);
	assert_equals(0, final_called);
	assert_equals(0, destroy_called);
}

void test_jalp_digest_fd_fails_when_create_fails()
{
	use_ctx_for_fd();
	signal(SIGABRT, abort_handler);
	gs_ctx->create = create_fails;
	int jmp = setjmp(env);
	if (0 == jmp) {
		jalp_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
		fail_test("Abort Should Have Been Called");
	}
	assert_equals(1, abort_called);
	assert_equals(1, create_called);
	assert_equals(0, init_called);
	assert_equals(0, update_called);
	assert_equals(0, final_called);
	assert_equals(0, destroy_called);
}

void test_jalp_digest_buffer_fails_when_init_fails()
{
	gs_ctx->init = init_fails;
	enum jal_status ret = jalp_digest_buffer(gs_ctx, gs_digest_input, DATA_LEN, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_equals(0, update_called);
	assert_equals(0, final_called);
	assert_equals(1, destroy_called);
}

void test_jalp_digest_fd_fails_when_init_fails()
{
	use_ctx_for_fd();
	gs_ctx->init = init_fails;
	enum jal_status ret = jalp_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_equals(0, update_called);
	assert_equals(0, final_called);
	assert_equals(1, destroy_called);
}

void test_jalp_digest_buffer_fails_when_update_fails()
{
	gs_ctx->update = update_fails;
	enum jal_status ret = jalp_digest_buffer(gs_ctx, gs_digest_input, DATA_LEN, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_equals(1, update_called);
	assert_equals(0, final_called);
	assert_equals(1, destroy_called);
}

void test_jalp_digest_buffer_fails_when_final_fails()
{
	gs_ctx->final = final_fails;
	enum jal_status ret = jalp_digest_buffer(gs_ctx, gs_digest_input, DATA_LEN, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_equals(1, update_called);
	assert_equals(1, final_called);
	assert_equals(1, destroy_called);
}

void test_jalp_digest_buffer_returns_correct_buffer()
{
	enum jal_status ret = jalp_digest_buffer(gs_ctx, gs_digest_input, DATA_LEN, &dgst_ptr);
	assert_equals(JAL_OK, ret);
	assert_equals(0, memcmp(gs_digest_value, dgst_ptr, DIGEST_LEN));
}

void test_jalp_digest_fd_fails_when_update_fails()
{
	use_ctx_for_fd();
	gs_ctx->update = update_fails;
	enum jal_status ret = jalp_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_not_equals(0, update_called);
	assert_equals(0, final_called);
	assert_equals(1, destroy_called);
}

void test_jalp_digest_fd_fails_when_final_fails()
{
	use_ctx_for_fd();
	gs_ctx->final = final_fails;
	enum jal_status ret = jalp_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, create_called);
	assert_equals(1, init_called);
	assert_not_equals(0, update_called);
	assert_equals(1, final_called);
	assert_equals(1, destroy_called);
}

void test_jalp_digest_fd_fails_on_fatal_read_errors() {
	use_ctx_for_fd();
	replace_function(read, read_always_fails);
	enum jal_status ret = jalp_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
}

void test_jalp_digest_fd_fails_when_lseek_fails() {
	use_ctx_for_fd();
	replace_function(lseek, lseek_fails_as_pipe);
	enum jal_status ret = jalp_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_not_equals(JAL_OK, ret);
	assert_equals(1, lseek_called);
}

void test_jalp_digest_fd_returns_correct_buffer()
{
	use_ctx_for_fd();
	enum jal_status ret = jalp_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_equals(JAL_OK, ret);
	assert_equals(0, memcmp(gs_digest_value, dgst_ptr, DIGEST_LEN));
}

void test_jalp_digest_buffer_returns_correct_buffer_when_len_is_null()
{
	gs_expected_input_len = 0;
	enum jal_status ret = jalp_digest_buffer(gs_ctx, gs_digest_input, 0, &dgst_ptr);
	assert_equals(JAL_OK, ret);
	assert_equals(0, memcmp(gs_digest_value, dgst_ptr, DIGEST_LEN));
}

void test_jalp_digest_fd_returns_correct_buffer_when_len_is_null()
{
	use_ctx_for_fd();
	gs_fake_file_size = 0;
	enum jal_status ret = jalp_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_equals(JAL_OK, ret);
	assert_equals(0, memcmp(gs_digest_value, dgst_ptr, DIGEST_LEN));
}

void test_jalp_digest_fd_returns_correct_buffer_with_short_len()
{
	use_ctx_for_fd();
	gs_fake_file_size = 256;
	enum jal_status ret = jalp_digest_fd(gs_ctx, gs_fake_file_fd, &dgst_ptr);
	assert_equals(JAL_OK, ret);
	assert_equals(0, memcmp(gs_digest_value, dgst_ptr, DIGEST_LEN));
}
