/**
 * @file This file contains tests for jalp_context functions.
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
#include <jalop/jalp_context.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include "jal_alloc.h"
#include "jalp_context_internal.h"

#define FAKE_SOCKET (int)0xdeadbeef

#define FAKE_PID (int)-1

#define DEFAULT_JALOP_RENDEZVOUS "/var/run/jalop/jalop.sock"
#define MOCKED_HOSTNAME "mocked_hostname"
#define MOCKED_APP_NAME "mocked_app_name"
#define SOME_HOST "some_host"
#define SOME_PATH "/path/to/jalop/rendezvous"
#define SOME_APP "test_jalp_context"
#define FAKE_PID_STR "-1"

struct jalp_context_t *jpctx = NULL;
struct jal_digest_ctx *dctx = NULL;
struct jal_digest_ctx *dctx2 = NULL;

// Set of dummy functions for a fake digest context
void *fake_create()
{
	return NULL;
}
int fake_init(__attribute__((unused)) void *instance)
{
	return JAL_OK;
}
int fake_update(__attribute__((unused)) void *instance,
		__attribute__((unused)) uint8_t *data,
		__attribute__((unused)) uint32_t len)
{
	return JAL_OK;
}
int fake_final(__attribute__((unused)) void *instance,
		__attribute__((unused)) uint8_t *digest,
		__attribute__((unused)) uint32_t *len)

{
	return JAL_OK;
}
void fake_destroy(__attribute__((unused)) void *instance)
{
	// do nothing
}

// second set of function callbacks to test multiple calls to
// jalp_set_digest_context
void *fake_create2()
{
	return NULL;
}
int fake_init2(__attribute__((unused)) void *instance)
{
	return JAL_OK;
}
int fake_update2(__attribute__((unused)) void *instance,
		__attribute__((unused)) uint8_t *data,
		__attribute__((unused)) uint32_t len)
{
	return JAL_OK;
}
int fake_final2(__attribute__((unused)) void *instance,
		__attribute__((unused)) uint8_t *digest,
		__attribute__((unused)) uint32_t *len)

{
	return JAL_OK;
}
void fake_destroy2(__attribute__((unused)) void *instance)
{
	// do nothing
}

static int close_called;
static int connect_call_cnt;
int socket_always_fails(__attribute__((unused)) int domain,
		__attribute__((unused)) int type,
		__attribute__((unused)) int protocol)
{
	return -1;
}
int mocked_connect(__attribute__((unused)) int fd,
		__attribute__((unused)) const struct sockaddr *addr,
		__attribute__((unused)) socklen_t addrlen)
{
	connect_call_cnt++;
	return 0;
}
int connect_always_fails(__attribute__((unused)) int fd,
		__attribute__((unused)) const struct sockaddr *addr,
		__attribute__((unused)) socklen_t addrlen)
{
	connect_call_cnt++;
	return -1;
}
int mocked_close(int fd)
{
	if (fd == FAKE_SOCKET) {
		close_called = 1;
		return 0;
	}
	return close(fd);
}
int mocked_gethostname(char *name, size_t len)
{
	strncpy(name, MOCKED_HOSTNAME, len);
	return 0;
}
int gethostname_always_fails(__attribute__((unused)) char *name,
		__attribute__((unused)) size_t len)
{
	return -1;
}
pid_t mocked_getpid()
{
	return FAKE_PID;
}
ssize_t readlink_always_fails(__attribute__((unused)) const char *path,
		__attribute__((unused)) char *buf,
		__attribute__((unused)) size_t bufsiz)
{
	return -1;
}
ssize_t mocked_readlink(__attribute__((unused)) const char *path,
		__attribute__((unused)) char *buf,
		__attribute__((unused)) size_t bufsiz)
{
	strncpy(buf, MOCKED_APP_NAME, bufsiz);
	return bufsiz < strlen(MOCKED_APP_NAME) ? bufsiz : strlen(MOCKED_APP_NAME);
}

void setup()
{
	replace_function(connect, mocked_connect);
	close_called = 0;
	connect_call_cnt = 0;

	jpctx = jalp_context_create();
	dctx = jal_digest_ctx_create();
	dctx2 = jal_digest_ctx_create();

	dctx->create = fake_create;
	dctx->init = fake_init;
	dctx->update = fake_update;
	dctx->final = fake_final;
	dctx->destroy = fake_destroy;
	dctx->len = 1;
	dctx->algorithm_uri = jal_strdup("asdf");

	dctx2->create = fake_create2;
	dctx2->init = fake_init2;
	dctx2->update = fake_update2;
	dctx2->final = fake_final2;
	dctx2->destroy = fake_destroy2;
	dctx2->len = 2;
	dctx2->algorithm_uri = jal_strdup("asdf2");

}
void teardown()
{
	jalp_context_destroy(&jpctx);
	jal_digest_ctx_destroy(&dctx);
	jal_digest_ctx_destroy(&dctx2);

	close_called = 0;
	connect_call_cnt = 0;
	restore_function(close);
	restore_function(socket);
	restore_function(connect);
	restore_function(readlink);
	restore_function(gethostname);
	restore_function(getpid);
}
void test_jalp_context_create_returns_struct_with_zeroed_fields()
{
	struct jalp_context_t *ptr = jalp_context_create();
	assert_not_equals(NULL, ptr);

	assert_equals(-1, ptr->socket);
	assert_equals((char *) NULL, ptr->path);
	assert_equals((char *) NULL, ptr->hostname);
	assert_equals((char *) NULL, ptr->app_name);
	jalp_context_destroy(&ptr);
}

void test_jalp_context_destroy_does_not_crash_with_null()
{
	jalp_context_destroy(NULL);
	struct jalp_context_t *ptr = NULL;
	jalp_context_destroy(&ptr);
	assert_equals((void *) NULL, ptr);
}

void test_jalp_context_destroy_closes_socket()
{
	replace_function(close, mocked_close)
	struct jalp_context_t *ptr = jalp_context_create();
	// bogus file descriptor
	ptr->socket = FAKE_SOCKET;

	jalp_context_destroy(&ptr);
	assert_equals((void *) NULL, ptr);
	assert_equals(1, close_called);
}

void test_jalp_disconnect_closes_the_socket()
{
	replace_function(close, mocked_close);
	struct jalp_context_t *ctx = jalp_context_create();
	// bogus file descriptor
	ctx->socket = FAKE_SOCKET;

	jalp_context_disconnect(ctx);
	assert_equals(1, close_called);
	assert_equals(-1, ctx->socket);

	jalp_context_destroy(&ctx);

}
void test_jalp_context_destroy_release_memory()
{
	// test under valgrind
	struct jalp_context_t *ptr = jalp_context_create();
	ptr->path = jal_strdup("/foo/bar");
	ptr->app_name = jal_strdup("test-dept");

	jalp_context_destroy(&ptr);
	assert_equals((void *) NULL, ptr);
}

void test_jalp_context_connect_returns_error_with_null()
{
	enum jal_status ret = jalp_context_connect(NULL);
	assert_equals(JAL_E_INVAL, ret);
}
void test_jalp_context_connect_returns_error_with_uninitialized_context()
{
	jalp_context *ctx = jalp_context_create();
	enum jal_status ret = jalp_context_connect(ctx);
	assert_equals(JAL_E_UNINITIALIZED, ret);
	jalp_context_destroy(&ctx);
}
void test_jalp_context_connect_returns_error_when_socket_fails()
{
	replace_function(socket, socket_always_fails);
	jalp_context *ctx = jalp_context_create();
	enum jal_status ret = jalp_context_init(ctx, NULL, NULL, NULL);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_connect(ctx);
	assert_equals(JAL_E_NOT_CONNECTED, ret);
	jalp_context_destroy(&ctx);
}
void test_jalp_context_connect_returns_error_when_connect_fails()
{
	replace_function(connect, connect_always_fails);
	jalp_context *ctx = jalp_context_create();
	enum jal_status ret = jalp_context_init(ctx, NULL, NULL, NULL);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_connect(ctx);
	assert_equals(JAL_E_NOT_CONNECTED, ret);
	jalp_context_destroy(&ctx);
}

void test_multiple_calls_to_jalp_context_connect_attempt_reconnection()
{
	jalp_context *ctx = jalp_context_create();
	enum jal_status ret = jalp_context_init(ctx, NULL, NULL, NULL);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_connect(ctx);
	assert_equals(JAL_OK, ret);
	assert_equals(1, connect_call_cnt);

	ret = jalp_context_connect(ctx);
	assert_equals(JAL_OK, ret);
	assert_equals(2, connect_call_cnt);

	jalp_context_destroy(&ctx);
}

void test_jalp_context_init_returns_context_with_defaults()
{
	// fake readlink to always return DEFAULT_APP_NAME
	replace_function(readlink, mocked_readlink);
	// fake readlink to always return MOCKED_HOSTNAME
	replace_function(gethostname, mocked_gethostname);

	enum jal_status ret;
	struct jalp_context_t *ctx;
	// probably overkill

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	NULL,		NULL,		NULL);
	assert_equals(JAL_OK, ret);
	assert_string_equals(DEFAULT_JALOP_RENDEZVOUS, ctx->path);
	assert_string_equals(MOCKED_HOSTNAME, ctx->hostname);
	assert_string_equals(MOCKED_APP_NAME, ctx->app_name);
	jalp_context_destroy(&ctx);

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	NULL,		NULL,		SOME_APP);
	assert_equals(JAL_OK, ret);
	assert_string_equals(DEFAULT_JALOP_RENDEZVOUS, ctx->path);
	assert_string_equals(MOCKED_HOSTNAME, ctx->hostname);
	assert_string_equals(SOME_APP, ctx->app_name);
	jalp_context_destroy(&ctx);

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	NULL,		SOME_HOST,	NULL);
	assert_equals(JAL_OK, ret);
	assert_string_equals(DEFAULT_JALOP_RENDEZVOUS, ctx->path);
	assert_string_equals(SOME_HOST, ctx->hostname);
	assert_string_equals(MOCKED_APP_NAME, ctx->app_name);
	jalp_context_destroy(&ctx);

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	NULL,		SOME_HOST,	SOME_APP);
	assert_equals(JAL_OK, ret);
	assert_string_equals(DEFAULT_JALOP_RENDEZVOUS, ctx->path);
	assert_string_equals(SOME_HOST, ctx->hostname);
	assert_string_equals(SOME_APP, ctx->app_name);
	jalp_context_destroy(&ctx);

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	SOME_PATH,	NULL,		NULL);
	assert_equals(JAL_OK, ret);
	assert_string_equals(SOME_PATH, ctx->path);
	assert_string_equals(MOCKED_HOSTNAME, ctx->hostname);
	assert_string_equals(MOCKED_APP_NAME, ctx->app_name);
	jalp_context_destroy(&ctx);

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	SOME_PATH,	NULL,		SOME_APP);
	assert_equals(JAL_OK, ret);
	assert_string_equals(SOME_PATH, ctx->path);
	assert_string_equals(MOCKED_HOSTNAME, ctx->hostname);
	assert_string_equals(SOME_APP, ctx->app_name);
	jalp_context_destroy(&ctx);

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	SOME_PATH,	SOME_HOST,	NULL);
	assert_equals(JAL_OK, ret);
	assert_string_equals(SOME_PATH, ctx->path);
	assert_string_equals(SOME_HOST, ctx->hostname);
	assert_string_equals(MOCKED_APP_NAME, ctx->app_name);
	jalp_context_destroy(&ctx);

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	SOME_PATH,	SOME_HOST,	SOME_APP);
	assert_equals(JAL_OK, ret);
	assert_string_equals(SOME_PATH, ctx->path);
	assert_string_equals(SOME_HOST, ctx->hostname);
	assert_string_equals(SOME_APP, ctx->app_name);
	jalp_context_destroy(&ctx);
}
void test_jalp_context_init_falls_back_to_pid_if_cannot_read_procfs()
{
	// make reading of procfs fail so things always fallback on the pid..
	replace_function(readlink, readlink_always_fails);
	// use a predictable pid/string
	replace_function(getpid, mocked_getpid);

	enum jal_status ret;
	struct jalp_context_t *ctx;
	// probably overkill

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	NULL,		NULL,		NULL);
	assert_equals(JAL_OK, ret);
	assert_string_equals(FAKE_PID_STR, ctx->app_name);
	jalp_context_destroy(&ctx);

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	NULL,		SOME_HOST,	NULL);
	assert_equals(JAL_OK, ret);
	assert_string_equals(FAKE_PID_STR, ctx->app_name);
	jalp_context_destroy(&ctx);

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	SOME_PATH,	NULL,		NULL);
	assert_equals(JAL_OK, ret);
	assert_string_equals(FAKE_PID_STR, ctx->app_name);
	jalp_context_destroy(&ctx);

	ctx = jalp_context_create();
	ret = jalp_context_init(ctx,	SOME_PATH,	SOME_HOST,	NULL);
	assert_equals(JAL_OK, ret);
	assert_string_equals(FAKE_PID_STR, ctx->app_name);
	jalp_context_destroy(&ctx);
}
void test_jalp_context_init_returns_error_when_context_is_null()
{
	enum jal_status ret;
	// perhaps a bit of overkill....
	ret = jalp_context_init(NULL,	NULL,		NULL,		 NULL);
	assert_equals(JAL_E_INVAL, ret);
	ret = jalp_context_init(NULL,	NULL,		NULL,		SOME_APP);
	assert_equals(JAL_E_INVAL, ret);
	ret = jalp_context_init(NULL,	NULL,		SOME_HOST,	NULL);
	assert_equals(JAL_E_INVAL, ret);
	ret = jalp_context_init(NULL,	NULL,		SOME_HOST,	SOME_APP);
	assert_equals(JAL_E_INVAL, ret);
	ret = jalp_context_init(NULL,	SOME_PATH,	NULL,		NULL);
	assert_equals(JAL_E_INVAL, ret);
	ret = jalp_context_init(NULL,	SOME_PATH,	NULL,		SOME_APP);
	assert_equals(JAL_E_INVAL, ret);
	ret = jalp_context_init(NULL,	SOME_PATH,	SOME_HOST,	NULL);
	assert_equals(JAL_E_INVAL, ret);
	ret = jalp_context_init(NULL,	SOME_PATH,	SOME_HOST,	SOME_APP);
	assert_equals(JAL_E_INVAL, ret);
}
void test_calling_jalp_context_init_multiple_times_returns_an_error()
{
	struct jalp_context_t *ctx = jalp_context_create();
	enum jal_status ret = jalp_context_init(ctx, SOME_PATH, SOME_HOST, SOME_APP);
	assert_equals(JAL_OK, ret);

	ret = jalp_context_init(ctx, SOME_PATH, SOME_HOST, SOME_APP);
	assert_equals(JAL_E_INITIALIZED, ret);

	assert_string_equals(SOME_PATH, ctx->path);
	assert_string_equals(SOME_HOST, ctx->hostname);
	assert_string_equals(SOME_APP, ctx->app_name);

	jalp_context_destroy(&ctx);
}
void test_calling_jalp_context_init_multiple_times_does_not_reset_the_connection()
{
	struct jalp_context_t *ctx = jalp_context_create();
	enum jal_status ret = jalp_context_init(ctx, SOME_PATH, SOME_HOST, SOME_APP);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_connect(ctx);
	assert_equals(JAL_OK, ret);
	int originalSocket = ctx->socket;

	ret = jalp_context_init(ctx, SOME_PATH, SOME_HOST, SOME_APP);
	assert_equals(JAL_E_INITIALIZED, ret);

	ret = jalp_context_init(ctx, "path2", "hostname2", "app_name2");
	assert_equals(0, close_called);
	assert_equals(originalSocket, ctx->socket);
	jalp_context_destroy(&ctx);
}

void test_jalp_set_digest_ctx_with_null_jalp_ctx_does_not_crash()
{
	enum jal_status ret = jalp_context_set_digest_callbacks(NULL, NULL);
	assert_equals(JAL_E_INVAL, ret);

	ret = jalp_context_set_digest_callbacks(NULL, dctx);
	assert_equals(JAL_E_INVAL, ret);
}
void test_jalp_set_digest_ctx_with_null_clears_ctx()
{
	// run under valgrind
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_set_digest_callbacks(jpctx, NULL);
	assert_equals(JAL_OK, ret);
	assert_equals((void*)NULL, jpctx->digest_ctx);
}

void test_jalp_set_digest_ctx_fails_with_invalid_length()
{
	dctx->len = -1;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_E_INVAL, ret);

	dctx->len = 0;
	ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_E_INVAL, ret);

}

void test_jalp_set_digest_ctx_fails_with_null_algorithm_uri()
{
	free(dctx->algorithm_uri);
	dctx->algorithm_uri = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_E_INVAL, ret);

}

void test_jalp_set_digest_ctx_fails_with_missing_create_function()
{
	dctx->create = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_E_INVAL, ret);
}
void test_jalp_set_digest_ctx_fails_with_missing_init_function()
{
	dctx->init = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_E_INVAL, ret);
}
void test_jalp_set_digest_ctx_fails_with_missing_update_function()
{
	dctx->update = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_E_INVAL, ret);
}
void test_jalp_set_digest_ctx_fails_with_missing_final_function()
{
	dctx->final = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_E_INVAL, ret);
}

void test_jalp_set_digest_ctx_fails_with_missing_destroy_function()
{
	dctx->destroy = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_E_INVAL, ret);
}
void test_jalp_set_digest_ctx_succeeds_with_valid_context()
{
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);
}
void test_jalp_set_digest_ctx_makes_a_copy()
{
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);

	assert_not_equals(jpctx->digest_ctx, dctx);
	assert_equals(jpctx->digest_ctx->len, dctx->len);
	assert_string_equals(jpctx->digest_ctx->algorithm_uri, dctx->algorithm_uri);
	assert_equals(jpctx->digest_ctx->create, dctx->create);
	assert_equals(jpctx->digest_ctx->init, dctx->init);
	assert_equals(jpctx->digest_ctx->update, dctx->update);
	assert_equals(jpctx->digest_ctx->final, dctx->final);
	assert_equals(jpctx->digest_ctx->destroy, dctx->destroy);
}

void test_jalp_multiple_calls_to_set_digest_context_replace_functions()
{
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);

	ret = jalp_context_set_digest_callbacks(jpctx, dctx2);
	assert_equals(JAL_OK, ret);

	assert_not_equals(jpctx->digest_ctx, dctx2);
	assert_equals(jpctx->digest_ctx->len, dctx2->len);
	assert_string_equals(jpctx->digest_ctx->algorithm_uri, dctx2->algorithm_uri);
	assert_equals(jpctx->digest_ctx->create, dctx2->create);
	assert_equals(jpctx->digest_ctx->init, dctx2->init);
	assert_equals(jpctx->digest_ctx->update, dctx2->update);
	assert_equals(jpctx->digest_ctx->final, dctx2->final);
	assert_equals(jpctx->digest_ctx->destroy, dctx2->destroy);
}

void test_jalp_multiple_calls_to_set_digest_do_not_leak()
{
	// run under valgrind
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);

	ret = jalp_context_set_digest_callbacks(jpctx, dctx2);
	assert_equals(JAL_OK, ret);

	ret = jalp_context_set_digest_callbacks(jpctx, NULL);
	assert_equals(JAL_OK, ret);
}

void test_multiple_calls_to_jalp_set_digest_ctx_with_null_jalp_ctx_does_not_crash()
{
	enum jal_status ret = jalp_context_set_digest_callbacks(NULL, NULL);
	assert_equals(JAL_E_INVAL, ret);

	ret = jalp_context_set_digest_callbacks(NULL, dctx);
	assert_equals(JAL_E_INVAL, ret);
}
void test_multiple_calls_to_jalp_set_digest_ctx_with_null_clears_ctx()
{
	// run under valgrind, shouldn't leak
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_set_digest_callbacks(jpctx, NULL);
	assert_equals(JAL_OK, ret);
	assert_equals((void*)NULL, jpctx->digest_ctx);
}

void test_second_call_to_jalp_set_digest_ctx_with_invalid_length_retains_original_context()
{
	dctx2->len = -1;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_set_digest_callbacks(jpctx, dctx2);
	assert_equals(JAL_E_INVAL, ret);

	// make sure it's still using the original context
	assert_equals(jpctx->digest_ctx->len, dctx->len);
	assert_equals(jpctx->digest_ctx->create, dctx->create);
	assert_equals(jpctx->digest_ctx->init, dctx->init);
	assert_equals(jpctx->digest_ctx->update, dctx->update);
	assert_equals(jpctx->digest_ctx->final, dctx->final);
	assert_equals(jpctx->digest_ctx->destroy, dctx->destroy);

}

void test_second_call_to_jalp_set_digest_ctx_with_missing_create_function_retains_original_context()
{
	dctx2->create = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_set_digest_callbacks(jpctx, dctx2);
	assert_equals(JAL_E_INVAL, ret);

	// make sure it's still using the original context
	assert_equals(jpctx->digest_ctx->len, dctx->len);
	assert_equals(jpctx->digest_ctx->create, dctx->create);
	assert_equals(jpctx->digest_ctx->init, dctx->init);
	assert_equals(jpctx->digest_ctx->update, dctx->update);
	assert_equals(jpctx->digest_ctx->final, dctx->final);
	assert_equals(jpctx->digest_ctx->destroy, dctx->destroy);
}
void test_second_call_to_jalp_set_digest_ctx_with_missing_init_function_retains_original_context()
{
	dctx2->init = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_set_digest_callbacks(jpctx, dctx2);
	assert_equals(JAL_E_INVAL, ret);

	// make sure it's still using the original context
	assert_equals(jpctx->digest_ctx->len, dctx->len);
	assert_equals(jpctx->digest_ctx->create, dctx->create);
	assert_equals(jpctx->digest_ctx->init, dctx->init);
	assert_equals(jpctx->digest_ctx->update, dctx->update);
	assert_equals(jpctx->digest_ctx->final, dctx->final);
	assert_equals(jpctx->digest_ctx->destroy, dctx->destroy);
}
void test_second_call_to_jalp_set_digest_ctx_with_missing_update_function_retains_original_context()
{
	dctx2->update = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_set_digest_callbacks(jpctx, dctx2);
	assert_equals(JAL_E_INVAL, ret);

	// make sure it's still using the original context
	assert_equals(jpctx->digest_ctx->len, dctx->len);
	assert_equals(jpctx->digest_ctx->create, dctx->create);
	assert_equals(jpctx->digest_ctx->init, dctx->init);
	assert_equals(jpctx->digest_ctx->update, dctx->update);
	assert_equals(jpctx->digest_ctx->final, dctx->final);
	assert_equals(jpctx->digest_ctx->destroy, dctx->destroy);
}
void test_second_call_to_jalp_set_digest_ctx_with_missing_final_function_retains_original_context()
{
	dctx2->final = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_set_digest_callbacks(jpctx, dctx2);
	assert_equals(JAL_E_INVAL, ret);

	// make sure it's still using the original context
	assert_equals(jpctx->digest_ctx->len, dctx->len);
	assert_equals(jpctx->digest_ctx->create, dctx->create);
	assert_equals(jpctx->digest_ctx->init, dctx->init);
	assert_equals(jpctx->digest_ctx->update, dctx->update);
	assert_equals(jpctx->digest_ctx->final, dctx->final);
	assert_equals(jpctx->digest_ctx->destroy, dctx->destroy);
}

void test_second_call_to_jalp_set_digest_ctx_with_missing_destroy_function_retains_original_context()
{
	dctx2->destroy = NULL;
	enum jal_status ret = jalp_context_set_digest_callbacks(jpctx, dctx);
	assert_equals(JAL_OK, ret);
	ret = jalp_context_set_digest_callbacks(jpctx, dctx2);
	assert_equals(JAL_E_INVAL, ret);

	// make sure it's still using the original context
	assert_equals(jpctx->digest_ctx->len, dctx->len);
	assert_equals(jpctx->digest_ctx->create, dctx->create);
	assert_equals(jpctx->digest_ctx->init, dctx->init);
	assert_equals(jpctx->digest_ctx->update, dctx->update);
	assert_equals(jpctx->digest_ctx->final, dctx->final);
	assert_equals(jpctx->digest_ctx->destroy, dctx->destroy);
}
