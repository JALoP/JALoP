#include <test-dept.h>
#include <jalop/jalp_context.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include "jal_alloc.h"
#include "jalp_context_internal.h"
#define FAKE_SOCKET (int)0xdeadbeef
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
void setup()
{
	replace_function(connect, mocked_connect);
	close_called = 0;
	connect_call_cnt = 0;
}
void teardown()
{
	close_called = 0;
	connect_call_cnt = 0;
	restore_function(close);
	restore_function(socket);
	restore_function(connect);
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
