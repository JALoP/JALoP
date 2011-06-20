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

/*static const char *DEFAULT_JALOP_RENDEZVOUS = "/var/run/jalop/jalop.sock";
static const char *MOCKED_HOSTNAME = "mocked_hostname";
static const char *MOCKED_APP_NAME = "mocked_app_name";
static const char *SOME_HOST = "some_host";
static const char *SOME_PATH = "/path/to/jalop/rendezvous";
static const char *SOME_APP = "test_jalp_context";
static const char *FAKE_PID_STR "-1"
*/

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
}
void teardown()
{
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
