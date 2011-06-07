#include <test-dept.h>
#include <jalop/jalp_context.h>
#include "jal_alloc.h"
#include "jalp_context_internal.h"
#include <unistd.h>
#define FAKE_SOCKET (int)0xdeadbeef
static int close_called;
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
	close_called = 0;
}
void teardown()
{
	close_called = 0;
	restore_function(close);
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

