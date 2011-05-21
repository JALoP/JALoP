#include <stdlib.h>
#include <setjmp.h>
#include <signal.h>
#include <test-dept.h>
#include <jalop/jalp_error_callback.h>

#include "jalp_error_callback_internal.h"

static int td_error_handler_called = 0;
static int abort_called = 0;
static jmp_buf env;

__attribute__((noreturn)) void abort_handler(__attribute__((unused))int sig)
{
	abort_called = 1;
	signal(SIGABRT, abort_handler);
	longjmp(env, 1);
}

static void td_error_handler(__attribute__((unused))int err)
{
	td_error_handler_called = 1;
}
void setup()
{
	signal(SIGABRT, abort_handler);
	td_error_handler_called = 0;
	abort_called = 0;
}
void teardown()
{
	restore_function(&abort);
}
void test_error_handler_executes_abort_by_default()
{
	assert_equals(0, abort_called);
	int ret = setjmp(env);
	if (0 == ret) {
		jalp_error_handler(1);
	}
	assert_equals(1, abort_called);
}
void test_set_errror_handler_fails_on_null()
{
	enum jal_status rval = jalp_set_error_callback(NULL);
	assert_equals(JAL_E_INVAL, rval);
}
void test_set_errror_handler_with_null_does_not_crash_when_error_handler_is_called()
{
	enum jal_status rval = jalp_set_error_callback(NULL);
	assert_equals(JAL_E_INVAL, rval);
	int ret = setjmp(env);
	if (0 == ret) {
		jalp_error_handler(1);
	}
	assert_equals(1, abort_called);
}
void test_set_error_handler_executes_user_handler_and_calls_abort()
{
	assert_equals(0, abort_called);
	assert_equals(0, td_error_handler_called);
	enum jal_status rval = jalp_set_error_callback(&td_error_handler);
	assert_equals(JAL_OK, rval);
	int ret = setjmp(env);
	if (0 == ret) {
		jalp_error_handler(1);
	}
	assert_equals(1, abort_called);
	assert_equals(1, td_error_handler_called);
}
