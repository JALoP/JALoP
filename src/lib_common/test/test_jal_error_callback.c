/**
 * @file This file contains tests for the jal error handler.
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
#include <setjmp.h>
#include <signal.h>
#include <test-dept.h>
#include <jalop/jal_error_callback.h>

#include "jal_error_callback_internal.h"

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
		jal_error_handler(1);
	}
	assert_equals(1, abort_called);
}
void test_set_errror_handler_fails_on_null()
{
	enum jal_status rval = jal_set_error_callback(NULL);
	assert_equals(JAL_E_INVAL, rval);
}
void test_set_errror_handler_with_null_does_not_crash_when_error_handler_is_called()
{
	enum jal_status rval = jal_set_error_callback(NULL);
	assert_equals(JAL_E_INVAL, rval);
	int ret = setjmp(env);
	if (0 == ret) {
		jal_error_handler(1);
	}
	assert_equals(1, abort_called);
}
void test_set_error_handler_executes_user_handler_and_calls_abort()
{
	assert_equals(0, abort_called);
	assert_equals(0, td_error_handler_called);
	enum jal_status rval = jal_set_error_callback(&td_error_handler);
	assert_equals(JAL_OK, rval);
	int ret = setjmp(env);
	if (0 == ret) {
		jal_error_handler(1);
	}
	assert_equals(1, abort_called);
	assert_equals(1, td_error_handler_called);
}
