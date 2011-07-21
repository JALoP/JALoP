/**
 * @file test_jalp_journal.cpp This file contains functions to test
 * jalp_journal_* functions.
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

// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// c++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
extern "C" {
#include <test-dept.h>
}

// this is needed so that UINT64_MAX is defined
#define __STDC_LIMIT_MACROS
#include <stdint.h>

#include <uuid/uuid.h>
#include <ctype.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_journal.h>
#include "jal_alloc.h"
#include "jalp_connection_internal.h"

jalp_context *ctx;

enum jal_status jalp_send_buffer(
		__attribute__((unused)) jalp_context *jctx,
		__attribute__((unused)) uint16_t message_type,
		__attribute__((unused)) void *data,
		__attribute__((unused)) uint64_t data_len,
		__attribute__((unused)) void *meta,
		__attribute__((unused)) uint64_t meta_len,
		__attribute__((unused)) int fd)
{
	return JAL_OK;
}
extern "C" void setup()
{
	jalp_init();
	ctx = jalp_context_create();
}

extern "C" void teardown()
{
	jalp_context_destroy(&ctx);
	jalp_shutdown();
}

extern "C" void test_journal_fd_fails_with_bad_input()
{
	enum jal_status ret;
	ret = jalp_journal_fd(ctx, NULL, -1);
	assert_equals(JAL_E_INVAL, ret);

	ret = jalp_journal_fd(NULL, NULL, -1);
	assert_equals(JAL_E_INVAL, ret);

}
extern "C" void test_journal_path_fails_with_null_path()
{
	enum jal_status ret;
	ret = jalp_journal_path(ctx, NULL, NULL);
	assert_equals(JAL_E_INVAL, ret);
}
extern "C" void test_journal_path_fails_with_bad_context()
{
	enum jal_status ret;
	ret = jalp_journal_path(NULL, NULL, "./README");
	assert_equals(JAL_E_INVAL, ret);
}
extern "C" void test_journal_path_fails_with_bad_file()
{
	enum jal_status ret;
	ret = jalp_journal_path(NULL, NULL, "./this/file/does/not/exist");
	assert_equals(JAL_E_INVAL, ret);
}
