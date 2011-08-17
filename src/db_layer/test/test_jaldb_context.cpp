/**
 * @file test_jaldb_context.cpp This file contains functions to test jaldb_context.
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

#include "jaldb_context.h"
#include "jaldb_context.hpp"
#include <xercesc/util/PlatformUtils.hpp>

XERCES_CPP_NAMESPACE_USE

#define OTHER_DB_ROOT "./testdb/"
#define OTHER_SCHEMA_ROOT "./schemas/"
#define JOURNAL_ROOT "/journal/"

extern "C" void setup()
{
}

extern "C" void teardown()
{
	XMLPlatformUtils::Terminate();
}

extern "C" void test_db_destroy_does_not_crash()
{
	jaldb_context *ctx = NULL;
	jaldb_context_destroy(&ctx);

	jaldb_context_destroy(NULL);
}
extern "C" void test_db_destroy_sets_ctx_to_null()
{
	jaldb_context *ctx = jaldb_context_create();
	assert_not_equals((void*) NULL, ctx);
	enum jaldb_status ret = jaldb_context_init(ctx, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT);
	assert_equals(JALDB_OK, ret);
	jaldb_context_destroy(&ctx);
	assert_pointer_equals((void*) NULL, ctx);
}
