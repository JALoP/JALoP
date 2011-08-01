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

#define OTHER_DB_ROOT "/foo/bar/jalop/"
#define OTHER_SCHEMA_ROOT "/foo/bar/jalop/schemas/"

#define DEFAULT_DB_ROOT "/var/lib/jalop/db/"
#define DEFAULT_SCHEMA_ROOT "/usr/local/share/jalop-v1.0/schemas"

#define APP_META_CONT "app_meta.dbxml"
#define SYS_META_CONT "sys_meta.dbxml"

#define AUDIT_APP_CONT "audit_" APP_META_CONT
#define AUDIT_SYS_CONT "audit_" SYS_META_CONT
#define AUDIT_CONT "audit.dbxml"

#define JOURNAL_APP_CONT "journal_" APP_META_CONT
#define JOURNAL_SYS_CONT "journal_" SYS_META_CONT
#define JOURNAL_ROOT "journal/"

#define LOG_APP_CONT "log_" APP_META_CONT
#define LOG_SYS_CONT "log_" SYS_META_CONT
#define LOG_DB "log.db"

extern "C" void setup()
{
}

extern "C" void teardown()
{
	XMLPlatformUtils::Terminate();
}

extern "C" void test_db_create_returns_initialized_struct()
{
	jaldb_context *ctx = jaldb_context_create();
	assert_not_equals((void*) NULL, ctx);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	jaldb_context_destroy(&ctx);
}
extern "C" void test_db_init_returns_an_error_for_null_ctx()
{
	enum jal_status ret = jaldb_context_init(NULL, NULL, NULL);
	assert_equals(JAL_E_INVAL, ret);
}

extern "C" void test_db_init_does_not_double_init()
{
	enum jal_status ret;
	jaldb_context *ctx = jaldb_context_create();

	ctx->manager = (XmlManager*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) 0xbadf00d, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	ctx->manager = NULL;
	jaldb_context_destroy(&ctx);
	ctx = jaldb_context_create();

	ctx->audit_sys_meta_container = (char*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) 0xbadf00d, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	ctx->audit_sys_meta_container = NULL;
	jaldb_context_destroy(&ctx);
	ctx = jaldb_context_create();

	ctx->audit_app_meta_container = (char*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) 0xbadf00d, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	ctx->audit_app_meta_container = NULL;
	jaldb_context_destroy(&ctx);
	ctx = jaldb_context_create();

	ctx->audit_container = (char*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) 0xbadf00d, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	ctx->audit_container = NULL;
	jaldb_context_destroy(&ctx);
	ctx = jaldb_context_create();

	ctx->log_sys_meta_container = (char*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) 0xbadf00d, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	ctx->log_sys_meta_container = NULL;
	jaldb_context_destroy(&ctx);
	ctx = jaldb_context_create();

	ctx->log_app_meta_container = (char*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) 0xbadf00d, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	ctx->log_app_meta_container = NULL;
	jaldb_context_destroy(&ctx);
	ctx = jaldb_context_create();

	ctx->log_db = (char*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) 0xbadf00d, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	ctx->log_db = NULL;
	jaldb_context_destroy(&ctx);
	ctx = jaldb_context_create();

	ctx->journal_sys_meta_container = (char*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) 0xbadf00d, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	ctx->journal_sys_meta_container = NULL;
	jaldb_context_destroy(&ctx);
	ctx = jaldb_context_create();

	ctx->journal_app_meta_container = (char*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) 0xbadf00d, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	ctx->journal_app_meta_container = NULL;
	jaldb_context_destroy(&ctx);
	ctx = jaldb_context_create();

	ctx->journal_root = (char*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) 0xbadf00d, ctx->journal_root);
	assert_pointer_equals((void*) NULL, ctx->schemas_root);
	ctx->journal_root = NULL;
	jaldb_context_destroy(&ctx);
	ctx = jaldb_context_create();

	ctx->schemas_root = (char*) 0xbadf00d;
	ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_E_INITIALIZED, ret);
	assert_pointer_equals((void*) NULL, ctx->manager);
	assert_pointer_equals((void*) NULL, ctx->audit_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->audit_container);
	assert_pointer_equals((void*) NULL, ctx->log_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->log_db);
	assert_pointer_equals((void*) NULL, ctx->journal_sys_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_app_meta_container);
	assert_pointer_equals((void*) NULL, ctx->journal_root);
	assert_pointer_equals((void*) 0xbadf00d, ctx->schemas_root);
	ctx->schemas_root = NULL;
	jaldb_context_destroy(&ctx);
}

extern "C" void test_db_init_initializes_members_with_default_paths()
{
	jaldb_context *ctx = jaldb_context_create();
	assert_not_equals((void*) NULL, ctx);
	enum jal_status ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, ctx->manager);
	assert_string_equals(DEFAULT_DB_ROOT AUDIT_SYS_CONT, ctx->audit_sys_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT AUDIT_APP_CONT, ctx->audit_app_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT AUDIT_CONT, ctx->audit_container);
	assert_string_equals(DEFAULT_DB_ROOT LOG_SYS_CONT, ctx->log_sys_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT LOG_APP_CONT, ctx->log_app_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT LOG_DB, ctx->log_db);
	assert_string_equals(DEFAULT_DB_ROOT JOURNAL_SYS_CONT, ctx->journal_sys_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT JOURNAL_APP_CONT, ctx->journal_app_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT JOURNAL_ROOT, ctx->journal_root);
	assert_string_equals(DEFAULT_SCHEMA_ROOT, ctx->schemas_root);
	jaldb_context_destroy(&ctx);
}

extern "C" void test_db_init_initializes_members_correctly_with_different_db_root()
{
	jaldb_context *ctx = jaldb_context_create();
	assert_not_equals((void*) NULL, ctx);
	enum jal_status ret = jaldb_context_init(ctx, OTHER_DB_ROOT, NULL);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, ctx->manager);
	assert_string_equals(OTHER_DB_ROOT "/" AUDIT_SYS_CONT, ctx->audit_sys_meta_container);
	assert_string_equals(OTHER_DB_ROOT "/" AUDIT_APP_CONT, ctx->audit_app_meta_container);
	assert_string_equals(OTHER_DB_ROOT "/" AUDIT_CONT, ctx->audit_container);
	assert_string_equals(OTHER_DB_ROOT "/" LOG_SYS_CONT, ctx->log_sys_meta_container);
	assert_string_equals(OTHER_DB_ROOT "/" LOG_APP_CONT, ctx->log_app_meta_container);
	assert_string_equals(OTHER_DB_ROOT "/" LOG_DB, ctx->log_db);
	assert_string_equals(OTHER_DB_ROOT "/" JOURNAL_SYS_CONT, ctx->journal_sys_meta_container);
	assert_string_equals(OTHER_DB_ROOT "/" JOURNAL_APP_CONT, ctx->journal_app_meta_container);
	assert_string_equals(OTHER_DB_ROOT "/" JOURNAL_ROOT, ctx->journal_root);
	assert_string_equals(DEFAULT_SCHEMA_ROOT, ctx->schemas_root);
	jaldb_context_destroy(&ctx);
}

extern "C" void test_db_init_initializes_members_correctly_with_different_schema_root()
{
	jaldb_context *ctx = jaldb_context_create();
	assert_not_equals((void*) NULL, ctx);
	enum jal_status ret = jaldb_context_init(ctx, NULL, OTHER_SCHEMA_ROOT);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, ctx->manager);
	assert_string_equals(DEFAULT_DB_ROOT AUDIT_SYS_CONT, ctx->audit_sys_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT AUDIT_APP_CONT, ctx->audit_app_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT AUDIT_CONT, ctx->audit_container);
	assert_string_equals(DEFAULT_DB_ROOT LOG_SYS_CONT, ctx->log_sys_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT LOG_APP_CONT, ctx->log_app_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT LOG_DB, ctx->log_db);
	assert_string_equals(DEFAULT_DB_ROOT JOURNAL_SYS_CONT, ctx->journal_sys_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT JOURNAL_APP_CONT, ctx->journal_app_meta_container);
	assert_string_equals(DEFAULT_DB_ROOT JOURNAL_ROOT, ctx->journal_root);
	assert_string_equals(OTHER_SCHEMA_ROOT, ctx->schemas_root);
	jaldb_context_destroy(&ctx);

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
	enum jal_status ret = jaldb_context_init(ctx, NULL, NULL);
	assert_equals(JAL_OK, ret);
	jaldb_context_destroy(&ctx);
	assert_pointer_equals((void*) NULL, ctx);
}
