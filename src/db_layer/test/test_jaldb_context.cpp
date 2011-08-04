/**
 * @file test_jaldb_context.cpp This file contains functions to test
 * jaldb_context.cpp.
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
// C++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif

extern "C" {
#include <test-dept.h>
}

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <db.h>
#include "jal_alloc.h"
#include "jaldb_context.h"
#include "jaldb_context.hpp"
#include <xercesc/util/PlatformUtils.hpp>
#include "jaldb_strings.h"
#include "jaldb_utils.h"

#define OTHER_DB_ROOT "./testdb/"
#define OTHER_SCHEMA_ROOT "./schemas/"
#define JOURNAL_ROOT "/journal/"

XERCES_CPP_NAMESPACE_USE
using namespace DbXml;

static jaldb_context *context = NULL;

extern "C" void setup()
{
	XMLPlatformUtils::Initialize();
	struct stat st;
	if (stat(OTHER_DB_ROOT, &st) != 0) {
		int status;
		status = mkdir(OTHER_DB_ROOT, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}
	else {
		struct dirent *d;
		DIR *dir;
		char buf[256];
		dir = opendir(OTHER_DB_ROOT);
		while ((d = readdir(dir)) != NULL) {
			sprintf(buf, "%s/%s", OTHER_DB_ROOT, d->d_name);
			remove(buf);
		}
		int ret_val;
		ret_val = closedir(dir);
	}
	context = jaldb_context_create();
	jaldb_context_init(context, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, true);
}

extern "C" void teardown()
{
	jaldb_context_destroy(&context);
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
	enum jaldb_status ret = jaldb_context_init(ctx, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, false);
	assert_equals(JALDB_OK, ret);
	jaldb_context_destroy(&ctx);
	assert_pointer_equals((void*) NULL, ctx);
}

extern "C" void test_store_confed_journal_sid_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_journal_sid(NULL, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *tmp_mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_store_confed_journal_sid(context, rhost, ser_id, &db_error_out);
	context->manager = tmp_mgr;
	free(rhost);
	free(ser_id);
	rhost = NULL;
	ser_id = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_store_confed_audit_sid_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_audit_sid(NULL, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *tmp_mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_store_confed_audit_sid(context, rhost, ser_id, &db_error_out);
	context->manager = tmp_mgr;
	assert_equals(JALDB_E_INVAL, ret);

	XmlContainer *tmp_cont = context->audit_sys_cont;
	context->audit_sys_cont = NULL;
	ret = jaldb_store_confed_audit_sid(context, rhost, ser_id, &db_error_out);
	context->audit_sys_cont = tmp_cont;
	free(rhost);
	free(ser_id);
	rhost = NULL;
	ser_id = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_store_confed_log_sid_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_log_sid(NULL, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *tmp_mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_store_confed_log_sid(context, rhost, ser_id, &db_error_out);
	context->manager = tmp_mgr;
	free(rhost);
	free(ser_id);
	rhost = NULL;
	ser_id = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_store_confed_sid_helper_returns_ok_with_valid_input()
{
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlDocument doc = context->audit_sys_cont->getDocument(JALDB_SERIAL_ID_DOC_NAME, 0);
	XmlValue attrVal(XmlValue::STRING, "12345");
	doc.setMetaData(JALDB_NS, JALDB_SERIAL_ID_NAME, attrVal);
	context->audit_sys_cont->updateDocument(doc, uc);
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("123");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_OK, ret);

	char *serid = jal_strdup("124");
	ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, serid, &db_error_out);
	free(rhost);
	free(ser_id);
	free(serid);
	rhost = NULL;
	ser_id = NULL;
	serid = NULL;
	assert_equals(JALDB_OK, ret);
}

extern "C" void test_store_confed_sid_helper_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_sid_helper(
		NULL, context->audit_conf_db, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, NULL, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, ser_id, NULL);
	free(rhost);
	free(ser_id);
	rhost = NULL;
	ser_id = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_store_confed_sid_helper_fails_with_sid_greater_than_or_equal_to_next_sid()
{
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlDocument doc = context->audit_sys_cont->getDocument(JALDB_SERIAL_ID_DOC_NAME, 0);
	XmlValue attrVal(XmlValue::STRING, "12345");
	doc.setMetaData(JALDB_NS, JALDB_SERIAL_ID_NAME, attrVal);
	context->audit_sys_cont->updateDocument(doc, uc);
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("123456");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_E_SID, ret);

	char *serid = jal_strdup("12345");
	ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, serid, &db_error_out);
	free(rhost);
	free(ser_id);
	free(serid);
	rhost = NULL;
	ser_id = NULL;
	serid = NULL;
	assert_equals(JALDB_E_SID, ret);
}
