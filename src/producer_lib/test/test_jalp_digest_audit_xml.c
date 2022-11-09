/**
 * @file test_jalp_digest_audit_xml.c This file contains unit tests for jalp_digest_audit.
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

#include <stdlib.h>
#include <stdio.h>
#include <test-dept.h>
#include <jalop/jalp_context.h>
#include <jalop/jal_digest.h>
#include "jalp_digest_audit_xml.h"
#include "jal_alloc.h"

static struct jal_digest_ctx *ctx = NULL;
static jalp_context *jalp_ctx = NULL;
uint8_t *buffer = NULL;
long buff_len = 0;

void setup()
{
	jalp_init();
	int ret = 0;
	ctx = jal_sha256_ctx_create();
	jalp_ctx = jalp_context_create();
	jalp_context_init(jalp_ctx, NULL, NULL, NULL, NULL);
	jalp_ctx->digest_ctx = ctx;


	FILE *f = NULL;

	f = fopen(TEST_INPUT_ROOT "good_audit_input.xml", "rb");
	assert_not_equals(NULL, f);

	ret = fseek(f, 0, SEEK_END);
	assert_equals(0, ret);

	buff_len = ftell(f);
	assert_true(buff_len > 0);

	ret = fseek(f, 0, SEEK_SET);
	assert_equals(0, ret);

	buffer = (uint8_t *)jal_malloc(buff_len);
	assert_not_equals(NULL, buffer);

	ret = fread(buffer, buff_len, 1, f);
	assert_not_equals(0, ret);

	fclose(f);
}

void setup_bad()
{
	free(buffer);
	int ret = 0;
	FILE *f = NULL;

	f = fopen(TEST_INPUT_ROOT "bad_input.xml", "rb");
	assert_not_equals(NULL, f);

	ret = fseek(f, 0, SEEK_END);
	assert_equals(0, ret);

	buff_len = ftell(f);
	assert_true(buff_len > 0);

	ret = fseek(f, 0, SEEK_SET);
	assert_equals(0, ret);

	buffer = (uint8_t *)jal_malloc(buff_len);
	assert_not_equals(NULL, buffer);

	ret = fread(buffer, buff_len, 1, f);
	assert_not_equals(0, ret);

	fclose(f);
}

void teardown()
{
	free(buffer);
	jal_digest_ctx_destroy(&ctx);
	jalp_shutdown();
}

#if 0
void test_jalp_digest_audit_record_returns_ok_with_valid_input()
{
	uint8_t *dgst = NULL;
	int dgst_len = 0;
	jalp_ctx->schema_root = SCHEMAS_ROOT;
	enum jal_status ret = jalp_digest_audit_record(jalp_ctx,
						buffer,
						buff_len,
						&dgst,
						&dgst_len);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, dgst);
	assert_not_equals(0, dgst_len);
	free(dgst);
}
#endif
void test_jalp_digest_auidit_record_returns_error_with_invalid_input()
{
	setup_bad();
	uint8_t *dgst = NULL;
	int dgst_len = 0;
	jalp_ctx->schema_root = SCHEMAS_ROOT;
	enum jal_status ret = jalp_digest_audit_record(jalp_ctx,
						buffer,
						buff_len,
						&dgst,
						&dgst_len);
	assert_equals(JAL_E_XML_PARSE, ret);
	assert_equals((void*) NULL, dgst);
	assert_equals(0, dgst_len);
}

void test_jalp_digest_audit_record_returns_schema_err_with_invalid_schema_root()
{
	uint8_t *dgst = NULL;
	int dgst_len = 0;
	jalp_ctx->schema_root = "/";
	enum jal_status ret = jalp_digest_audit_record(jalp_ctx,
						buffer,
						buff_len,
						&dgst,
						&dgst_len);
	assert_equals(JAL_E_XML_SCHEMA, ret);
	assert_equals((void*) NULL, dgst);
	assert_equals(0, dgst_len);
}

void test_jalp_digest_audit_record_returns_inval_with_null_ctx()
{
	uint8_t *dgst = NULL;
	int dgst_len = 0;
	jalp_ctx->schema_root = SCHEMAS_ROOT;
	enum jal_status ret = jalp_digest_audit_record(NULL,
						buffer,
						buff_len,
						&dgst,
						&dgst_len);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*) NULL, dgst);
	assert_equals(0, dgst_len);
}

void test_jalp_digest_audit_record_returns_inval_with_null_schema_root()
{
	uint8_t *dgst = NULL;
	int dgst_len = 0;
	jalp_ctx->schema_root = NULL;
	enum jal_status ret = jalp_digest_audit_record(jalp_ctx,
						buffer,
						buff_len,
						&dgst,
						&dgst_len);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*) NULL, dgst);
	assert_equals(0, dgst_len);
}

void test_jalp_digest_audit_record_returns_inval_with_null_buffer()
{
	uint8_t *dgst = NULL;
	int dgst_len = 0;
	jalp_ctx->schema_root = SCHEMAS_ROOT;
	enum jal_status ret = jalp_digest_audit_record(jalp_ctx,
						NULL,
						buff_len,
						&dgst,
						&dgst_len);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*) NULL, dgst);
	assert_equals(0, dgst_len);
}

void test_jalp_digest_audit_record_returns_inval_with_zero_buf_len()
{
	uint8_t *dgst = NULL;
	int dgst_len = 0;
	jalp_ctx->schema_root = SCHEMAS_ROOT;
	enum jal_status ret = jalp_digest_audit_record(jalp_ctx,
						buffer,
						0,
						&dgst,
						&dgst_len);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals((void*) NULL, dgst);
	assert_equals(0, dgst_len);
}

void test_jalp_digest_audit_record_returns_inval_with_dgst_null()
{
	int dgst_len = 0;
	jalp_ctx->schema_root = SCHEMAS_ROOT;
	enum jal_status ret = jalp_digest_audit_record(jalp_ctx,
						buffer,
						buff_len,
						NULL,
						&dgst_len);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(0, dgst_len);
}

void test_jalp_digest_audit_record_returns_inval_with_dgst_ptr_not_null()
{
	uint8_t *dgst = jal_malloc(1);
	int dgst_len = 0;
	jalp_ctx->schema_root = SCHEMAS_ROOT;
	enum jal_status ret = jalp_digest_audit_record(jalp_ctx,
						buffer,
						buff_len,
						&dgst,
						&dgst_len);
	free(dgst);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(0, dgst_len);
}
