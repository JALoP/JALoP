/**
 * @file This file contains tests for jaln_context.c functions.
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

#include <jalop/jaln_network.h>
#include "jaln_context.h"

#include <test-dept.h>
#include <string.h>

static jaln_context *ctx = NULL;
void setup()
{
	ctx = jaln_context_create();
}

void teardown()
{
	jaln_context_destroy(&ctx);
}

void test_context_create()
{
	assert_not_equals((void*) NULL, ctx);
	assert_equals((void*) NULL, ctx->pub_callbacks);
	assert_equals((void*) NULL, ctx->sub_callbacks);
	assert_equals((void*) NULL, ctx->conn_callbacks);
	assert_not_equals((void*) NULL, ctx->dgst_algs);
	assert_not_equals((void*) NULL, ctx->xml_encodings);
	assert_equals(1, ctx->ref_cnt);
	assert_not_equals((void*)NULL, ctx->sha256_digest);
}

void test_context_destroy_does_not_crash()
{
	struct jaln_context_t *ctx = NULL;
	jaln_context_destroy(NULL);
	jaln_context_destroy(&ctx);
}

void test_ref_and_unref_work()
{
	assert_equals(1, ctx->ref_cnt);
	jaln_ctx_ref(ctx);
	assert_equals(2, ctx->ref_cnt);

	jaln_ctx_unref(ctx);
	assert_equals(1, ctx->ref_cnt);
	jaln_ctx_unref(ctx);
	// The second unref should destroy the ctx, run on valgrind to check
	// for leaks.
	ctx = NULL;
}
