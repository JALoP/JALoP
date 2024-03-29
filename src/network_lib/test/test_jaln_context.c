/**
 * @file test_jaln_context.c This file contains tests for jaln_context.c functions.
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
#include <test-dept.h>
#include <string.h>

#include "jaln_context.h"
#include "jaln_session.h"

#define HOSTNAME_1 "192.168.1.1"
#define HOSTNAME_2 "192.168.1.2"

static jaln_context *ctx = NULL;
static jaln_session *sess = NULL;
static char *hostname_1 = NULL;
static char *hostname_2 = NULL;
void setup()
{
	ctx = jaln_context_create();

	sess = jaln_session_create();
	sess->ch_info->hostname = strdup(HOSTNAME_1);
	hostname_1 = strdup(HOSTNAME_1);
	hostname_2 = strdup(HOSTNAME_2);
}

void teardown()
{
	jaln_context_destroy(&ctx);
	jaln_session_destroy(&sess);
	free(hostname_1);
	free(hostname_2);
}

void test_context_create()
{
	assert_not_equals((void*) NULL, ctx);
	assert_equals((void*) NULL, ctx->pub_callbacks);
	assert_equals((void*) NULL, ctx->conn_callbacks);
	assert_not_equals((void*) NULL, ctx->dgst_algs);
	assert_not_equals((void*) NULL, ctx->xml_compressions);
	assert_equals(1, ctx->ref_cnt);
	assert_false(ctx->is_connected);
}

void test_context_destroy_does_not_crash()
{
	jaln_context *null_ctx = NULL;
	jaln_context_destroy(NULL);
	jaln_context_destroy(&null_ctx);
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
