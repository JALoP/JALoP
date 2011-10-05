/**
 * @file This file contains tests for jaln_digest.c functions.
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

#include "jaln_digest.h"
#include "jaln_context.h"

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#include <test-dept.h>

#define NUM_ALGS 3
static jaln_context *ctx = NULL;

void setup()
{
	ctx = jaln_context_create();
}

void teardown()
{
	jaln_context_destroy(&ctx);
}

void test_register_digest_does_not_permit_null()
{
	/* Registering a NULL digest should fail. */
	assert_equals(JAL_E_INVAL, jaln_register_digest_algorithm(ctx, NULL));
}

void test_register_digest_algorithm()
{
	struct jal_digest_ctx *last = NULL;

	/* Register several different digests. */
	for (int num_algs = 0; num_algs < NUM_ALGS; num_algs++) {
		struct jal_digest_ctx *new_digest = jal_sha256_ctx_create();

		free(new_digest->algorithm_uri);
		new_digest->algorithm_uri = NULL;
		jal_asprintf(&(new_digest->algorithm_uri), "URI: %i", num_algs);

		assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, new_digest));
		assert_equals(num_algs + 1, axl_list_length(ctx->dgst_algs));
		last = axl_list_get_last(ctx->dgst_algs);
		assert_string_equals(new_digest->algorithm_uri, last->algorithm_uri);
	}
}

void test_register_digest_algorithm_permits_duplicates()
{
	/* Register original digest. */
	struct jal_digest_ctx *duplicate_digest = jal_sha256_ctx_create();

	free(duplicate_digest->algorithm_uri);
	duplicate_digest->algorithm_uri = NULL;
	duplicate_digest->algorithm_uri = jal_strdup("Duplicate URI");

	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, duplicate_digest));

	/* Register duplicate digest. */
	struct jal_digest_ctx *duplicate_digest_dup = jal_sha256_ctx_create();

	free(duplicate_digest_dup->algorithm_uri);
	duplicate_digest_dup->algorithm_uri = NULL;
	duplicate_digest_dup->algorithm_uri = jal_strdup("Duplicate URI");

	int num_algs = axl_list_length(ctx->dgst_algs);

	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, duplicate_digest_dup));
	assert_equals(num_algs, axl_list_length(ctx->dgst_algs));
}

void test_register_digest_algorithm_case_insensitive_duplicates()
{
	/* Register original digest. */
	struct jal_digest_ctx *duplicate_digest = jal_sha256_ctx_create();

	free(duplicate_digest->algorithm_uri);
	duplicate_digest->algorithm_uri = NULL;
	duplicate_digest->algorithm_uri = jal_strdup("Case Duplicate URI");

	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, duplicate_digest));

	/* Register duplicate digest. */
	struct jal_digest_ctx *duplicate_digest_dup = jal_sha256_ctx_create();

	free(duplicate_digest_dup->algorithm_uri);
	duplicate_digest_dup->algorithm_uri = NULL;
	duplicate_digest_dup->algorithm_uri = jal_strdup("Case Duplicate URI");

	int num_algs = axl_list_length(ctx->dgst_algs);
	duplicate_digest_dup->algorithm_uri[0] = tolower(duplicate_digest_dup->algorithm_uri[0]);

	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, duplicate_digest_dup));
	assert_equals(num_algs, axl_list_length(ctx->dgst_algs));

	struct jal_digest_ctx *last = NULL;
	last = axl_list_get_last(ctx->dgst_algs);
	assert_string_equals("case Duplicate URI", last->algorithm_uri);
}

