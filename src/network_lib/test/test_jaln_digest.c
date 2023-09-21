/**
 * @file test_jaln_digest.c This file contains tests for jaln_digest.c functions.
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
	for (int num_algs = 0; num_algs < JAL_DIGEST_ALGORITHM_COUNT; num_algs++) {
		struct jal_digest_ctx *new_digest = jal_digest_ctx_create(num_algs);

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
	struct jal_digest_ctx *duplicate_digest = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(duplicate_digest->algorithm_uri);
	duplicate_digest->algorithm_uri = NULL;
	duplicate_digest->algorithm_uri = jal_strdup("Duplicate URI");

	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, duplicate_digest));

	/* Register duplicate digest. */
	struct jal_digest_ctx *duplicate_digest_dup = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

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
	struct jal_digest_ctx *duplicate_digest = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(duplicate_digest->algorithm_uri);
	duplicate_digest->algorithm_uri = NULL;
	duplicate_digest->algorithm_uri = jal_strdup("Case Duplicate URI");

	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, duplicate_digest));

	/* Register duplicate digest. */
	struct jal_digest_ctx *duplicate_digest_dup = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

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

void test_compare_encoding_case_insensitive_where_text_exists_same_case()
{
	// Value we are looking for
	char *dig5 = "some text";

	/* Register digests. */
	struct jal_digest_ctx *dig1 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig1->algorithm_uri);
	dig1->algorithm_uri = NULL;
	dig1->algorithm_uri = jal_strdup("some TexT");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig1));

	struct jal_digest_ctx *dig2 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig2->algorithm_uri);
	dig2->algorithm_uri = NULL;
	dig2->algorithm_uri = jal_strdup("some text");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig2));

	struct jal_digest_ctx *dig3 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig3->algorithm_uri);
	dig3->algorithm_uri = NULL;
	dig3->algorithm_uri = jal_strdup("some more TexT");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig3));

	struct jal_digest_ctx *dig4 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig4->algorithm_uri);
	dig4->algorithm_uri = NULL;
	dig4->algorithm_uri = jal_strdup("some TexT more");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->dgst_algs, jaln_digest_lookup_func, dig5);

	assert_not_equals(ptr, NULL);
}

void test_compare_encoding_case_insensitive_where_text_exists_diff_case()
{
	// Value we are looking for
	char *dig5 = "SoMe tEXt";

	/* Register digests. */
	struct jal_digest_ctx *dig1 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig1->algorithm_uri);
	dig1->algorithm_uri = NULL;
	dig1->algorithm_uri = jal_strdup("some TexT");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig1));

	struct jal_digest_ctx *dig2 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig2->algorithm_uri);
	dig2->algorithm_uri = NULL;
	dig2->algorithm_uri = jal_strdup("some text");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig2));

	struct jal_digest_ctx *dig3 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig3->algorithm_uri);
	dig3->algorithm_uri = NULL;
	dig3->algorithm_uri = jal_strdup("some more TexT");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig3));

	struct jal_digest_ctx *dig4 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig4->algorithm_uri);
	dig4->algorithm_uri = NULL;
	dig4->algorithm_uri = jal_strdup("some TexT more");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->dgst_algs, jaln_digest_lookup_func, dig5);

	assert_not_equals(ptr, NULL);
}

void test_compare_encoding_case_insensitive_where_text_not_exists()
{
	char *dig5 = "Uh Oh!";

	/* Register digests. */
	struct jal_digest_ctx *dig1 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig1->algorithm_uri);
	dig1->algorithm_uri = NULL;
	dig1->algorithm_uri = jal_strdup("some TexT");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig1));

	struct jal_digest_ctx *dig2 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig2->algorithm_uri);
	dig2->algorithm_uri = NULL;
	dig2->algorithm_uri = jal_strdup("some text");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig2));

	struct jal_digest_ctx *dig3 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig3->algorithm_uri);
	dig3->algorithm_uri = NULL;
	dig3->algorithm_uri = jal_strdup("some more TexT");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig3));

	struct jal_digest_ctx *dig4 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig4->algorithm_uri);
	dig4->algorithm_uri = NULL;
	dig4->algorithm_uri = jal_strdup("some TexT more");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->dgst_algs, jaln_digest_lookup_func, dig5);

	assert_equals(ptr, NULL);
}

void test_compare_encoding_case_insensitive_where_partial_text_exists()
{
	char *dig5 = "some ";

	/* Register digests. */
	struct jal_digest_ctx *dig1 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig1->algorithm_uri);
	dig1->algorithm_uri = NULL;
	dig1->algorithm_uri = jal_strdup("some TexT");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig1));

	struct jal_digest_ctx *dig2 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig2->algorithm_uri);
	dig2->algorithm_uri = NULL;
	dig2->algorithm_uri = jal_strdup("some text");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig2));

	struct jal_digest_ctx *dig3 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig3->algorithm_uri);
	dig3->algorithm_uri = NULL;
	dig3->algorithm_uri = jal_strdup("some more TexT");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig3));

	struct jal_digest_ctx *dig4 = jal_digest_ctx_create(JAL_DIGEST_ALGORITHM_DEFAULT);

	free(dig4->algorithm_uri);
	dig4->algorithm_uri = NULL;
	dig4->algorithm_uri = jal_strdup("some TexT more");
	assert_equals(JAL_OK, jaln_register_digest_algorithm(ctx, dig4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->dgst_algs, jaln_digest_lookup_func, dig5);

	assert_equals(ptr, NULL);
}

void test_compare_encoding_case_insensitive_where_list_null()
{
	char *dig1 = "wouldn't this be a suprise!";

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(NULL, jaln_digest_lookup_func, dig1);

	assert_equals(ptr, NULL);
}

void test_compare_encoding_case_insensitive_where_text_null()
{
	char *dig1 = NULL;

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->dgst_algs, jaln_digest_lookup_func, dig1);

	assert_equals(ptr, NULL);
}

void test_compare_digest_insensitive_when_digest_is_null()
{
	assert_false(jaln_digest_lookup_func(NULL, "some_dgst"));
}


