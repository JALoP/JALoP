/**
 * @file test_jaln_compression.c This file contains tests for jaln_compression.c functions.
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


#include <axl.h>
#include <test-dept.h>

#include "jal_asprintf_internal.h"

#include "jaln_compression.h"
#include "jaln_context.h"

#define NUM_CMPS 3
static jaln_context *ctx = NULL;
static axlList *str_list = NULL;
static axlList *empty_str_list = NULL;
static char **arr_out;
static int arr_sz;

void setup()
{
	ctx = jaln_context_create();
	str_list = axl_list_new(jaln_string_list_case_insensitive_func, free);
	axl_list_append(str_list, strdup("foobar"));
	axl_list_append(str_list, strdup("barfoo"));
	axl_list_append(str_list, NULL);

	empty_str_list = axl_list_new(jaln_string_list_case_insensitive_func, free);
	arr_sz = 0;
}

void teardown()
{
	jaln_context_destroy(&ctx);
	axl_list_free(str_list);
	axl_list_free(empty_str_list);

	jaln_string_array_destroy(&arr_out, arr_sz);
}

void test_register_compression_does_not_permit_null()
{
	/* Registering a NULL compression should fail. */
	assert_equals(JAL_E_INVAL, jaln_register_compression(ctx, NULL));
}

void test_register_compression()
{
	char *last = NULL;

	/* Register several different compressions. */
	for (int num_cmps = 0; num_cmps < NUM_CMPS; num_cmps++) {
		char *new_cmp = NULL;
		jal_asprintf(&new_cmp, "Compression %i", num_cmps);

		assert_equals(JAL_OK, jaln_register_compression(ctx, new_cmp));
		assert_equals(num_cmps + 1, axl_list_length(ctx->xml_compressions));
		last = axl_list_get_last(ctx->xml_compressions);
		assert_not_equals(new_cmp, last);
		assert_string_equals(new_cmp, last);

		free(new_cmp);
	}
}

void test_register_compression_permits_duplicates()
{
	/* Register original compression. */
	const char duplicate_cmp[] = "Duplicate Compression";

	assert_equals(JAL_OK, jaln_register_compression(ctx, duplicate_cmp));

	/* Register duplicate compression. */
	int num_cmps = axl_list_length(ctx->xml_compressions);

	assert_equals(JAL_OK, jaln_register_compression(ctx, duplicate_cmp));
	assert_equals(num_cmps, axl_list_length(ctx->xml_compressions));
}

void test_register_compression_case_insensitive_duplicates()
{
	/* Register original compression. */
	const char duplicate_cmp[] = "Case Duplicate Compression";
	const char duplicate_cmp_alt[] = "case duplicate compression";

	assert_equals(JAL_OK, jaln_register_compression(ctx, duplicate_cmp));

	/* Register duplicate compression. */
	int num_cmps = axl_list_length(ctx->xml_compressions);

	assert_equals(JAL_OK, jaln_register_compression(ctx, duplicate_cmp_alt));
	assert_equals(num_cmps, axl_list_length(ctx->xml_compressions));

	char *last = NULL;
	last = axl_list_get_last(ctx->xml_compressions);
	assert_string_equals(duplicate_cmp_alt, last);
}

void test_compare_compression_case_insensitive_lookup_where_text_exists_same_case()
{
	/* Register original compression. */
	char *cmp1 = strdup("some TexT");
	char *cmp2 = strdup("some texT");
	char *cmp3 = strdup("some more TexT");
	char *cmp4 = strdup("some TexT more");

	// Add some string values to the axl compression list of ctx
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp1));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp2));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp3));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->xml_compressions,
			jaln_string_list_case_insensitive_lookup_func,
			cmp1);

	assert_not_equals(ptr, NULL);

	free(cmp1);
	free(cmp2);
	free(cmp3);
	free(cmp4);
}

void test_compare_compression_case_insensitive_lookup_where_text_exists_diff_case()
{
	/* Register original compression. */
	char *cmp1 = strdup("some TexT");
	char *cmp2 = strdup("some texT");
	char *cmp3 = strdup("some more TexT");
	char *cmp4 = strdup("some TexT more");
	char *cmp5 = strdup("SoMe tEXt");

	// Add some string values to the axl compression list of ctx
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp1));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp2));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp3));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->xml_compressions,
			jaln_string_list_case_insensitive_lookup_func,
			cmp5);

	assert_not_equals(ptr, NULL);

	free(cmp1);
	free(cmp2);
	free(cmp3);
	free(cmp4);
	free(cmp5);
}

void test_compare_compression_case_insensitive_lookup_where_text_not_exists()
{
	/* Register original compression. */
	char *cmp1 = strdup("some TexT");
	char *cmp2 = strdup("some texT");
	char *cmp3 = strdup("some more TexT");
	char *cmp4 = strdup("some TexT more");
	char *cmp5 = strdup("uh OH!");

	// Add some string values to the axl compression list of ctx
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp1));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp2));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp3));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->xml_compressions,
			jaln_string_list_case_insensitive_lookup_func,
			cmp5);

	assert_equals(ptr, NULL);

	free(cmp1);
	free(cmp2);
	free(cmp3);
	free(cmp4);
	free(cmp5);
}

void test_compare_compression_case_insensitive_lookup_where_partial_text_exists()
{
	/* Register original compression. */
	char *cmp1 = strdup("some TexT");
	char *cmp2 = strdup("some texT");
	char *cmp3 = strdup("some more TexT");
	char *cmp4 = strdup("some TexT more");
	char *cmp5 = strdup("some ");

	// Add some string values to the axl compression list of ctx
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp1));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp2));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp3));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->xml_compressions,
			jaln_string_list_case_insensitive_lookup_func,
			cmp5);

	assert_equals(ptr, NULL);

	free(cmp1);
	free(cmp2);
	free(cmp3);
	free(cmp4);
	free(cmp5);
}

void test_compare_compression_case_insensitive_lookup_where_list_null()
{
	/* Register original compression. */
	char *cmp1 = strdup("some TexT");
	char *cmp2 = strdup("some texT");
	char *cmp3 = strdup("some more TexT");
	char *cmp4 = strdup("some TexT more");

	// Add some string values to the axl compression list of ctx
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp1));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp2));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp3));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(NULL,
			jaln_string_list_case_insensitive_lookup_func,
			cmp4);

	assert_equals(ptr, NULL);

	free(cmp1);
	free(cmp2);
	free(cmp3);
	free(cmp4);
}

void test_compare_compression_case_insensitive_lookup_where_text_null()
{
	/* Register original compression. */
	char *cmp1 = strdup("some TexT");
	char *cmp2 = strdup("some texT");
	char *cmp3 = strdup("some more TexT");
	char *cmp4 = strdup("some TexT more");
	char *cmp5 = NULL;

	// Add some string values to the axl compression list of ctx
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp1));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp2));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp3));
	assert_equals(JAL_OK, jaln_register_compression(ctx, cmp4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->xml_compressions,
			jaln_string_list_case_insensitive_lookup_func,
			cmp5);

	assert_equals(ptr ,NULL);

	free(cmp1);
	free(cmp2);
	free(cmp3);
	free(cmp4);
	free(cmp5);
}

void test_compare_compression_case_insensitive_lookup_where_null_vs_null()
{
	char *valA = NULL;
	char *valB = NULL;
	
	// NULL and NULL are considered the same, therefore expect a true result.
	assert_equals(axl_true, jaln_string_list_case_insensitive_lookup_func(valA,valB));
}

void test_compare_compression_case_insensitive_lookup_where_text_vs_null()
{
	char *valA = "text!";
	char *valB = NULL;

	assert_equals(axl_false, jaln_string_list_case_insensitive_lookup_func(valA,valB));
	assert_equals(axl_false, jaln_string_list_case_insensitive_lookup_func(valB,valA));
}

void test_string_list_to_array_fails_on_bad_input()
{
	assert_equals(JAL_E_INVAL, jaln_axl_string_list_to_array(NULL, &arr_out, &arr_sz));
	assert_equals(JAL_E_INVAL, jaln_axl_string_list_to_array(str_list, NULL, &arr_sz));
	assert_equals(JAL_E_INVAL, jaln_axl_string_list_to_array(str_list, &arr_out, NULL));

	arr_out = (char**) 0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_axl_string_list_to_array(str_list, &arr_out, &arr_sz));
	arr_out = NULL;

}

void test_string_list_to_array_works_with_non_empty_list()
{
	assert_equals(JAL_OK, jaln_axl_string_list_to_array(str_list, &arr_out, &arr_sz));
	assert_equals(axl_list_length(str_list), arr_sz);
	for(int i = 0; i < axl_list_length(str_list); i++) {
		char *in_list = (char*) axl_list_get_nth(str_list, i);
		if (in_list) {
			assert_not_equals(in_list, arr_out[i]);
			assert_not_equals((void*) NULL, arr_out[i]);
			assert_equals(strlen(in_list), strlen(arr_out[i]));
			assert_equals(0, memcmp(in_list, arr_out[i], strlen(in_list)));
		} else {
			assert_equals((void *) NULL, arr_out[i]);
		}
	}
}

void test_string_list_to_array_works_with_empty()
{
	assert_equals(JAL_OK, jaln_axl_string_list_to_array(empty_str_list, &arr_out, &arr_sz));
	assert_equals(0, arr_sz);
}

void test_string_array_destroy_works()
{
	assert_equals(JAL_OK, jaln_axl_string_list_to_array(str_list, &arr_out, &arr_sz));
	assert_not_equals((void*) NULL, arr_out);
	assert_not_equals(0, arr_sz);
	jaln_string_array_destroy(&arr_out, arr_sz);
	assert_equals((void*) NULL, arr_out);
}

void test_string_array_destroy_does_not_crash_with_bad_input()
{
	arr_sz = 1;
	jaln_string_array_destroy(&arr_out, arr_sz);
	jaln_string_array_destroy(NULL, arr_sz);
}

