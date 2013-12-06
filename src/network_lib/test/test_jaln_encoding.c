/**
 * @file test_jaln_encoding.c This file contains tests for jaln_encoding.c functions.
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

#include "jaln_context.h"
#include "jaln_encoding.h"

#define NUM_ENCS 3
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

void test_register_encoding_does_not_permit_null()
{
	/* Registering a NULL encoding should fail. */
	assert_equals(JAL_E_INVAL, jaln_register_encoding(ctx, NULL));
}

void test_register_encoding()
{
	char *last = NULL;

	/* Register several different encodings. */
	for (int num_encs = 0; num_encs < NUM_ENCS; num_encs++) {
		char *new_enc = NULL;
		jal_asprintf(&new_enc, "Encoding %i", num_encs);

		assert_equals(JAL_OK, jaln_register_encoding(ctx, new_enc));
		assert_equals(num_encs + 1, axl_list_length(ctx->xml_encodings));
		last = axl_list_get_last(ctx->xml_encodings);
		assert_not_equals(new_enc, last);
		assert_string_equals(new_enc, last);

		free(new_enc);
	}
}

void test_register_encoding_permits_duplicates()
{
	/* Register original encoding. */
	const char duplicate_enc[] = "Duplicate Encoding";

	assert_equals(JAL_OK, jaln_register_encoding(ctx, duplicate_enc));

	/* Register duplicate encoding. */
	int num_encs = axl_list_length(ctx->xml_encodings);

	assert_equals(JAL_OK, jaln_register_encoding(ctx, duplicate_enc));
	assert_equals(num_encs, axl_list_length(ctx->xml_encodings));
}

void test_register_encoding_case_insensitive_duplicates()
{
	/* Register original encoding. */
	const char duplicate_enc[] = "Case Duplicate Encoding";
	const char duplicate_enc_alt[] = "case duplicate encoding";

	assert_equals(JAL_OK, jaln_register_encoding(ctx, duplicate_enc));

	/* Register duplicate encoding. */
	int num_encs = axl_list_length(ctx->xml_encodings);

	assert_equals(JAL_OK, jaln_register_encoding(ctx, duplicate_enc_alt));
	assert_equals(num_encs, axl_list_length(ctx->xml_encodings));

	char *last = NULL;
	last = axl_list_get_last(ctx->xml_encodings);
	assert_string_equals(duplicate_enc_alt, last);
}

void test_compare_encoding_case_insensitive_lookup_where_text_exists_same_case()
{
	/* Register original encoding. */
	char *enc1 = strdup("some TexT");
	char *enc2 = strdup("some texT");
	char *enc3 = strdup("some more TexT");
	char *enc4 = strdup("some TexT more");

	// Add some string values to the axl encoding list of ctx
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc1));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc2));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc3));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->xml_encodings,
			jaln_string_list_case_insensitive_lookup_func,
			enc1);

	assert_not_equals(ptr, NULL);

	free(enc1);
	free(enc2);
	free(enc3);
	free(enc4);
}

void test_compare_encoding_case_insensitive_lookup_where_text_exists_diff_case()
{
	/* Register original encoding. */
	char *enc1 = strdup("some TexT");
	char *enc2 = strdup("some texT");
	char *enc3 = strdup("some more TexT");
	char *enc4 = strdup("some TexT more");
	char *enc5 = strdup("SoMe tEXt");

	// Add some string values to the axl encoding list of ctx
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc1));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc2));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc3));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->xml_encodings,
			jaln_string_list_case_insensitive_lookup_func,
			enc5);

	assert_not_equals(ptr, NULL);

	free(enc1);
	free(enc2);
	free(enc3);
	free(enc4);
	free(enc5);
}

void test_compare_encoding_case_insensitive_lookup_where_text_not_exists()
{
	/* Register original encoding. */
	char *enc1 = strdup("some TexT");
	char *enc2 = strdup("some texT");
	char *enc3 = strdup("some more TexT");
	char *enc4 = strdup("some TexT more");
	char *enc5 = strdup("uh OH!");

	// Add some string values to the axl encoding list of ctx
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc1));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc2));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc3));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->xml_encodings,
			jaln_string_list_case_insensitive_lookup_func,
			enc5);

	assert_equals(ptr, NULL);

	free(enc1);
	free(enc2);
	free(enc3);
	free(enc4);
	free(enc5);
}

void test_compare_encoding_case_insensitive_lookup_where_partial_text_exists()
{
	/* Register original encoding. */
	char *enc1 = strdup("some TexT");
	char *enc2 = strdup("some texT");
	char *enc3 = strdup("some more TexT");
	char *enc4 = strdup("some TexT more");
	char *enc5 = strdup("some ");

	// Add some string values to the axl encoding list of ctx
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc1));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc2));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc3));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->xml_encodings,
			jaln_string_list_case_insensitive_lookup_func,
			enc5);

	assert_equals(ptr, NULL);

	free(enc1);
	free(enc2);
	free(enc3);
	free(enc4);
	free(enc5);
}

void test_compare_encoding_case_insensitive_lookup_where_list_null()
{
	/* Register original encoding. */
	char *enc1 = strdup("some TexT");
	char *enc2 = strdup("some texT");
	char *enc3 = strdup("some more TexT");
	char *enc4 = strdup("some TexT more");

	// Add some string values to the axl encoding list of ctx
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc1));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc2));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc3));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(NULL,
			jaln_string_list_case_insensitive_lookup_func,
			enc4);

	assert_equals(ptr, NULL);

	free(enc1);
	free(enc2);
	free(enc3);
	free(enc4);
}

void test_compare_encoding_case_insensitive_lookup_where_text_null()
{
	/* Register original encoding. */
	char *enc1 = strdup("some TexT");
	char *enc2 = strdup("some texT");
	char *enc3 = strdup("some more TexT");
	char *enc4 = strdup("some TexT more");
	char *enc5 = NULL;

	// Add some string values to the axl encoding list of ctx
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc1));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc2));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc3));
	assert_equals(JAL_OK, jaln_register_encoding(ctx, enc4));

	axlPointer ptr = NULL;

	ptr = axl_list_lookup(ctx->xml_encodings,
			jaln_string_list_case_insensitive_lookup_func,
			enc5);

	assert_equals(ptr ,NULL);

	free(enc1);
	free(enc2);
	free(enc3);
	free(enc4);
	free(enc5);
}

void test_compare_encoding_case_insensitive_lookup_where_null_vs_null()
{
	char *valA = NULL;
	char *valB = NULL;
	
	// NULL and NULL are considered the same, therefore expect a true result.
	assert_equals(axl_true, jaln_string_list_case_insensitive_lookup_func(valA,valB));
}

void test_compare_encoding_case_insensitive_lookup_where_text_vs_null()
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

