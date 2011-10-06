/**
 * @file This file contains tests for jaln_encodings.c functions.
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

#include "jaln_context.h"
#include "jaln_encoding.h"
#include "jal_asprintf_internal.h"

#include <test-dept.h>

#define NUM_ENCS 3
static jaln_context *ctx = NULL;

void setup()
{
	ctx = jaln_context_create();
}

void teardown()
{
	jaln_context_destroy(&ctx);
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

