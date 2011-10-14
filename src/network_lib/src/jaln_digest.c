/**
 * @file jaln_digest.c This file contains function definitions for code related
 * to the digest used during JALoP communications.
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
#include "jaln_encoding.h"

void jaln_digest_list_destroy(axlPointer ptr)
{
	struct jal_digest_ctx *ctx = (struct jal_digest_ctx*)ptr;
	jal_digest_ctx_destroy(&ctx);
}

int jaln_digest_list_equal_func(axlPointer a, axlPointer b)
{
	struct jal_digest_ctx *dgst_a = (struct jal_digest_ctx*)a;
	struct jal_digest_ctx *dgst_b = (struct jal_digest_ctx*)b;
	return strcasecmp(dgst_a->algorithm_uri, dgst_b->algorithm_uri);
}

axl_bool jaln_digest_lookup_func(axlPointer ptr, axlPointer data)
{
	struct jal_digest_ctx *dgst = (struct jal_digest_ctx*)ptr;
	if (dgst == NULL) {
		return axl_false;
	}
	return 0 == jaln_string_list_case_insensitive_func(dgst->algorithm_uri, data);
}
