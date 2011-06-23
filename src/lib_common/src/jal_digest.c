/**
 * @file jal_digest.c This file contains functions for dealing with the
 * jal_digest_ctx struct.
 *
 * @section LICENSE
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

#include <jalop/jal_digest.h>
#include "jal_alloc.h"

struct jal_digest_ctx *jal_digest_ctx_create()
{
	struct jal_digest_ctx *new_digest_ctx;
	new_digest_ctx = jal_calloc(1, sizeof(*new_digest_ctx));
	return new_digest_ctx;
}

void jal_digest_ctx_destroy(struct jal_digest_ctx **digest_ctx)
{
	if (!digest_ctx || !*digest_ctx) {
		return;
	}
	free(*digest_ctx);
	*digest_ctx = 0;
}
