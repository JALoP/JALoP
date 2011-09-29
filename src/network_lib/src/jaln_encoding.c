/**
 * @file jaln_encodings.c This file contains function definitions for code related
 * to the XML encodings
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
#include "jal_alloc.h"
#include "jaln_context.h"
#include "jaln_encoding.h"

int jaln_string_list_case_insensitive_func(axlPointer a, axlPointer b)
{
	char *str_a = (char *)a;
	char *str_b = (char *)b;
	return strcasecmp(str_a, str_b);
}

int jaln_register_encoding(jaln_context *ctx,
				const char *encoding)
{
	if (!ctx || !ctx->xml_encodings || !encoding) {
		return JAL_E_INVAL;
	}
	char *enc_to_insert = jal_strdup(encoding);

	axl_list_remove(ctx->xml_encodings, enc_to_insert);
	axl_list_append(ctx->xml_encodings, enc_to_insert);

	return JAL_OK;
}
