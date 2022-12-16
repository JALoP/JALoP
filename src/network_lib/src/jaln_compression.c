/**
 * @file jaln_compression.c This file contains function definitions for code related
 * to the XML compressions
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
#include "jal_alloc.h"
#include "jaln_compression.h"
#include "jaln_context.h"

int jaln_string_list_case_insensitive_func(axlPointer a, axlPointer b)
{
	char *str_a = (char *)a;
	char *str_b = (char *)b;
	return strcasecmp(str_a, str_b);
}

int jaln_register_compression(jaln_context *ctx,
				const char *compression)
{
	if (!ctx || !ctx->xml_compressions || !compression) {
		return JAL_E_INVAL;
	}
	char *cmp_to_insert = jal_strdup(compression);

	axl_list_remove(ctx->xml_compressions, cmp_to_insert);
	axl_list_append(ctx->xml_compressions, cmp_to_insert);

	return JAL_OK;
}

axl_bool jaln_string_list_case_insensitive_lookup_func(axlPointer ptr, axlPointer data)
{
	if (ptr && data) {
		return 0 == jaln_string_list_case_insensitive_func(ptr, data);
	}
	if (ptr) {
		return axl_false;
	}
	if (data) {
		return axl_false;
	}
	return axl_true;
}

enum jal_status jaln_axl_string_list_to_array(axlList *list,
		char ***arr_out,
		int *size_out)
{
	if (!list || !arr_out || *arr_out || !size_out) {
		return JAL_E_INVAL;
	}
	int sz = axl_list_length(list);
	char **arr = jal_calloc(sz, sizeof(char*));
	axlListCursor *cursor = axl_list_cursor_new(list);
	axl_list_cursor_first(cursor);
	int idx = 0;
	while (axl_list_cursor_has_item(cursor)) {
		char *str = (char*) axl_list_cursor_get(cursor);
		if (str) {
			arr[idx] = jal_strdup(str);
		}
		axl_list_cursor_next(cursor);
		idx++;
	}
	axl_list_cursor_free(cursor);
	*arr_out = arr;
	*size_out = sz;
	return JAL_OK;
}

void jaln_string_array_destroy(char ***parr, int arr_size)
{
	if (!parr || !*parr || 0 > arr_size) {
		return;
	}
	char **arr = *parr;
	for (int i = 0; i < arr_size; i++) {
		free(arr[i]);
	}
	free(arr);
	(*parr) = NULL;
}
