/**
 * @file jalp_param.c This file implements functions to
 * deal with the jalp_param data structure.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as b$
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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implie$
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <string.h>
#include <jalop/jalp_structured_data.h>
#include "jalp_alloc.h"

struct jalp_param *jalp_param_insert(struct jalp_param *prev, char *name,
							      char *value)
{
	if (!name || !value) {
		return NULL;
	}

	struct jalp_param *old_next = NULL;
	struct jalp_param *new_jalp_param = jalp_calloc(1, sizeof(*new_jalp_param));
	char *tmp_name = jalp_malloc(strlen(name) + 1);
	char *tmp_value = jalp_malloc(strlen(value) + 1);

	strcpy(tmp_name, name);
	strcpy(tmp_value, value);


	if (prev) {
		old_next = prev->next;
		prev->next = new_jalp_param;
	}

	new_jalp_param->key = tmp_name;
	new_jalp_param->value = tmp_value;
	new_jalp_param->next = old_next;

	return new_jalp_param;

}
void jalp_param_destroy(struct jalp_param **param_list)
{
	struct jalp_param *tmp = (*param_list)->next;
	char *tmp_key = (*param_list)->key;
	char *tmp_value = (*param_list)->value;

	if (tmp) {
		(*param_list)->key = NULL;
		(*param_list)->value = NULL;
		(*param_list)->next = NULL;
		jalp_param_destroy(&tmp);
	}
	free(tmp_key);
	free(tmp_value);

	/* If the linked list was circular, the head of the list won't be
	 * free'd twice. */
	if (tmp_key) {
		free(*param_list);
	}
	*param_list = NULL;
}
