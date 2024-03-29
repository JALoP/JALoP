/**
 * @file jalp_param.c This file implements functions to
 * deal with the jalp_param data structure.
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

#include <stdlib.h>
#include <string.h>
#include <jalop/jalp_structured_data.h>
#include "jal_alloc.h"

struct jalp_param *jalp_param_append(struct jalp_param *prev, const char *name,
							      const char *value)
{
	if (!name || !value) {
		return NULL;
	}

	struct jalp_param *old_next = NULL;
	struct jalp_param *new_jalp_param;
	new_jalp_param = jal_malloc(sizeof(*new_jalp_param));

	if (prev) {
		old_next = prev->next;
		prev->next = new_jalp_param;
	}

	new_jalp_param->key = jal_strdup(name);
	new_jalp_param->value = jal_strdup(value);
	new_jalp_param->next = old_next;

	return new_jalp_param;

}

struct jalp_param *jalp_param_update(struct jalp_param *prev, const char *name,
							      const char *value)
{
	if (!name || !value) {
		return NULL;
	}
	struct jalp_param *cur_param = prev;

	while (cur_param) {
		if (0 == strcmp(cur_param->key, name)) { /* Key found, update value. */
			free(cur_param->value);
			cur_param->value = jal_strdup(value);
			return cur_param;
		} else {                             /* Check the next param. */
			if (cur_param != prev) {
				prev = cur_param;
			}
			cur_param = cur_param->next;
		}
	}

	/* No matching param found, create a new one and append. */
	struct jalp_param *new_param = NULL;
	new_param = jal_malloc(sizeof(*new_param));
	new_param->key = jal_strdup(name);
	new_param->value = jal_strdup(value);
	new_param->next = NULL;
	prev->next = new_param;

	return new_param;
}

void jalp_param_destroy(struct jalp_param **param_list)
{
	if (!param_list || !*param_list) {
		return;
	}

	struct jalp_param *current;
	struct jalp_param *next = *param_list;

	while (next) {
		current = next;
		next = current->next;
		free(current->key);
		free(current->value);
		free(current);
	}


	*param_list = NULL;
}
