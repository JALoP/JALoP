/**
 * @file jalp_structured_data.c This file defines functions to
 * deal with structured_data elements
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as be$
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
#include <jalop/jalp_structured_data.h>
#include "jal_alloc.h"

struct jalp_structured_data *jalp_structured_data_append(struct jalp_structured_data *prev,
                                                         char *sd_id)
{

	if (!sd_id) {
		return NULL;
	}

	struct jalp_structured_data *old_next = NULL;
	struct jalp_structured_data *new_structured_data;
	new_structured_data = jal_calloc(1, sizeof(*new_structured_data));

	if (prev) {
		old_next = prev->next;
		prev->next = new_structured_data;
	}

	new_structured_data->sd_id = jal_strdup(sd_id);
	new_structured_data->next = old_next;

	return new_structured_data;


}
void jalp_structured_data_destroy(struct jalp_structured_data **sd_group)
{
	if (!sd_group || !(*sd_group)) {
		return;
	}

	struct jalp_structured_data * current;
	struct jalp_structured_data * next;

	next = *sd_group;

	while(next) {
		current = next;
		next = current->next;

		free(current->sd_id);
		jalp_param_destroy(&(current->param_list));
		free(current);
	}

	*sd_group = NULL;
}
