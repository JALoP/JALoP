/**
 * @file jalp_transform.c This file has functions for creating and destroying
 * jalp_transform structures.
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


#include <jalop/jalp_journal_metadata.h>
#include "jal_alloc.h"


struct jalp_transform *jalp_transform_append(struct jalp_transform *prev,
		char *uri, char *xml_snippet)
{
	if (!uri) {
		return NULL;
	}

	struct jalp_transform *transform = NULL;
	transform = jal_malloc(sizeof(*transform));

	transform->uri = jal_strdup(uri);
	transform->xml = jal_strdup(xml_snippet);

	if (prev) {
		transform->next = prev->next;
		prev->next = transform;
	} else {
		transform->next = NULL;
	}

	return transform;
}

void jalp_transform_destroy_one(struct jalp_transform *transform)
{
	free(transform->uri);
	free(transform->xml);
	free(transform);
}

void jalp_transform_destroy(struct jalp_transform **transform)
{
	if (!transform || !(*transform)) {
		return;
	}

	struct jalp_transform *cur = *transform;
	while(cur) {
		struct jalp_transform *next = cur->next;
		jalp_transform_destroy_one(cur);
		cur = next;
	}

	*transform = NULL;
}
