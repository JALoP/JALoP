/**
 * @file jalp_content_type.c This file defines functions to deal adding
 * "content-type" information.
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
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jalp_structured_data.h>
#include "jalp_alloc.h"

struct jalp_content_type *jalp_content_type_create(void)
{
	struct jalp_content_type *new_content_type = jalp_calloc(1, sizeof(*new_content_type));
	// pick a sane default for media_type
	new_content_type->media_type = JALP_MT_APPLICATION;
	return new_content_type;
}

void jalp_content_type_destroy(struct jalp_content_type **content_type)
{
	if (!content_type || !(*content_type)) {
		return;
	}
	free((*content_type)->subtype);
	jalp_param_destroy(&(*content_type)->params);
	free(*content_type);
	*content_type = NULL;
}

