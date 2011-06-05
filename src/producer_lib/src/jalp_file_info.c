/**
 * @file jalp_file_info.c This file has functions for creating and destroying
 * jalp_file_info structures.
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

struct jalp_file_info *jalp_file_info_create(void)
{
	struct jalp_file_info *file_info = NULL;
	file_info = jal_malloc(sizeof(*file_info));

	file_info->original_size = 0;
	file_info->size = 0;
	file_info->filename = NULL;
	file_info->threat_level = JAL_THREAT_UNKNOWN;
	file_info->content_type = NULL;

	return file_info;
}

void jalp_file_info_destroy(struct jalp_file_info **file_info)
{
	if (!file_info || !(*file_info)) {
		return;
	}

	free((*file_info)->filename);
	jalp_content_type_destroy(&(*file_info)->content_type);

	*file_info = NULL;
}
