/**
 * @file jalp_journal_metadata.c This file contains functions
 * for jalp_journal_metadata
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below
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
#include "jal_alloc.h"

struct jalp_journal_metadata *jalp_journal_metadata_create(void)
{
	struct jalp_journal_metadata *new_journal_metadata;
	new_journal_metadata = jal_calloc(1, sizeof(*new_journal_metadata));

	return new_journal_metadata;
}
void jalp_journal_metadata_destroy(struct jalp_journal_metadata **journal_meta)
{
	if(!journal_meta || !(*journal_meta)) {
		return;
	}

	jalp_file_info_destroy(&(*journal_meta)->file_info);
	jalp_transform_destroy(&(*journal_meta)->transforms);
	free(*journal_meta);
	*journal_meta = NULL;
}
