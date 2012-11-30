/**
 * @file jaldb_record.c This file contains functions related to the
 * jaldb_record structure.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include "jaldb_record.h"
#include "jaldb_segment.h"

struct jaldb_record *jaldb_create_record()
{
	struct jaldb_record *ret = jal_calloc(1, sizeof(*ret));
	ret->version = JALDB_RECORD_VERSION;
	ret->type = JALDB_RTYPE_UNKNOWN;
	uuid_clear(ret->uuid);
	return ret;
}

void jaldb_destroy_record(struct jaldb_record **pprecord)
{
	if (!pprecord || !*pprecord) {
		return;
	}

	struct jaldb_record *rec = *pprecord;
	jaldb_destroy_segment(&(rec->sys_meta));
	jaldb_destroy_segment(&(rec->app_meta));
	jaldb_destroy_segment(&(rec->payload));
	free(rec->source);
	free(rec->hostname);
	free(rec->timestamp);
	free(rec->username);
	free(rec->sec_lbl);
	free(rec);
	*pprecord = NULL;
}

