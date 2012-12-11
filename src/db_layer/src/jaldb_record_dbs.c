/**
 * @file jaldb_record_dbs.c This file provides the implementation of
 * functions related to jaldb_record_dbs objects.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <db.h>

#include "jal_alloc.h"

#include "jaldb_record_dbs.h"

struct jaldb_record_dbs *jaldb_create_record_dbs()
{
	struct jaldb_record_dbs *ret = (struct jaldb_record_dbs*) jal_calloc(1, sizeof(*ret));
	return ret;
}

void jaldb_destroy_record_dbs(struct jaldb_record_dbs **record_dbs)
{
	if (!record_dbs || !*record_dbs) {
		return;
	}

	struct jaldb_record_dbs *rdbs = *record_dbs;

	// According to BDB documentation, secondary databases should be closed
	// before the primary. Any new indices must be closed before the
	// primary_db is closed.

	if (rdbs->timestamp_tz_idx_db) {
		rdbs->timestamp_tz_idx_db->close(rdbs->timestamp_tz_idx_db, 0);
	}
	if (rdbs->timestamp_no_tz_idx_db) {
		rdbs->timestamp_no_tz_idx_db->close(rdbs->timestamp_no_tz_idx_db, 0);
	}
	if (rdbs->record_id_idx_db) {
		rdbs->record_id_idx_db->close(rdbs->record_id_idx_db, 0);
	}
	if (rdbs->sid_db) {
		rdbs->sid_db->close(rdbs->sid_db, 0);
	}
	if (rdbs->primary_db) {
		rdbs->primary_db->close(rdbs->primary_db, 0);
	}
	free(rdbs);
	*record_dbs = NULL;
}

