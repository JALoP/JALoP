/**
 * @file jaldb_utils.c This file provides some additional utilities for the db
 * layer.
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
#include "jaldb_utils.h"
#include "jaldb_status.h"
#include "jal_alloc.h"
#include <string.h>
#include <stdlib.h>


enum jaldb_status jaldb_store_confed_sid(DB *db, DB_TXN *txn, const char *remote_host,
		const char *sid, int *db_err_out)
{
	if (!db || !txn || !remote_host || !sid || !db_err_out) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status ret = JALDB_E_DB;
	int err = 0;
	DBT key;
	DBT old_val;
	DBT new_val;

	memset(&key, 0, sizeof(key));
	memset(&old_val, 0, sizeof(old_val));
	memset(&new_val, 0, sizeof(new_val));

	key.data = jal_strdup(remote_host);

	key.size = strlen(remote_host);
	key.flags = DB_DBT_USERMEM;

	new_val.data = jal_strdup(sid);
	new_val.size = strlen(sid);

	old_val.flags = DB_DBT_MALLOC;
	err = db->get(db, txn, &key, &old_val, DB_RMW);
	if ((err != DB_NOTFOUND) && (err != 0)) {
		JALDB_DB_ERR(db, err);
		goto out;
	}
	int update = 1;
	if (err == 0 &&
		jaldb_sid_cmp(new_val.data, new_val.size,
			old_val.data, old_val.size) <= 0) {
		update = 0;
	}
	if (!update) {
		ret = JALDB_E_ALREADY_CONFED;
		goto out;
	}
	err = db->put(db, txn, &key, &new_val,0);
	if (err != 0) {
		JALDB_DB_ERR(db, err);
		goto out;
	}
	ret = JALDB_OK;
out:
	free(key.data);
	free(new_val.data);
	free(old_val.data);
	*db_err_out = err;
	return ret;
}

int jaldb_sid_cmp(const char *sid1, size_t s1_len, const char* sid2, size_t s2_len)
{
	if (s1_len < s2_len) {
		return -1;
	}
	if (s1_len > s2_len) {
		return 1;
	}
	return strcmp(sid1, sid2);
}

