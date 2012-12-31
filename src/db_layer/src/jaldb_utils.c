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
#include "jaldb_utils.h"
#include "jaldb_status.h"
#include "jal_alloc.h"
#include "jal_fs_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <jalop/jal_status.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

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
	new_val.size = strlen(sid) + 1;

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

enum jaldb_status jaldb_create_file(
	const char *db_root,
	char **relative_path_out,
	int *fd)
{
	if (!db_root || !relative_path_out || *relative_path_out || !fd) {
		return JALDB_E_INVAL;
	}
	// This is for the string 'yyyy/mm/dd/journal.XXXXXX'
	#define TEMPLATE_LEN 26
	enum jaldb_status ret = JALDB_E_INTERNAL_ERROR;
	enum jal_status jal_ret = JAL_E_INVAL;

	time_t current_time;
	struct tm gmt;
	char *full_path = NULL;
	char *template = NULL;
	int written = -1;
	int len = -1;
	int lfd = -1;

	current_time = time(NULL);
	if (current_time == (time_t) -1) {
		// should never happen for gettimeofday
		goto error_out;
	}

	memset(&gmt, 0, sizeof(gmt));
	if (NULL == gmtime_r(&current_time, &gmt)) {
		// should never happen
		goto error_out;
	}
	template = (char*) jal_malloc(TEMPLATE_LEN);
	if (0 == strftime(template, TEMPLATE_LEN, "%Y/%m/%d/journal.XXXXXX", &gmt)) {
		// a return of 0 is an error in this case, but it should never
		// happen.
		goto error_out;
	}
	len = strlen(db_root) + 1 + TEMPLATE_LEN;
	full_path = (char*) jal_malloc(len);
	written = snprintf(full_path, len, "%s/%s", db_root, template);
	if (written >= len) {
		// shouldn't happen since the size of full_path was calculated
		// based on db_root & template
		goto error_out;
	}
	jal_ret = jal_create_dirs(full_path);
	if (JAL_OK != jal_ret) {
		goto error_out;
	}
	ret = JALDB_OK;
	lfd = mkstemp(full_path);
	if (lfd == -1) {
		ret = JALDB_E_INTERNAL_ERROR;
		goto error_out;
	}
	memcpy(template, full_path + strlen(db_root) + 1, TEMPLATE_LEN);
	goto out;
error_out:
	free(template);
	template = NULL;
	if (lfd > -1) {
		close(lfd);
		lfd = -1;
	}
out:
	*relative_path_out = template;
	free(full_path);
	*fd = lfd;
	return ret;
}

char *jaldb_gen_timestamp()
{
	char *ftime = (char*)jal_malloc(26);
	char *tz_offset = (char*)jal_malloc(7);
	time_t rawtime;
	struct tm *tm;

	time(&rawtime);
	tm = localtime(&rawtime);
	strftime(ftime, 26, "%Y-%m-%dT%H:%M:%S", tm);

	/* Timezone
	 * Inserts ':' into [+-]HHMM for [+-]HH:MM */
	strftime(tz_offset, 7, "%z", tm);
	tz_offset[6] = '\0';
	tz_offset[5] = tz_offset[4];
	tz_offset[4] = tz_offset[3];
	tz_offset[3] = ':';

	strcat(ftime, tz_offset);
	free(tz_offset);

	return ftime;
}

