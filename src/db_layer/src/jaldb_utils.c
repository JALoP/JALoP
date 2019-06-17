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
 * Copyright (c) 2011-2013 Tresys Technology LLC, Columbia, Maryland, USA
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
#include "jal_asprintf_internal.h"
#include "jal_fs_utils.h"
#include "jaldb_context.h"
#include "jaldb_record_dbs.h"

#include <errno.h>
#include <fcntl.h>
#include <jalop/jal_status.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <db.h>
#include <pthread.h>

#include <stdlib.h>

#define UUID_STR_LEN 37

enum jaldb_status jaldb_store_confed_nonce(DB *db, DB_TXN *txn, const char *remote_host,
		const char *nonce, int *db_err_out)
{
	if (!db || !txn || !remote_host || !nonce || !db_err_out) {
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

	new_val.data = jal_strdup(nonce);
	new_val.size = strlen(nonce) + 1;

	old_val.flags = DB_DBT_MALLOC;
	err = db->get(db, txn, &key, &old_val, DB_RMW);
	if ((err != DB_NOTFOUND) && (err != 0)) {
		JALDB_DB_ERR(db, err);
		goto out;
	}
	int update = 1;
	if (err == 0 &&
		jaldb_nonce_cmp(new_val.data, new_val.size,
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

int jaldb_nonce_cmp(const char *nonce1, size_t s1_len, const char* nonce2, size_t s2_len)
{
	if (s1_len < s2_len) {
		return -1;
	}
	if (s1_len > s2_len) {
		return 1;
	}
	return strcmp(nonce1, nonce2);
}

enum jaldb_status jaldb_create_file(
	const char *db_root,
	char **relative_path_out,
	int *fd,
	uuid_t uuid,
	enum jaldb_rec_type rtype,
	enum jaldb_data_type dtype)
{
	if (!db_root || !relative_path_out || *relative_path_out || !fd || uuid_is_null(uuid) || rtype == JALDB_RTYPE_UNKNOWN) {
		return JALDB_E_INVAL;
	}

	#define UUID_STRING_REP_LEN 37

	// First two hexidecimal characters of UUID as directory + /
	#define DIRPATH_LEN 3

	//TYPE_LEN is long enough to hold "_journal_sys_meta", which is the longest type name
	#define TYPE_LEN 17

	#define FILENAME_LEN UUID_STRING_REP_LEN + TYPE_LEN + 1

	#define REL_PATH_LEN DIRPATH_LEN + FILENAME_LEN

	enum jaldb_status ret = JALDB_E_INTERNAL_ERROR;
	enum jal_status jal_ret = JAL_E_INVAL;

	char *full_path = NULL;
	char *suffix = NULL;
	int root_len = -1;
	int lfd = -1;
	char *uuid_string = jal_calloc(UUID_STRING_REP_LEN,sizeof(char));
	uuid_unparse(uuid,uuid_string);

	root_len = strlen(db_root);

	full_path = (char *) jal_calloc(root_len+REL_PATH_LEN,sizeof(char));

	strcpy(full_path,db_root);

	int path_pos = root_len;

	// Grab the first two digits of the uuid for the directory to create
	full_path[path_pos++] = uuid_string[0];
	full_path[path_pos++] = uuid_string[1];
	full_path[path_pos++] = '/';

	suffix = jal_calloc(FILENAME_LEN,sizeof(char));

	
	if (rtype == JALDB_RTYPE_JOURNAL)
	{
		strcpy(suffix,"journal");
	}
	else if (rtype == JALDB_RTYPE_AUDIT)
	{
		strcpy(suffix,"audit");
	}
	else if (rtype == JALDB_RTYPE_LOG)
	{
		strcpy(suffix,"log");
	}
	else
	{
		ret = JALDB_E_INVAL;
		goto error_out;
	}

	if (dtype == JALDB_DTYPE_SYS_META)
	{
		strcat(suffix,"_sys_meta_");
	}
	else if (dtype == JALDB_DTYPE_APP_META)
	{
		strcat(suffix,"_app_meta_");
	}
	else if (dtype == JALDB_DTYPE_PAYLOAD)
	{
		strcat(suffix,"_payload_");
	}
	else
	{
		ret = JALDB_E_INVAL;
		goto error_out;
	}
	strcat(suffix,uuid_string);

	jal_ret = jal_create_dirs(full_path);
	if (JAL_OK != jal_ret) {
		goto error_out;
	}

	strcat(full_path,suffix);

	// Create the file as read/write with permission mode set to owner read/write
	lfd = open(full_path, O_RDWR | O_CREAT, S_IRUSR|S_IWUSR);
	if (lfd == -1) {
		goto error_out;
	}

	ret = JALDB_OK;
	*relative_path_out = jal_calloc(REL_PATH_LEN,sizeof(char));
	memcpy(*relative_path_out, full_path + root_len, REL_PATH_LEN);
	goto out;

error_out:
	if (lfd > -1) {
		close(lfd);
		lfd = -1;
	}
out:
	free(full_path);
	free(uuid_string);
	free(suffix);
	*fd = lfd;
	return ret;
}

char *jaldb_gen_timestamp()
{
	char *ftime = (char*)jal_malloc(34);
	struct tm *tm = (struct tm*)jal_malloc(sizeof(struct tm));

	struct timeval *tv = jal_malloc(sizeof(struct timeval));

	if (gettimeofday(tv,NULL) || !gmtime_r(&tv->tv_sec, tm)) {
		free(ftime);
		free(tm);
		free(tv);
		return NULL;
	}

	int bytes = strftime(ftime, 26, "%Y-%m-%dT%H:%M:%S", tm);

	snprintf(ftime+bytes,7,".%06ld",tv->tv_usec);

	free(tm);
	free(tv);

	return ftime;
}

char *jaldb_gen_primary_key(uuid_t uuid)
{
	if (uuid_is_null(uuid)) {
		return NULL;
	}

	char uuid_str[UUID_STR_LEN];
	uuid_unparse(uuid,uuid_str);

	char *ts = jaldb_gen_timestamp();
	if (!ts) {
		return NULL;
	}
	pid_t pid = getpid();
	pthread_t tid = pthread_self();//portable
	char *key = NULL;

	jal_asprintf(&key, "%s_%s_%d_%u", uuid_str, ts, pid, tid);

	free(ts);

	return key;
}
