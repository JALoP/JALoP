/**
 * @file
 *
 * @brief This file provides some additional utilities for the db
 * layer.
 *
 * ### LICENSE
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
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
#include "jal_ts_utils.h"
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
#include <pthread.h>

#include <stdlib.h>

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

	enum jaldb_status ret = JALDB_E_INTERNAL_ERROR;
	enum jal_status jal_ret = JAL_E_INVAL;

	std::string full_path;
	std::string suffix;
	int root_len = -1;
	int lfd = -1;
	char *uuid_string = (char*)jal_calloc(UUID_STRING_REP_LEN+1,sizeof(char)); //add 1 for NULL char
	uuid_unparse(uuid,uuid_string);

	full_path = std::string(db_root);
	root_len = full_path.length();

	// Grab the first two digits of the uuid for the directory to create
	full_path += uuid_string[0];
	full_path += uuid_string[1];
	full_path += '/';

	if (rtype == JALDB_RTYPE_JOURNAL)
	{
		suffix = "journal";
	}
	else if (rtype == JALDB_RTYPE_AUDIT)
	{
		suffix = "audit";
	}
	else if (rtype == JALDB_RTYPE_LOG)
	{
		suffix ="log";
	}
	else
	{
		ret = JALDB_E_INVAL;
		goto error_out;
	}

	if (dtype == JALDB_DTYPE_SYS_META)
	{
		suffix += "_sys_meta_";
	}
	else if (dtype == JALDB_DTYPE_APP_META)
	{
		suffix += "_app_meta_";
	}
	else if (dtype == JALDB_DTYPE_PAYLOAD)
	{
		suffix += "_payload_";
	}
	else
	{
		ret = JALDB_E_INVAL;
		goto error_out;
	}
	suffix += std::string(uuid_string);

	jal_ret = jal_create_dirs(full_path.c_str());
	if (JAL_OK != jal_ret) {
		goto error_out;
	}

	full_path += suffix;

	// Create the file as read/write with permission mode set to owner read/write
	lfd = open(full_path.c_str(), O_RDWR | O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP); // nosemgrep - suppress medium finding
	if (lfd == -1) {
		goto error_out;
	}

	ret = JALDB_OK;
	*relative_path_out = (char *)jal_calloc(full_path.length() - root_len + 1,sizeof(char));
	memcpy(*relative_path_out, full_path.c_str() + root_len, REL_PATH_LEN); // nosemgrep - the copy length is less than or equal to the destination buffer size
	goto out;

error_out:
	if (lfd > -1) {
		close(lfd);
		lfd = -1;
	}
out:
	*fd = lfd;
	free(uuid_string);
	return ret;
}

char *jaldb_gen_primary_key(uuid_t uuid)
{
	if (uuid_is_null(uuid)) {
		return NULL;
	}

	char uuid_str[UUID_STR_LEN];
	uuid_unparse(uuid,uuid_str);

	char *ts = jal_gen_timestamp_usec();
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
