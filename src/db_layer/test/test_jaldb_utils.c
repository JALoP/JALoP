/**
 * @file test_jaldb_utils.c This file contains functions to test jaldb_utils.c.
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

#include <db.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <test-dept.h>
#include <time.h>
#include <unistd.h>
#include <jalop/jal_status.h>
#include <fcntl.h>

#include "jal_alloc.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "test_utils.h"
#include "jaldb_context.h"

#define OTHER_DB_ROOT "./testdb/"

static DB_ENV *env = NULL;
static DB *dbase = NULL;

time_t time_always_fails(__attribute__((unused)) time_t *timer)
{
	return -1;
}

void setup()
{
	struct stat st;
	if (stat(OTHER_DB_ROOT, &st) != 0) {
		(void)mkdir(OTHER_DB_ROOT, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}
	else {
		struct dirent *d;
		DIR *dir;
		char buf[sizeof(OTHER_DB_ROOT) + sizeof(d->d_name)];
		dir = opendir(OTHER_DB_ROOT);
		while ((d = readdir(dir)) != NULL) {
			sprintf(buf, "%s/%s", OTHER_DB_ROOT, d->d_name);
			remove(buf);
		}
		(void)closedir(dir);
	}
	uint32_t env_flags = DB_CREATE |
		DB_INIT_LOCK |
		DB_INIT_LOG |
		DB_INIT_MPOOL |
		DB_INIT_TXN |
		DB_THREAD;
	(void)db_env_create(&env, 0);
	(void)env->open(env, OTHER_DB_ROOT, env_flags, 0);
}

void teardown()
{
	if (dbase) {
		dbase->close(dbase, 0);
	}
	dbase = NULL;
	env->close(env, 0);
	env = NULL;
}

void test_store_confed_nonce_returns_ok_with_valid_input()
{
	DB_TXN *transaction = NULL;
	int db_error = env->txn_begin(env, NULL, &transaction, 0);
	db_error = db_create(&dbase, env, 0);
	db_error = dbase->open(dbase, transaction, JALDB_CONF_DB, NULL, DB_BTREE, DB_CREATE, 0);
	char *rhost = jal_strdup("remote_host");
	char *nonce = jal_strdup("1234");
	int err = 0;
	int *db_error_out = &err;
	int ret = jaldb_store_confed_nonce(dbase, transaction, rhost, nonce, db_error_out);
	transaction->commit(transaction, 0);
	DBT key;
	DBT data;
	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));
	key.data = jal_strdup(rhost);
	key.size = strlen(rhost);
	key.flags = DB_DBT_USERMEM;
	data.flags = DB_DBT_MALLOC;
	db_error = dbase->get(dbase, NULL, &key, &data, 0);
	assert_equals(0, db_error);
	int result;
	result = strncmp("1234", data.data, strlen("1234"));
	assert_equals(0, result);
	free(rhost);
	free(nonce);
	free(data.data);
	free(key.data);
	rhost = NULL;
	nonce = NULL;
	data.data = NULL;

	assert_equals(JALDB_OK, ret);
}

void test_store_confed_nonce_returns_error_when_trying_to_insert_nonce_twice()
{
	DB_TXN *transaction = NULL;
	(void)env->txn_begin(env, NULL, &transaction, 0);
	(void)db_create(&dbase, env, 0);
	(void)dbase->open(dbase, transaction, JALDB_CONF_DB, NULL, DB_BTREE, DB_CREATE, 0);
	char *rhost = jal_strdup("remote_host");
	char *nonce = jal_strdup("1234");
	int err = 0;
	int *db_error_out = &err;
	int ret = jaldb_store_confed_nonce(dbase, transaction, rhost, nonce, db_error_out);
	assert_equals(JALDB_OK, ret);

	char *nonce2 = jal_strdup("1234");
	ret = jaldb_store_confed_nonce(dbase, transaction, rhost, nonce2, db_error_out);
	transaction->commit(transaction, 0);
	free(rhost);
	free(nonce);
	free(nonce2);
	rhost = NULL;
	nonce = NULL;
	nonce2 = NULL;
	assert_equals(JALDB_E_ALREADY_CONFED, ret);
}

void test_store_confed_nonce_returns_error_with_invalid_input()
{
	DB_TXN *transaction = NULL;
	(void)env->txn_begin(env, NULL, &transaction, 0);
	(void)db_create(&dbase, env, 0);
	(void)dbase->open(dbase, transaction, JALDB_CONF_DB, NULL, DB_BTREE, DB_CREATE, 0);
	char *rhost = jal_strdup("remote_host");
	char *nonce = jal_strdup("1234");
	int err = 0;
	int *db_error_out = &err;
	int ret = jaldb_store_confed_nonce(NULL, transaction, rhost, nonce, db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_nonce(dbase, NULL, rhost, nonce, db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_nonce(dbase, transaction, NULL, nonce, db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_nonce(dbase, transaction, rhost, NULL, db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_nonce(dbase, transaction, rhost, nonce, NULL);
	transaction->commit(transaction, 0);
	free(rhost);
	free(nonce);
	rhost = NULL;
	nonce= NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

void test_nonce_cmp_returns_correct_value()
{
	(void)db_create(&dbase, env, 0);
	(void)dbase->open(dbase, NULL, JALDB_CONF_DB, NULL, DB_BTREE, DB_CREATE, 0);
	const char *s1 = "12345";
	size_t slen1 = strlen(s1);
	const char *s2 = "1234";
	size_t slen2 = strlen(s2);
	int ret = jaldb_nonce_cmp(s1, slen1, s2, slen2);
	assert_equals(1, ret);

	const char *s3 = "2345";
	slen1 = strlen(s3);
	const char *s4 = "23456";
	slen2 = strlen(s4);
	ret = jaldb_nonce_cmp(s3, slen1, s4, slen2);
	assert_equals(-1, ret);

	const char *s5 = "3456";
	slen1 = strlen(s5);
	const char *s6 = "3456";
	slen2 = strlen(s6);
	ret = jaldb_nonce_cmp(s5, slen1, s6, slen2);
	assert_equals(0, ret);
}

int open_always_fails(__attribute__((unused)) const char *path, __attribute__((unused)) int oflag, ... )
{
	return -1;
}

void test_jaldb_create_file_returns_cleanly_when_open_fails()
{
	replace_function(open, open_always_fails);
	char *path = NULL;
	int fd = -1;
	uuid_t uuid,uuid_orig;
	uuid_generate(uuid);
	uuid_copy(uuid_orig,uuid);
	enum jaldb_status ret = jaldb_create_file("/tmp/", &path, &fd,uuid,JALDB_RTYPE_AUDIT,JALDB_DTYPE_SYS_META);
	assert_equals(JALDB_E_INTERNAL_ERROR, ret);
	assert_pointer_equals((void*) NULL, path);
	assert_equals(-1, fd);
	assert_equals(uuid_compare(uuid,uuid_orig),0);

	// When this particular failure occurs, the subdirectory /tmp/XX where XX is the first
	// two characters in uuid will still happen as a side effect, but path is left as NULL
	// So we have to rebuild the directory name ourselves
	const int UUID_LEN = 37;
	char *uuid_string = jal_calloc(UUID_LEN,sizeof(char));
	uuid_unparse(uuid,uuid_string);

	char* dir_path = NULL;
	int dir_path_len = strlen("/tmp/XX/") + 1;
	dir_path = jal_calloc(dir_path_len, sizeof(char));
	strcpy(dir_path, "/tmp/");
	strncat(dir_path, uuid_string, 2);
	dir_path[dir_path_len-1] = '/';

	// Remove this directory
	remove(dir_path);
	free(dir_path);
	free(uuid_string);
	restore_function(open);
}

void test_jaldb_create_file_returns_cleanly_when_db_root_is_null()
{
	char *path = NULL;
	int fd = -1;
	uuid_t uuid,uuid_orig;
	uuid_generate(uuid);
	uuid_copy(uuid_orig,uuid);
	enum jaldb_status ret = jaldb_create_file(NULL, &path, &fd,uuid,JALDB_RTYPE_AUDIT,JALDB_DTYPE_SYS_META);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, path);
	assert_equals(-1, fd);
	assert_equals(uuid_compare(uuid,uuid_orig),0);
}

void test_jaldb_create_file_returns_cleanly_when_rtype_is_unknown()
{
	char *path = NULL;
	int fd = -1;
	uuid_t uuid,uuid_orig;
	uuid_generate(uuid);
	uuid_copy(uuid_orig,uuid);
	enum jaldb_status ret = jaldb_create_file("/tmp/", &path, &fd,uuid,JALDB_RTYPE_UNKNOWN,JALDB_DTYPE_SYS_META);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, path);
	assert_equals(-1, fd);
	assert_equals(uuid_compare(uuid,uuid_orig),0);
}


void test_jaldb_create_file_works()
{
	char *path = NULL;
	char *full_path = NULL;
	int fd = -1;
	uuid_t uuid, uuid_orig;
	uuid_generate(uuid);
	uuid_copy(uuid_orig,uuid);

	enum jaldb_status ret = jaldb_create_file("/tmp/",&path,&fd,uuid,JALDB_RTYPE_AUDIT,JALDB_DTYPE_SYS_META);
	assert_equals(JAL_OK,ret);
	assert_equals(uuid_compare(uuid,uuid_orig),0);
	assert_not_equals(fd,-1);
	assert_not_equals(path, NULL);

	full_path = jal_calloc(strlen(path)+6,sizeof(char));
	snprintf(full_path,strlen(path)+6,"/tmp/%s",path);

	// Ensure the file was created
	assert_equals(access(full_path,F_OK),0);
	// Remove the file
	remove(full_path);

	// truncate to just the /tmp/XX portion by finding the last / and replacing it with 0
	char* lastSlash = strrchr(full_path, '/');
	assert_not_equals(NULL, lastSlash);
	// Sanity checks to make sure we don't try to remove /tmp
	assert_not_equals(strlen("/tmp/"), strlen(full_path));
	assert_not_equals(strlen("/tmp"), strlen(full_path));
	*lastSlash = 0;

	// remove the temporary directory /tmp/XX
	remove(full_path);

	free(full_path);
	free(path);
}

void test_jaldb_gen_timestamp_works()
{
	char *timestamp = jaldb_gen_timestamp();
	assert_not_equals(NULL,timestamp);
	struct tm time;
	int ms;

	char *end_timestamp = strptime(timestamp, "%Y-%m-%dT%H:%M:%S", &time);

	assert_not_equals(NULL,end_timestamp);

	assert_equals(1,sscanf(end_timestamp,".%d-%*d:%*d",&ms));

}
