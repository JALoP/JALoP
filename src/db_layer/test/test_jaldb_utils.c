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

#include <test-dept.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <db.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "jal_alloc.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"

#define OTHER_DB_ROOT "./testdb/"

static DB_ENV *env = NULL;
static DB *dbase = NULL;

void setup()
{
	struct stat st;
	if (stat(OTHER_DB_ROOT, &st) != 0) {
		int status;
		status = mkdir(OTHER_DB_ROOT, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}
	else {
		struct dirent *d;
		DIR *dir;
		char buf[256];
		dir = opendir(OTHER_DB_ROOT);
		while ((d = readdir(dir)) != NULL) {
			sprintf(buf, "%s/%s", OTHER_DB_ROOT, d->d_name);
			remove(buf);
		}
		int ret_val;
		ret_val = closedir(dir);
	}
	uint32_t env_flags = DB_CREATE |
		DB_INIT_LOCK |
		DB_INIT_LOG |
		DB_INIT_MPOOL |
		DB_INIT_TXN |
		DB_THREAD;
	int db_error = db_env_create(&env, 0);
	db_error = env->open(env, OTHER_DB_ROOT, env_flags, 0);
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

void test_store_confed_sid_returns_ok_with_valid_input()
{
	DB_TXN *transaction = NULL;
	int db_error = env->txn_begin(env, NULL, &transaction, 0);
	db_error = db_create(&dbase, env, 0);
	db_error = dbase->open(dbase, transaction, JALDB_CONF_DB, NULL, DB_BTREE, DB_CREATE, 0);
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int err = 0;
	int *db_error_out = &err;
	int ret = jaldb_store_confed_sid(dbase, transaction, rhost, ser_id, db_error_out);
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
	free(ser_id);
	free(data.data);
	rhost = NULL;
	ser_id = NULL;
	data.data = NULL;

	assert_equals(JALDB_OK, ret);
}

void test_store_confed_sid_returns_error_when_trying_to_insert_sid_twice()
{
	DB_TXN *transaction = NULL;
	int db_error = env->txn_begin(env, NULL, &transaction, 0);
	db_error = db_create(&dbase, env, 0);
	db_error = dbase->open(dbase, transaction, JALDB_CONF_DB, NULL, DB_BTREE, DB_CREATE, 0);
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int err = 0;
	int *db_error_out = &err;
	int ret = jaldb_store_confed_sid(dbase, transaction, rhost, ser_id, db_error_out);
	assert_equals(JALDB_OK, ret);

	char *serid = jal_strdup("1234");
	ret = jaldb_store_confed_sid(dbase, transaction, rhost, serid, db_error_out);
	transaction->commit(transaction, 0);
	free(rhost);
	free(ser_id);
	free(serid);
	rhost = NULL;
	ser_id = NULL;
	serid = NULL;
	assert_equals(JALDB_E_ALREADY_CONFED, ret);
}

void test_store_confed_sid_returns_error_with_invalid_input()
{
	DB_TXN *transaction = NULL;
	int db_error = env->txn_begin(env, NULL, &transaction, 0);	
	db_error = db_create(&dbase, env, 0);
	db_error = dbase->open(dbase, transaction, JALDB_CONF_DB, NULL, DB_BTREE, DB_CREATE, 0);
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int err = 0;
	int *db_error_out = &err;
	int ret = jaldb_store_confed_sid(NULL, transaction, rhost, ser_id, db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_sid(dbase, NULL, rhost, ser_id, db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_sid(dbase, transaction, NULL, ser_id, db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_sid(dbase, transaction, rhost, NULL, db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_sid(dbase, transaction, rhost, ser_id, NULL);
	transaction->commit(transaction, 0);
	free(rhost);
	free(ser_id);
	rhost = NULL;
	ser_id= NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

void test_sid_cmp_returns_correct_value()
{
	int db_error = db_create(&dbase, env, 0);
	db_error = dbase->open(dbase, NULL, JALDB_CONF_DB, NULL, DB_BTREE, DB_CREATE, 0);
	const char *s1 = "12345";
	size_t slen1 = strlen(s1);
	const char *s2 = "1234";
	size_t slen2 = strlen(s2);
	int ret = jaldb_sid_cmp(s1, slen1, s2, slen2);
	assert_equals(1, ret);

	const char *s3 = "2345";
	slen1 = strlen(s3);
	const char *s4 = "23456";
	slen2 = strlen(s4);
	ret = jaldb_sid_cmp(s3, slen1, s4, slen2);
	assert_equals(-1, ret);

	const char *s5 = "3456";
	slen1 = strlen(s5);
	const char *s6 = "3456";
	slen2 = strlen(s6);
	ret = jaldb_sid_cmp(s5, slen1, s6, slen2);
	assert_equals(0, ret);
}
