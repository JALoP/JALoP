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
#include <dirent.h>
#include <db.h>
#include "jal_alloc.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"

#define OTHER_DB_ROOT "./testdb/"

DB_ENV *env = NULL;
DB *dbase = NULL;

void setup()
{
	struct dirent *d;
	DIR *dir;
	char buf[256];
	dir = opendir(OTHER_DB_ROOT);
	while ((d = readdir(dir)) != NULL) {
		sprintf(buf, "%s/%s", OTHER_DB_ROOT, d->d_name);
		remove(buf);
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
	printf("Key: %s\n", (char *)key.data);
	printf("Data: %s\n", (char *)data.data);
	free(data.data);
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
	assert_equals(JALDB_E_INVAL, ret);
}

void test_sid_cmp_returns_correct_value()
{
	int db_error = db_create(&dbase, env, 0);
	db_error = dbase->open(dbase, NULL, JALDB_CONF_DB, NULL, DB_BTREE, DB_CREATE, 0);
	const char *s1 = jal_strdup("12345");
	size_t s1len = strlen(s1);
	const char *s2 = jal_strdup("1234");
	size_t s2len = strlen(s2);
	int ret = jaldb_sid_cmp(s1, s1len, s2, s2len);
	assert_equals(1, ret);

	s1 = jal_strdup("2345");
	s1len = strlen(s1);
	s2 = jal_strdup("23456");
	s2len = strlen(s2);
	ret = jaldb_sid_cmp(s1, s1len, s2, s2len);
	assert_equals(-1, ret);

	s1 = jal_strdup("3456");
	s1len = strlen(s1);
	s2 = jal_strdup("3456");
	s2len = strlen(s2);
	ret = jaldb_sid_cmp(s1, s1len, s2, s2len);
	assert_equals(0, ret);
}
