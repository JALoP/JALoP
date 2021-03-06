/**
 * @file test_jaldb_nonce.c This file contains functions to test
 * functions related to acquiring a serial id.
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

#include <test-dept.h>

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <db.h>

#include "jaldb_nonce.h"
static DB *nonce_db;
static DBT nonce_dbt1;
static DBT nonce_dbt2;
static DBT nonce_dbt3;
static DBT nonce_dbt4;

#define NONCE1 "9b5754ef-ce82-4dd2-af61-d329cc526203_2013-11-20T09:12:34.12345_1234_12345"
#define NONCE2 "9b5754ef-ce82-4dd2-af61-d329cc526203_2013-11-20T09:12:34.12345_1234_1234567"
#define NONCE3 "9b5754ef-ce82-4dd2-af61-d329cc526203_2013-11-20T09:12:34.12345_1234_12346"
#define NONCE4 "9c5754ef-ce82-4dd2-af61-d329cc526203_2013-11-20T09:12:34.12345_1234_12345"

void setup()
{
	int err = db_create(&nonce_db, NULL, 0);
	assert_equals(0, err);
	assert_not_equals((void*) NULL, nonce_db);
	err = nonce_db->open(nonce_db, NULL, NULL, NULL, DB_BTREE, DB_CREATE, 0600);
	assert_equals(0, err);

	memset(&nonce_dbt1, 0, sizeof(DBT));
	nonce_dbt1.data = NONCE1;
	nonce_dbt1.size = strlen(NONCE1) + 1;

	memset(&nonce_dbt2, 0, sizeof(DBT));
	nonce_dbt2.data = NONCE2;
	nonce_dbt2.size = strlen(NONCE2) + 1;

	memset(&nonce_dbt3, 0, sizeof(DBT));
	nonce_dbt3.data = NONCE3;
	nonce_dbt3.size = strlen(NONCE3) + 1;

	memset(&nonce_dbt4, 0, sizeof(DBT));
	nonce_dbt4.data = NONCE4;
	nonce_dbt4.size = strlen(NONCE4) + 1;
}

void teardown()
{
	nonce_db->close(nonce_db, 0);
}

// Sanity check that the comparison function matches the Berkeley DB signature.
void test_nonce_compare_prototype_is_valid()
{
	DB *db;
	int db_err;
	db_err = db_create(&db, NULL, 0);
	assert_equals(0, db_err);

	db_err = db->set_bt_compare(db, jaldb_nonce_compare);
	assert_equals(0, db_err);

	db->close(db, DB_NOSYNC);
}

void test_nonce_compare_works()
{
	// nonces should sort in order 1,2,3,4
	assert_true(0 > jaldb_nonce_compare(NULL, &nonce_dbt1, &nonce_dbt2));
	assert_true(0 > jaldb_nonce_compare(NULL, &nonce_dbt2, &nonce_dbt3));
	assert_true(0 > jaldb_nonce_compare(NULL, &nonce_dbt3, &nonce_dbt4));
	assert_true(0 > jaldb_nonce_compare(NULL, &nonce_dbt1, &nonce_dbt4));
	assert_true(0 > jaldb_nonce_compare(NULL, &nonce_dbt2, &nonce_dbt4));
	assert_true(0 > jaldb_nonce_compare(NULL, &nonce_dbt1, &nonce_dbt3));

	assert_true(0 == jaldb_nonce_compare(NULL, &nonce_dbt1, &nonce_dbt1));
	assert_true(0 == jaldb_nonce_compare(NULL, &nonce_dbt2, &nonce_dbt2));
	assert_true(0 == jaldb_nonce_compare(NULL, &nonce_dbt3, &nonce_dbt3));
	assert_true(0 == jaldb_nonce_compare(NULL, &nonce_dbt4, &nonce_dbt4));

	assert_true(0 < jaldb_nonce_compare(NULL, &nonce_dbt4, &nonce_dbt3));
	assert_true(0 < jaldb_nonce_compare(NULL, &nonce_dbt4, &nonce_dbt2));
	assert_true(0 < jaldb_nonce_compare(NULL, &nonce_dbt4, &nonce_dbt1));
	assert_true(0 < jaldb_nonce_compare(NULL, &nonce_dbt3, &nonce_dbt2));
	assert_true(0 < jaldb_nonce_compare(NULL, &nonce_dbt3, &nonce_dbt1));
	assert_true(0 < jaldb_nonce_compare(NULL, &nonce_dbt2, &nonce_dbt1));

}
