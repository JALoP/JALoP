/**
 * @file test_jaldb_serial_id.c This file contains functions to test
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
#include <openssl/bn.h>

#include <test-dept.h>

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <db.h>

#include "jaldb_serial_id.h"
static DB *sid_db;
static BIGNUM *bn_one;
static BIGNUM *bn_two;
static DBT dbt_one;
static DBT dbt_two;
static DBT nonce_dbt1;
static DBT nonce_dbt2;
static DBT nonce_dbt3;
static DBT nonce_dbt4;
static uint8_t one;
static uint8_t two;

#define NONCE1 "9b5754ef-ce82-4dd2-af61-d329cc526203_2013-11-20T09:12:34.12345_1234_12345"
#define NONCE2 "9b5754ef-ce82-4dd2-af61-d329cc526203_2013-11-20T09:12:34.12345_1234_1234567"
#define NONCE3 "9b5754ef-ce82-4dd2-af61-d329cc526203_2013-11-20T09:12:34.12345_1234_12346"
#define NONCE4 "9c5754ef-ce82-4dd2-af61-d329cc526203_2013-11-20T09:12:34.12345_1234_12345"

void setup()
{
	int err = db_create(&sid_db, NULL, 0);
	assert_equals(0, err);
	assert_not_equals((void*) NULL, sid_db);
	err = sid_db->open(sid_db, NULL, NULL, NULL, DB_BTREE, DB_CREATE, 0600);
	assert_equals(0, err);

	one = 1;
	bn_one = BN_bin2bn(&one, sizeof(one), NULL);
	assert_not_equals((void*) NULL, bn_one);
	dbt_one.data = &one;
	dbt_one.size = sizeof(one);

	two = 2;
	bn_two = BN_bin2bn(&two, sizeof(two), NULL);
	assert_not_equals((void*) NULL, bn_two);
	dbt_two.data = &two;
	dbt_two.size = sizeof(two);

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
	sid_db->close(sid_db, 0);
	BN_free(bn_one);
	BN_free(bn_two);
}


void test_sid_compare()
{
#define BN_MAX_BYTES 64
	DBT dbt1, dbt2;
	BIGNUM *bn1p = NULL;
	BIGNUM *bn2p = NULL;
	//BN_init(bn1p);
	//BN_init(bn2p);
	unsigned char bn1bytes[BN_MAX_BYTES];
	unsigned char bn2bytes[BN_MAX_BYTES];
	int err;
	int bn1size;
	int bn2size;
	err = BN_dec2bn(&bn1p, "123456789012343567890123456789012345678901234567890");
	assert_not_equals(0, err);
	err = BN_dec2bn(&bn2p, "123456789012343567890123456789012345678901234567891");
	assert_not_equals(0, err);

	bn1size = BN_num_bytes(bn1p);
	assert_true((bn1size <= BN_MAX_BYTES));
	BN_bn2bin(bn1p, bn1bytes);
	dbt1.data = bn1bytes;
	dbt1.size = bn1size;

	bn2size = BN_num_bytes(bn2p);
	assert_true((bn2size <= BN_MAX_BYTES));
	BN_bn2bin(bn2p, bn2bytes);
	dbt2.data = bn2bytes;
	dbt2.size = bn2size;

	err = jaldb_sid_compare(NULL, &dbt1, &dbt2);
	assert_true((err < 0));

	err = jaldb_sid_compare(NULL, &dbt2, &dbt1);
	assert_true((err > 0));

	err = jaldb_sid_compare(NULL, &dbt1, &dbt1);
	assert_equals(0, err);

	BN_free(bn1p);
	BN_free(bn2p);

#undef BN_MAX_BYTES
}

// Sanity check that the comparison function matches the Berkeley DB signature.
void test_sid_compare_prototype_is_valid()
{
	DB *db;
	int db_err;
	db_err = db_create(&db, NULL, 0);
	assert_equals(0, db_err);

	db_err = db->set_bt_compare(db, jaldb_sid_compare);
	assert_equals(0, db_err);

	db->close(db, DB_NOSYNC);
}

void test_initialize_serial_id_works()
{
	int err;
	err = jaldb_initialize_serial_id(sid_db, NULL);
	assert_equals(0, err);

	DBT key;
	DBT sid;
	memset(&key, 0, sizeof(key));
	memset(&sid, 0, sizeof(sid));

	key.data = strdup("next_sid");
	key.size = strlen("next_sid") + 1;
	sid.flags = DB_DBT_REALLOC;

	err = sid_db->get(sid_db, NULL, &key, &sid, 0);
	assert_equals(0, err);

	assert_equals(0, jaldb_sid_compare(sid_db, &dbt_one, &sid));
	free(key.data);
	free(sid.data);
}

void test_initialize_will_not_re_init()
{
	int err;
	DBT key;
	DBT sid;
	memset(&key, 0, sizeof(key));
	memset(&sid, 0, sizeof(sid));
	sid.flags = DB_DBT_REALLOC;

	err = jaldb_initialize_serial_id(sid_db, NULL);
	assert_equals(0, err);

	memset(&key, 0, sizeof(key));
	memset(&sid, 0, sizeof(sid));

	// force increment of SID
	err = jaldb_get_next_serial_id(sid_db, NULL, &sid);

	err = jaldb_initialize_serial_id(sid_db, NULL);
	assert_equals(0, err);

	key.data = strdup("next_sid");
	key.size = strlen("next_sid") + 1;

	err = sid_db->get(sid_db, NULL, &key, &sid, 0);
	assert_equals(0, err);

	assert_equals(0, jaldb_sid_compare(sid_db, &dbt_two, &sid));
	free(key.data);
	free(sid.data);
}

void test_get_next_serial_id_works()
{
	int err;
	err = jaldb_initialize_serial_id(sid_db, NULL);
	assert_equals(0, err);

	DBT sid;
	memset(&sid, 0, sizeof(sid));
	sid.flags = DB_DBT_REALLOC;

	err = jaldb_get_next_serial_id(sid_db, NULL, &sid);
	assert_equals(0, err);
	assert_equals(0, jaldb_sid_compare(sid_db, &dbt_one, &sid));
	free(sid.data);
	sid.data = NULL;

	err = jaldb_get_next_serial_id(sid_db, NULL, &sid);
	assert_equals(0, err);
	assert_equals(0, jaldb_sid_compare(sid_db, &dbt_two, &sid));

	free(sid.data);
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
