/**
 * @file jaldb_serial_id.c Implementation of utilties dealing with serial ids.
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

#include <errno.h>
#include <jalop/jal_status.h>
#include <openssl/bn.h>
#include <string.h>

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"

#include "jaldb_serial_id.h"
#include "jaldb_strings.h"

#define SID_KEY "next_sid"

int jaldb_initialize_serial_id(DB *db, DB_TXN *txn)
{
	int err = 0;
	BIGNUM *bn_one = NULL;
	uint8_t tmp;
	DBT key;
	DBT val;
	memset(&key, 0, sizeof(key));
	memset(&val, 0, sizeof(val));

	if (!db) {
		err = EINVAL;
		goto out;
	}

	key.data = strdup(SID_KEY);
	key.size = strlen(SID_KEY) + 1;
	key.flags = DB_DBT_REALLOC;

	val.flags = DB_DBT_REALLOC | DB_DBT_PARTIAL;

	// Get the existing 'next' SID
	err = db->get(db, txn, &key, &val, 0);
	if (DB_NOTFOUND != err) {
		// already initialized, don't do anything.
		goto out;
	}

	tmp = 1;
	bn_one = BN_bin2bn(&tmp, sizeof(tmp), NULL);

	val.size = BN_num_bytes(bn_one);
	val.data = jal_malloc(val.size);
	val.flags = DB_DBT_REALLOC;

	BN_bn2bin(bn_one, val.data);
	err = db->put(db, txn, &key, &val, 0);

out:
	BN_free(bn_one);
	free(key.data);
	free(val.data);
	return err;
}

int jaldb_sid_compare(DB *db, const DBT *dbt1, const DBT *dbt2)
{
	BIGNUM *bn1 = BN_new();
	BIGNUM *bn2 = BN_new();
	if (!dbt1 || !dbt1->data || (0 == dbt1->size) || !dbt2 || !dbt2->data || (0 == dbt2->size)) {
		jal_error_handler(JAL_E_NO_MEM);
	}

	BN_bin2bn((unsigned char *)dbt1->data, dbt1->size, bn1);
	BN_bin2bn((unsigned char *)dbt2->data, dbt2->size, bn2);
	int ret = BN_cmp(bn1, bn2);

	BN_free(bn1);
	BN_free(bn2);
	return ret;
}

int jaldb_get_next_serial_id(DB *db,
		DB_TXN *txn,
		DBT *sid)
{
	int err = 0;
	BIGNUM *bn_res = NULL;
	BIGNUM *bn_sid = NULL;
	BIGNUM *bn_one = NULL;
	DBT key;
	uint8_t tmp;

	if (!db || !sid) {
		return EINVAL;
	}

	memset(sid, 0, sizeof(*sid));
	memset(&key, 0, sizeof(key));
	key.data = jal_strdup(SID_KEY);
	key.size = strlen(SID_KEY) + 1;
	key.flags = DB_DBT_REALLOC;

	sid->flags = DB_DBT_REALLOC;

	// Get the existing 'next' SID
	err = db->get(db, txn, &key, sid, 0);
	if (0 != err) {
		goto out;
	}
	
	bn_sid = BN_new();
	bn_res = BN_new();
	tmp = 1;
	bn_one = BN_bin2bn(&tmp, sizeof(tmp), NULL);

	// Increment
	BN_bin2bn((unsigned char *)sid->data, sid->size, bn_sid);
	BN_add(bn_res, bn_sid, bn_one);

	sid->size = BN_num_bytes(bn_res);
	void *tmpp = realloc(sid->data, sid->size);
	if (NULL == tmpp) {
		err = ENOMEM;
		goto out;
	}
	sid->data = tmpp;
	BN_bn2bin(bn_res, sid->data);
	// Store the new 'next' SID
	err = db->put(db, txn, &key, sid, 0);
	if (0 != err) {
		goto out;
	}

	sid->size = BN_num_bytes(bn_sid);
	tmpp = realloc(sid->data, sid->size);
	if (NULL == tmpp) {
		free(sid->data);
		sid->data = NULL;
		sid->size = 0;
		err = ENOMEM;
		goto out;
	}
	sid->data = tmpp;
	BN_bn2bin(bn_sid, sid->data);
	err = 0;
out:
	BN_free(bn_sid);
	BN_free(bn_res);
	BN_free(bn_one);
	free(key.data);
	return err;
}

