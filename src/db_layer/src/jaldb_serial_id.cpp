/**
 * @file jaldb_serial_id.cpp Implementation of utilties dealing with serial ids.
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

#include <cstring>
#include <jalop/jal_status.h>
#include <openssl/bn.h>

#include "jal_error_callback_internal.h"

#include "jaldb_serial_id.hpp"
#include "jaldb_strings.h"

using namespace std;

enum jaldb_status jaldb_get_next_serial_id(DB_TXN *txn, DB *db, string &sid)
{
	return JALDB_E_NOT_IMPL;
}

enum jaldb_status jaldb_initialize_serial_id(DB_TXN *parent_txn, DB *db, int *db_err)
{
	return JALDB_E_NOT_IMPL;
}

void jaldb_increment_serial_id(string &sid)
{
	int inc = 1;
	int idx;
	for (idx = (sid.length() - 1); (inc == 1 && idx >= 0); idx--) {
		inc = 0;
		switch (sid[idx]) {
		case '9':
			sid[idx] = 'A';
			break;
		case 'Z':
			sid[idx] = 'a';
			break;
		case 'z':
			sid[idx] = '0';
			inc = 1;
			break;
		default:
			sid[idx] += 1;
		}
	}
	if (inc) {
		sid.insert(0, 1, '1');
	}
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

