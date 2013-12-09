/**
 * @file jaldb_nonce.c Implementation of utilties dealing with nonces.
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
#include <string.h>

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"

#include "jaldb_nonce.h"
#include "jaldb_strings.h"

int jaldb_nonce_compare(DB *db, const DBT *dbt1, const DBT *dbt2)
{
	int ret;
	if (!dbt1 || !dbt1->data || (0 == dbt1->size) || !dbt2 || !dbt2->data || (0 == dbt2->size)) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	if (dbt1->size == dbt2->size) {
		ret = strncmp(dbt1->data, dbt2->data, dbt1->size);
	} else if (dbt1->size > dbt2->size) {
		ret = strncmp(dbt1->data, dbt2->data, dbt2->size);
		if (ret == 0) ret = 1;
	} else {
		ret = strncmp(dbt1->data, dbt2->data, dbt1->size);
		if (ret == 0) ret = -1;
	}
	return ret;
}
