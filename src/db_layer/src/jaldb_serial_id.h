/**
 * @file jaldb_serial_id.h This file deals with C function declarations related to serial ids for the DB Layer.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#ifndef _JALDB_SERIAL_ID_H_
#define _JALDB_SERIAL_ID_H_

#include <db.h>
#include "jaldb_status.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Helper function to insert the first serial ID for a container.
 *
 * @param [in] txn A transaction to use.
 * @param [in] cont The container to insert into.
 * @param [out] db_err An internal DB_ERROR
 *
 * @return JALDB_OK or an error code.
 */
enum jaldb_status jaldb_initialize_serial_id(DB_TXN *parent_txn,
		DB *db,
		int *db_err);

/**
 * Comparison function for use by Berkeley DB when performing SID comparisons.
 * Both \p DBT objects are treated as Openssl Big Number objects, i.e.
 * arbitrary length, big-endian byte strings.
 *
 * @param [in] db The DB the comparison is happening on.
 * @param [in] dbt1 The first element's key.
 * @param [in] dbt2 The second element's key.
 *
 * @return less than zero if <tt>dbt1 < dbt2</tt>, greater than zero if
 * <tt>dbt1 > dbt2</tt>, and 0 if <tt>dbt1 == dbt2</tt>.
 */
int jaldb_sid_compare(DB *db, const DBT *dbt1, const DBT *dbt2);

#ifdef __cplusplus
}
#endif

#endif // _JALDB_SERIAL_ID_HPP_
