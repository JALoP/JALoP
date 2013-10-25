/**
 * @file jaldb_serial_id.h This file deals with C function declarations related
 * to serial ids for the DB Layer.
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
 * @param [in] db The DB to initialize
 * @param [in] txn A transaction to use (may be null)
 * @param [out] db_err An internal DB_ERROR
 *
 * @return 0 on success, or a BDB error code.
 */
int jaldb_initialize_serial_id(DB *db, DB_TXN *parent_txn);

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

/**
 * Obtain the next serial ID from a container and update the value in the
 * database.
 *
 * @param[in] txn A transaction to associate with the modification.
 * @param[in] uc The update context to use.
 * @param[in] container The container that tracks the serial ID. It must have a
 * document name JALDB_SERIAL_ID_DOC_NAME.
 * @param[out] sid On success, this will contain the next serial ID. Warning:
 * This function blindly overwrites the memory associated with \p sid, and
 * forces the use of DBT_REALLOC as <tt>sid->flags</tt>. The caller is
 * responsible for freeing any memory assigned to <tt>sid->data</tt>.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_CORRUPTED if there is a problem in the database.
 *
 * This function does not perform any exception handling. The caller must
 * handle exceptions as appropriate.
 */
int jaldb_get_next_serial_id(DB *db,
		DB_TXN *txn,
		DBT *sid);

/**
 * Comparison function for use by Berkeley DB when performing nonce comparisons.
 *
 * @param [in] db The DB the comparison is happening on.
 * @param [in] dbt1 The first element's key.
 * @param [in] dbt2 The second element's key.
 *
 * @return less than zero if <tt>dbt1 < dbt2</tt>, greater than zero if
 * <tt>dbt1 > dbt2</tt>, and 0 if <tt>dbt1 == dbt2</tt>.
 */

int jaldb_nonce_compare(DB *db, const DBT *dbt1, const DBT *dbt2);

#ifdef __cplusplus
}
#endif

#endif // _JALDB_SERIAL_ID_HPP_
