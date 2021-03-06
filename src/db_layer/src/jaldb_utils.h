/**
 * @file jaldb_utils.h This file provides some additional utilities for the db
 * layer.
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

#ifndef _JAL_DB_UTILS_H_
#define _JAL_DB_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <db.h>
#include "jaldb_status.h"
#include "jaldb_record.h"
#include "jaldb_context.h"

#define JALDB_STR_HELPER(x) #x
#define JALDB_STR(x) JALDB_STR_HELPER(x)

/**
 * Macro to that will log a Berkeley DB error with the file and line number
 * @param db a DB* or DB_ENV*
 * @param err The Berkeley DB error code
 */
#define JALDB_DB_ERR(__db, __err) \
	do { \
		__db->err(__db, __err, __FILE__ "(" JALDB_STR( __LINE__ ) ")"  );\
	} while (0)

/**
 * Inserts maps a host to their most recently conf'ed nonce.
 * Regardless of the return value, it is the caller's responsibility
 * to either commit, or abort the transaction.
 *
 * @param[in] db The database to update
 * @param[in] txn A transaction to associate with the update
 * @param[in] remote_host The remote host to associate with
 * @param[in] nonce The latest conf'ed nonce
 * @param[out] db_err_out The internal error from Berkeley DB (if any). This is only valid
 * when the function returns JALDB_E_DB.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_INVAL when when of the parameters is bad.
 *  - JALDB_E_DB if there was an error pertaining to Berkeley DB.
 *  - JALDB_E_ALREADY_CONFED if the current mapping in the database is
 *    the same as \p nonce or sequentially later.
 */
enum jaldb_status jaldb_store_confed_nonce(DB *db, DB_TXN *txn, const char *remote_host,
		const char *nonce, int *db_err_out);

/**
 * Helper utility to compare to nonces.
 * @param[in] nonce1 The first string to compare
 * @param[in] s1_len The length of the first string
 * @param[in] nonce2 The second string to compare
 * @param[in] s2_len The length of the second string
 *
 * @return This function returns less than 0 if nonce1 comes before nonce2, 0 if
 * the nonces are equal, and > 0 if nonce1 comes after nonce2.
 */
int jaldb_nonce_cmp(const char *nonce1, size_t s1_len, const char* nonce2, size_t s2_len);

/**
 * Helper function to create a file in the databse.
 * @param[in] db_root The root to create the file at
 * @param[out] path The path (relative to \p db_root) of the new file.
 * @param[out] fd An open file descriptor for this file.
 * @return 
 *  - JAL_OK on success
 */
enum jaldb_status jaldb_create_file(
	const char *db_root,
	char **path,
	int *fd,
	uuid_t uuid,
	enum jaldb_rec_type rtype,
	enum jaldb_data_type dtype);

/**
 * Create a timestamp for the Current time in the XML DateTime format.
 *
 * @return a newly allocated string that contains the current time as an XML
 * DateTime string.
 */
char *jaldb_gen_timestamp();

/**
 * Generate a primary key for use in the database.  The format is:
 * uuid_timestamp_pid_tid
 * @param[in] uuid the uuid to use in the key
 *
 * @return key generated, or NULL on error
 */
char *jaldb_gen_primary_key(uuid_t uuid);

#ifdef __cplusplus
}
#endif

#endif // _JAL_DB_UTILS_H_
