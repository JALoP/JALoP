/**
 * @file
 *
 * @brief This file provides some additional utilities for the db
 * layer.
 *
 * ### LICENSE
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
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

#include "jaldb_status.h"
#include "jaldb_record.h"
#include "jaldb_context.h"

#define JALDB_STR_HELPER(x) #x
#define JALDB_STR(x) JALDB_STR_HELPER(x)

//sample:  d2/journal_payload_d2c62dcf-2eab-4141-a102-221ba9be5513
#define UUID_STRING_REP_LEN 36
// First two hexidecimal characters of UUID as directory + /
#define DIRPATH_LEN 3
//TYPE_LEN is long enough to hold "_journal_sys_meta", which is the longest type name
#define TYPE_LEN 16
#define FILENAME_LEN UUID_STRING_REP_LEN + TYPE_LEN
#define REL_PATH_LEN DIRPATH_LEN + FILENAME_LEN

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
 * @param[in] uuid Unique identifier for this file
 * @param[in] rtype The record type
 * @param[in] dtype The data type
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
