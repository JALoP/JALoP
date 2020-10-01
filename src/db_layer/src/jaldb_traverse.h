/**
 * @file jaldb_traverse.h This file defines types and functions for traversing
 * the records in the database.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#ifndef _JALDB_TRAVERSE_H_
#define _JALDB_TRAVERSE_H_

#include "jaldb_context.h"
#include "jaldb_record.h"
#include "jaldb_status.h"

#ifdef __cplusplus
extern "C" {
#endif

enum jaldb_iter_status {
	JALDB_ITER_CONT,	//!< Continue processing records.
	JALDB_ITER_REM,		//!< Remove the current record.
	JALDB_ITER_ABORT,	//!< Stop processing and return control to the caller.
};

/**
 * Function callback functions that traversal functions use to make decisions
 * regarding a specific record.
 *
 * This callback is used in a number of functions that can traverse the
 * database in a variety of ways. The return of this function is used to
 * determine what (if anything) should happen.
 *
 * In most instances, the \p rec should not be modified (or at least, any
 * modifications are not written to the DB).
 *
 * @param[in] nonce The nonce as a hex string (starting with '0x')
 * @param[in] rec The current record
 * @param[in] up This is the same pointer that is passed to the traversal
 *               function, it can be used to store some state information,
 *               etc.
 */
typedef enum jaldb_iter_status (*jaldb_iter_cb)(const char *nonce, struct jaldb_record *rec, void *up);

/**
 * Utility function to iterate over the records in a DB in order by timestamp.
 *
 * This function iterates over the database in timestamp order. Operations performed
 * on each record are dictated by the return value of the callback. Only timestamps
 * which fulfill <tt> start_time <= current_time <= end_time </tt> are examined. Timestamps are
 * never negative numbers.
 *
 * If the return from \p cb is JALDB_ITER_CONT, continue processing, but do not 
 * modify the current record.
 *
 * If the return from \p cb is JALDB_ITER_REMOVE, remove the current record,
 * and continue processing.
 *
 * Any other return value causes processing to halt, the current record is not
 * removed, and control is returned to the caller.
 *
 * @param[in] ctx The DB context to use.
 * @param[in] type The type of record to delete.
 * @param[in] timestamp The end time to stop iterating
 * @param[in] cb The user specified callback.
 * @param[in] up A pointer value that is passed un-modified to \p cb as the \p up
 * parameter.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_iterate_by_timestamp(jaldb_context *ctx,
		enum jaldb_rec_type type,
		const char *timestamp,
		jaldb_iter_cb cb, void *up);

enum jaldb_status jaldb_iterate_by_timestamp2(jaldb_context *ctx,
		enum jaldb_rec_type type,
		const char *timestamp,
		jaldb_iter_cb cb, void *up);

#ifdef __cplusplus
}
#endif

#endif

