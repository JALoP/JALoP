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

struct jaldb_record;

#ifdef __cplusplus
extern "C" {
#endif

enum jaldb_iter_status {
	JALDB_ITER_CONT, //<! Continue processing records.
	JALDB_ITER_REM,  //<! Remove the current record.
	JALDB_ITER_ABORT, //<! Stop processing and return control to the caller.
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
 * @param[in] sid The serial ID as a hex string (starting with '0x')
 * @param[in] rec The current record
 * @param[in] up This is the same pointer that is passed to the traversal
 *               function, it can be used to store some state information,
 *               etc.
 */
typedef enum jaldb_iter_status (*jaldb_iter_cb)(const char *hex_sid, struct jaldb_record *rec, void *up);

#ifdef __cplusplus
}
#endif

#endif

