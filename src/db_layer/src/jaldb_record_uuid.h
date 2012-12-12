/**
 * @file jaldb_record_uuid.h Declaration of utilties related to the record
 * UUID stored with the JALoP record in the database.
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
#ifndef __JALDB_RECORD_UUID_H_
#define __JALDB_RECORD_UUID_H_

#include <db.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function to extract the record UUID as a secondary key.
 *
 * This function extracts the UUID component of the JALoP record as it is
 * inserted into the database.
 *
 * @param[in] secondary Pointer to the secondary DB that is getting modified,
 * this is only checked to see if the record is byte-swapped.
 * @param[in] key The key for the data in the primary DB
 * @param[in] data The data for the record
 * @param[out] result the DBT object to fill in for the UUID secondary key.
 *
 * @return 0 to indicate the record should be indexed, -1 to indicate an error
 * occurred.
 */
int jaldb_extract_record_uuid(DB *secondary, const DBT *key, const DBT *data, DBT *result);

#ifdef __cplusplus
}
#endif

#endif
