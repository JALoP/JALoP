/**
 * @file jaldb_datetime.h Declaration of utilties related to XML DateTime
 * strings within the JALoP DBs.
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

#ifndef _JALDB_DATETIME_H_
#define _JALDB_DATETIME_H_

#include <db.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * B-Tree Comparison function for XML DateTime strings.
 *
 * This function is intended for use as the key comparison function when keys
 * are XML DateTime strings. Because some XML DateTimes cannot be compared, all
 * keys must have timezone attributes. For example, the 2 DateTimes
 * <tt>2012-12-12T09:00:00</tt> and <tt>2012-12-12T09:00:00Z</tt> cannot be
 * compared because the timezone for the former is unknown, and therefore could
 * indicate the same time, an earlier time, or a later time than the latter.
 *
 * If there is any sort of parse error on the keys, or the values are
 * indeterminate, then jal_error_handler is called.
 *
 * @param[in] db The Berkeley DB that contains the keys, this is unused.
 * @param[in] dbt1 The DBT that represents the application provided key (i.e.
 * key to search for).
 * @param[in] dbt2 The DBT that represents the current key from the tree.
 *
 * @return -1 if <tt>(db1 < dbt2)</tt>, 0 if <tt>(dbt1 == dbt1)</tt>, 1 if <tt>(dbt1 > dbt2)</tt>
 *
 */
int jaldb_xml_datetime_compare(DB *db, const DBT *dbt1, const DBT *dbt2);

#ifdef __cplusplus
}
#endif

#endif
