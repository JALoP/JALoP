/**
 * @file jaldb_record_dbs.h This file provides the structure definition and
 * functions related to jaldb_record_dbs objects.
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

#ifndef _JALDB_RECORD_BDS_
#define _JALDB_RECORD_BDS_

#include <db.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This structure is used to track related DBs for a specific type of record.
 *
 * For permanent storage (i.e. records created by either the local store, or,
 * in the case of a Subscriber, confirmed as correctly received) records are
 * indexed by the Timestamp & UUID identified by the System Meta-data.
 */
struct jaldb_record_dbs {
	DB *primary_db;             //<! The database to store actual records in.
	DB *timestamp_tz_idx_db;    //<! The secondary database to use for timestamps (with timezones) indices.
	DB *timestamp_no_tz_idx_db; //<! The secondary database to use for timestamps (without timezones) indices.
	DB *record_id_idx_db;       //<! The database to use for record UUID indices
	DB *sid_db;                 //<! The database to use for obtaining the 'next' serial ID.
};

#ifdef __cplusplus
}
#endif

#endif // _JALDB_RECORD_BDS_
