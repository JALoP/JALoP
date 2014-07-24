/**
 * @file jaldb_record.h This file provides the structure used to insert &
 * retrieve records from the database, as well as functions for allocating/
 * freeing memory associated with the structure.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#ifndef _JALDB_RECORD_H_
#define _JALDB_RECORD_H_

#include <stdint.h>
#include <uuid/uuid.h>

#include "jaldb_status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JALDB_RECORD_VERSION 1
#define JALDB_MAX_REC_LENGTH 200000000 

struct jaldb_segment;


/**
* Enum used to distinguish between record types
*/
enum jaldb_rec_type {
	JALDB_RTYPE_JOURNAL  = 1 << 0, //!< Indicates a Journal Record */
	JALDB_RTYPE_AUDIT    = 1 << 1, //!< Indicates an Audit Record */
	JALDB_RTYPE_LOG      = 1 << 2, //!< Indicates a Log Record */
	JALDB_RTYPE_UNKNOWN  = 1 << 3, //!< Indicates the record type is unknown/unset */
};

/*
 * Enum used to distinguish between system metadata, application metadata, and payload components of a record
 */

enum jaldb_data_type {
        JALDB_DTYPE_SYS_META = 1 << 4, // Indicates System Metadata
        JALDB_DTYPE_APP_META = 1 << 5, // Indicates Application Metadata
        JALDB_DTYPE_PAYLOAD  = 1 << 6, // Indicates Payload Metadata
};


/**
 * This structure is used to insert/retrieve records from the database.
 */
struct jaldb_record {
	char                 *network_nonce;  //!< The nonce used for network communications about this record.
	uint64_t             pid;             //!< The process ID of the process that created the record.
	uint64_t             uid;             //!< The User ID of process that generated the event.
	struct jaldb_segment *sys_meta;       //!< Structure containing data regarding the system metadata, or NULL.
	struct jaldb_segment *app_meta;       //!< Structure containing data regarding the app metadata, or NULL.
	struct jaldb_segment *payload;        //!< Structure containing data regarding the payload (journal audit or log data), or NULL.
	char                 *source;         //!< The source of this record.
	char                 *hostname;       //!< The hostname of the machine that created the record.
	char                 *timestamp;      //!< The timestamp of this record in XML Schema DateTime format.
	char                 *username;       //!< The username of the process that generated the event.
	char                 *sec_lbl;        //!< The security label of the process that generated the event.
	int                  version;         //!< The in-database version of the record, currently always \p 1.
	enum jaldb_rec_type  type;            //!< The type of the record
	char                 synced;          //!< Indicates if the record was sent to at least 1 remote.
	char                 confirmed;       //!< Indicates if the record has been confirmed via digest.
	char                 have_uid;        //!< Indicates if the uid filed is valid.
	uuid_t               host_uuid;       //!< The UUID of the machine that created the record.
	uuid_t               uuid;            //!< The UUID of the record.
};

/**
 * Function to create a jaldb_record
 * @return a newly allocated jaldb_record.
 */
struct jaldb_record *jaldb_create_record();

/**
 * Function to destroy a jaldb_record.
 * This will call appropriate destroy functions & free on all of it's members.
 * @param [in,out] pprecord The jaldb_record to destroy. This will be set to NULL.
 */
void jaldb_destroy_record(struct jaldb_record **pprecord);

/**
 * Perform some basic sanity checks on a record before inserting into the DB.
 * This function ensures that some basic attributes are in place and that each
 * data type includes the requisite sections of a jalop record. I.e. Log
 * records must have either application meta-data or a payload, or both,
 * whereas for journal and audit data, the payload is required, and the
 * application meta-data is optional. Note that this function does not perform
 * any schema validation checks.
 *
 * @param[in] rec The jaldb_record object to check;
 * @return JALDB_OK on success, or JALDB_EINVAL on error.
 */
enum jaldb_status jaldb_record_sanity_check(struct jaldb_record *);

#ifdef __cplusplus
}
#endif

#endif
