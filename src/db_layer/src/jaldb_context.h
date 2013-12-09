/**
 * @file jaldb_context.h This file defines the DB context management functions.
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

#ifndef _JALDB_CONTEXT_H_
#define _JALDB_CONTEXT_H_

#include "db.h"
#include "jaldb_record.h"
#include "jaldb_status.h"

#ifdef __cplusplus
extern "C" {
#endif

struct jaldb_record_dbs;
struct jaldb_segment;
struct jaldb_context_t;
typedef struct jaldb_context_t jaldb_context;

/**
 * Creates an empty DB context.
 *
 * @return The created empty DB context.
 *
 */
jaldb_context *jaldb_context_create();

/**
 * Initializes a DB context.
 * @param[in] ctx The context to initialize.
 * @param[in] db_root The root path of the DB Layer's files. If db_root is
 * NULL, then the default is /var/lib/jalop/db.
 * @param[in] schemas_root The path to the directory containing JALoP related
 * schemas. If schemas_root is NULL, then the default is
 * /usr/share/jalop/schemas.
 * @param[in] db_rdonly_flag A flag which indicates whether DB_RDONLY should
 * be passed to the DB open function.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_context_init(
	jaldb_context *ctx,
	const char *db_root,
	const char *schemas_root,
	int db_rdonly_flag);

/**
 * Destroys a DB context.
 * Release all resources associated with this context. This should remove any
 * temporary databases that were created.
 *
 * @param ctx[in,out] The context to destroy. *ctx will be set to NULL.
 */
void jaldb_context_destroy(jaldb_context **ctx);

/**
 * Inserts an audit record into a temporary container.
 * @param[in] ctx The context.
 * @param[in] db_name A name to associate with the container.
 * @param[in] sys_meta_buf A buffer containing the system metadata.
 * @param[in] sys_meta_len The size (in bytes) of sys_meta_buf.
 * @param[in] app_meta_buf A buffer containing the application metadata.
 * @param[in] app_meta_len The size (in bytes) of app_meta_buf.
 * @param[in] audit_buf A buffer containing the audit data.
 * @param[in] audit_len The size (in bytes) of audit_buf.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_insert_audit_record_into_temp(
	jaldb_context *ctx,
	char *db_name,
	const uint8_t *sys_meta_buf,
	const size_t sys_meta_len,
	const uint8_t *app_meta_buf,
	const size_t app_meta_buf_len,
	const uint8_t *audit_buf,
	const size_t audit_len);

/**
 * Retrieves a record by nonce.
 *
 * @param[in] ctx The context.
 * @param[in] type The type of record (journal, audit, log).
 * @param[in] nonce The nonce of the record being retrieved.
 * @param[out] rec This will be filled in as a jaldb_record object if the
 * record is found. Note that any segments located on disk will not be opened
 * automatically.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */

enum jaldb_status jaldb_get_record(jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *nonce,
		struct jaldb_record **rec);

/**
 * Retrieves a temporary record by nonce and source.
 *
 * @param[in] ctx The context.
 * @param[in] type The type of record (journal, audit, log).
 * @param[in] nonce The nonce of the record being retrieved.
 * @param[in] source The source of the record
 * @param[out] rec This will be filled in as a jaldb_record object if the
 * record is found. Note that any segments located on disk will not be opened
 * automatically.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_get_record_from_temp(jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *nonce,
		char *source,
		struct jaldb_record **rec);

/**
 * Retrieves a record by serial UUID.
 *
 * @param[in] ctx The context.
 * @param[in] type The type of record (journal, audit, log).
 * @param[in] uuid The UUID of the record to retrieved.
 * @param[out] nonce The nonce of the retrieved record. The
 * caller is responsible for freeing this memory.
 * @param[out] rec This will be filled in as a jaldb_record object if the
 * record is found. Note that any segments located on disk will not be opened
 * automatically.
 *
 * @return JAL_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_get_record_by_uuid(jaldb_context *ctx,
		enum jaldb_rec_type type,
		uuid_t uuid,
		char **nonce,
		struct jaldb_record **rec);

/**
 * Finds a given record and marks it as sent to a remote source.
 *
 * @param[in] ctx The context.
 * @param[in] type The type of record (journal, audit, or log).
 * @param[in] nonce The nonce of the record to mark.
 *
 * @return JALDB_OK on success, or a different JALDB error code on failure.
 */
enum jaldb_status jaldb_mark_sent(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		const char *nonce);


/**
 * Finds a given record and marks it as synced with a remote source.
 *
 * @param[in] ctx The context.
 * @param[in] type The type of record (journal, audit, or log).
 * @param[in] nonce The nonce of the record to mark.
 *
 * @return JALDB_OK on success, or a different JALDB error code on failure.
 */
enum jaldb_status jaldb_mark_synced(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		const char *nonce);

/**
 * Retrieves the next un-synced record from the database.
 *
 * @param[in] ctx The context.
 * @param[in] type The type of record to retrieve.
 * @param[out] nonce The nonce for the returned record.
 * @param[out] rec The record from the DB.
 *
 * @return JALDB_OK if the function succeeds or an error code.
 */
enum jaldb_status jaldb_next_unsynced_record(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	char **nonce,
	struct jaldb_record **rec);

/**
 * Retrieves the next chronological record from the database.
 *
 * @param[in] ctx The context.
 * @param[in] type The type of record to retrieve.
 * @param[out] nonce The nonce for the returned record.
 * @param[out] rec The record from the DB.
 * @param[in/out] timestamp The timestamp of the last sent record.
 * 		Overwritten to the new timestamp when a record is returned
 * 		Calling with a timestamp less than a previous timestamp
 * 		may result in records being sent multiple times.
 *
 * @return JALDB_OK if the function succeeds or an error code.
 */
enum jaldb_status jaldb_next_chronological_record(
	jaldb_context *ctx,
	enum jaldb_rec_type type,
	char **nonce,
	struct jaldb_record **rec,
	char** timestamp);

/**
 * Utility to insert any JALoP record
 * @param[in] ctx the DB context.
 * @param[in] rec The record to insert.
 * @param[out] local_nonce The nonce assigned to the record by the DB
 *
 * @return JALDB_OK on success, or an error code.
 */
enum jaldb_status jaldb_insert_record(jaldb_context *ctx, struct jaldb_record *rec, char **local_nonce);

/**
 * Utility to insert any JALoP record into a temporary database
 * @param[in] ctx the DB context.
 * @param[in,out] rec The record to insert.
 * @param[in] source The source of the record
 * @param[in] nonce The nonce of the record
 *
 * @return JALDB_OK on success, or an error code.
 */
enum jaldb_status jaldb_insert_record_into_temp(jaldb_context *ctx, struct jaldb_record *rec, char* source, char* nonce);

/**
 * Utility to transfer a record from a temporary database into the permanent database
 * @param[in] ctx The DB context.
 * @param[in] type The record type
 * @param[in] source The source of the record
 * @param[in] nonce_in The nonce of the record in the temp db
 * @param[out] nonce_out The nonce of the record in the permanent db
 *
 * @return JALDB_OK on success, or an error code.
 */
 enum jaldb_status jaldb_xfer(jaldb_context *ctx, enum jaldb_rec_type type, char* source, char* nonce_in, char** nonce_out);


/**
 * Open a segment on disk for reading.
 *
 * It is an error to try to open a segment whose \p on_disk flag is not 1.
 * @param[in] ctx The jaldb_context
 * @param[in,out] s The segment to open. If this segment already has an open
 * file descriptor, this function is a no-op.
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_open_segment_for_read(jaldb_context *ctx, struct jaldb_segment *s);

/**
 * Remove a record (by nonce) from the database
 *
 * @param[in] ctx The context.
 * @param[in] nonce The nonce of the record being retrieved.
 *
 * @return JALDB_OK if the function succeeds or an error code.
 */
enum jaldb_status jaldb_remove_record(jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *nonce);

/**
 * Remove a record (by NONCE) from the temporary database
 *
 * @param[in] ctx The context.
 * @param[in] type The type of record (journal, audit, log).
 * @param[in] source The source of the record.
 * @param[in] nonce The nonce of the record being removed.
 *
 * @return JALDB_OK if the function succeeds or an error code.
 */
enum jaldb_status jaldb_remove_record_from_temp(
		jaldb_context *ctx,
		enum jaldb_rec_type type,
		char *source,
		char *nonce);

/**
 * Utility function to remove all the segments store on disk for a specific
 * record.
 * @param[in] ctx the jaldb_context
 * @param[in] rec the record whose segemnts should be removed.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_remove_segment_from_disk(jaldb_context *ctx, struct jaldb_segment *segment);

/**
 * Utility function to remove a single segment from disk.
 * @param[in] ctx the jaldb_context
 * @param[in] segment the segment to remove.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_remove_segments_from_disk(jaldb_context *ctx, struct jaldb_record *rec);

/**
 * Get the primary jaldb_record_dbs struct for a given type of data
 * @param[in] ctx the jaldb_context
 * @param[in] type the type of data
 * @param[out] rdbs the primary jaldb_record_dbs struct for that type
 * 
 * @return JALDB_OK on success, or an error
 */
enum jaldb_status jaldb_get_primary_record_dbs(
		jaldb_context *ctx, 
		enum jaldb_rec_type type,
		struct jaldb_record_dbs **rdbs);

/**
 * Lookup temporary record dbs in the appropriate map
 * @param[in] ctx the context to use
 * @param[in] source the source string to look for in the map
 * @param[in] type the type of record
 * @param[out] rdbs the record db found, or NULL if it was not found
 *
 * @return	JALDB_OK - success
 * 		JALDB_E_INVAL - invalid parameter
 */		
enum jaldb_status jaldb_lookup_rdbs_in_map(
		jaldb_context *ctx, 
		const char *source, 
		enum jaldb_rec_type type,
		struct jaldb_record_dbs **rdbs);

/**
 * Store record dbs struct in the appropriate temporary map for its source string
 * @param[in] ctx the context to use
 * @param[in] source the string to use as the key in the map
 * @param[in] type the type of record
 * @param[in] rdbs the record db struct to store
 *
 * @return	JALDB_OK - success
 * 		JALDB_E_INVAL - invalid parameter
 */
enum jaldb_status jaldb_store_rdbs_in_map(
		jaldb_context *ctx, 
		const char *source, 
		enum jaldb_rec_type type,
		struct jaldb_record_dbs *rdbs);

/**
 * Open dbs for a record_dbs struct to be used for temporary storage of unconfirmed records
 * @param[in] ctx the context to use
 * @param[in] rdbs the temporary record dbs struct
 * @param[in] db_flags flags to pass to Berkeley db
 *
 * @return	JALDB_OK - success
 * 		JALDB_E_DB - database error
 */
enum jaldb_status jaldb_open_dbs_for_temp(
		jaldb_context *ctx,
		const char *source,
		enum jaldb_rec_type rtype,
		struct jaldb_record_dbs *rdbs,
		const u_int32_t db_flags);
#ifdef __cplusplus
}
#endif

#endif // _JALDB_CONTEXT_H_
