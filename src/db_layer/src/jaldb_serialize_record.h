/**
 * @file jaldb_record_serialize.h This file provides the functions headers for
 * serializing/deserializing JALoP Records from a memory buffer.
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

#ifndef _JALDB_RECORD_SERIALIZE_H_
#define _JALDB_RECORD_SERIALIZE_H_

#include <uuid/uuid.h>
#include "jaldb_status.h"

#ifdef __cplusplus
extern "C" {
#endif

#define JALDB_DB_LAYOUT_VERSION 1
#define JALDB_RFLAGS_HAVE_SYS_META    (1 << 0)
#define JALDB_RFLAGS_HAVE_APP_META    (1 << 1)
#define JALDB_RFLAGS_HAVE_PAYLOAD     (1 << 2)
#define JALDB_RFLAGS_HAVE_UID         (1 << 3)
#define JALDB_RFLAGS_SYS_META_ON_DISK (1 << 4)
#define JALDB_RFLAGS_APP_META_ON_DISK (1 << 5)
#define JALDB_RFLAGS_PAYLOAD_ON_DISK  (1 << 6)
#define JALDB_RFLAGS_SYNCED           (1 << 7)
#define JALDB_RFLAGS_SENT             (1 << 8)

struct jaldb_record;
struct jaldb_segment;

/**
 * Internal structure used for serializing/de-serializing JALoP records to/from
 * the DB.
 */
struct jaldb_serialize_record_headers {
	uint16_t version;      //<! The version of the DB layout.
	uint32_t flags;        //<! Bitmask of flags.
	uint64_t pid;          //<! The process ID
	uint64_t uid;          //<! The user ID
	uint64_t sys_meta_sz;  //<! The size of the system meta-data
	uint64_t app_meta_sz;  //<! The size of the application meta-data
	uint64_t payload_sz;   //<! The size of the payload
	uuid_t host_uuid;      //<! The UUID of the host machine that generated the record
	uuid_t record_uuid;    //<! The UUID of the record
};

/**
 * Helper utility to append a variable length string to the memory buffer.
 * This function assumes that there is enough space in \p *buf to add the
 * characters from \p str, including a null terminator.
 * @param[in,out] buf The buffer to append to. The address is advanced by
 *     \p strlen(str) or 1 (in the event of an empty/null string.
 * @param[in] str The string to add to the buffer.
 */
void jaldb_serialize_add_string(uint8_t **buf, const char *str);

/**
 * Helper utility to the contents of a data segment to a memory buffer.
 * This function assumes that there is enough space in \p *buf to add the
 * contents of the segment. If \p segment indicates the data is store on disk,
 * then the relative path of the file is added to the buffer. If \p segment
 * indicates the data is stored in RAM, then \p buf is appended with the actual
 * bytes of the segment.
 *
 * @param[in,out] buf The buffer to append to. The address is advanced
 *     accordingly.
 * @param[in] segment The segment data to add.
 */
void jaldb_serialize_add_segment(uint8_t **buf, const struct jaldb_segment *segment);

/**
 * Helper function to increment a \p size_t variable by the length of a string.
 * This function will increment \p *size to ensure there is enough space to
 * store the contents of \p str. If \p str is NULL, then 1 byte is reserved
 * (for a NULL terminator).
 * @param[in,out] size Address to the variable to increment.
 * @param[in] str The string
 *
 * @return JALDB_OK on success, or an error code.
 */
enum jaldb_status jaldb_serialize_inc_by_string(size_t *size, const char *str);

/**
 * Helper function to increment a \p size_t variable to store a specific data
 * segment.
 * This function will increment \p *size to ensure there is enough space to
 * store the requisite data for of \p segment. If \p segment is null, 1 byte of
 * space is still reserved (for the requisite null terminator). If \p segment
 * indicates the data is stored on disk, then \p *size is incremented to store
 * the relative path to the payload. If \p segment indicates the data is stored
 * on disk, then \p *size is incremented to store the full segment data.
 *
 * @param[in,out] size Address to the variable to increment.
 * @param[in] segment The segment data to reserve space for
 *
 * @return JALDB_OK on success, or an error code.
 */
enum jaldb_status jaldb_serialize_inc_by_segment_size(size_t *size, const struct jaldb_segment *segment);

/**
 * Utility to serialize a \p jaldb_record to a memory buffer
 * @param[in] byte_swap Flag to control whether or not integer fields need to
 * be byte-swapped.
 * @param[in] record The record to serialize
 * @param[out] buffer On success, the serialized contents of \p record.
 * @param[out] bsize On success, the size (in bytes) of \p *buffer.
 *
 * @return JALDB_OK on success, or an error code.
 */
enum jaldb_status jaldb_serialize_record(
					const char byte_swap,
					struct jaldb_record *record,
					uint8_t **buffer,
					size_t *bsize);

/**
 * Utility to de-serialize a \p jaldb_record from a memory buffer
 * @param[in] byte_swap Flag to control whether or not integer fields need to
 * be byte-swapped.
 * @param[in] buffer The buffer to de-serialize
 * @param[in] bsize The size (in bytes) of \p buffer
 * @param[out] record The de-serialized contents of \p buffer as a \p
 * jaldb_record.
 *
 * @return JALDB_OK on success, or an error code.
 */
enum jaldb_status jaldb_deserialize_record(
					const char byte_swap,
					uint8_t *buffer,
					size_t bsize,
					struct jaldb_record **record);

/**
 * Extract the next string from the memory buffer.
 * This functions scans \p *buffer for a \p null terminator to construct a
 * string. The search is limited to bytes in the range \p *buffer -
 * \p (buffer + *size). If a \p null byte is not found in that range, an error
 * is returned, and \p *buffer & \p size are unchanged.
 *
 * If a \p null byte is found, then a copy of the string is created, it must be
 * freed with a call to free().
 *
 * @param[in,out] buffer the buffer extract a string from. On success \p buffer
 * will be advanced by strlen(*str);
 * @param[in,out] size the number of bytes remaining in \p buffer.
 * @param[out] str on success, a newly allocated copy of the string.
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_deserialize_string(uint8_t **buffer, size_t *size, char** str);

/**
 * Extract a jaldb_segment from the buffer.
 * This function will create & populate a jaldb_segment structure from the
 * buffer.
 *
 * @param[in] on_disk flag to indicate if the actual contents of the segment
 * are located on the disk, or in the database.
 * @param[in,out] buffer the buffer to read from. \p buffer will be advanced
 * past the segment on success.
 * @param[in,out] size the number of bytes remaining in \p buffer. \p size will
 * be decrement by the number of bytes consumed by the jaldb_segment.
 * @param[out] segment an address to copy the segment into. The caller is
 * responsible for freeing this memory with jaldb_destroy_segment().
 *
 * @return JALDB_OK on success, or an error.
 */
enum jaldb_status jaldb_deserialize_segment(char on_disk,
		size_t segment_length,
		uint8_t **buffer,
		size_t *size,
		struct jaldb_segment **segment);

#ifdef __cplusplus
}
#endif

#endif
