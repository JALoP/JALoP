/**
 * @file jaldb_segment.h This file provides the structure used to represent a
 * single segment of a JALoP record (system meta-data, application meta-data, or
 * payload), as well as functions for allocating/freeing memory associated with
 * the structure.
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

#ifndef _JALDB_SEGMENT_H_
#define _JALDB_SEGMENT_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Structure representing one component of a JALoP record.
 * In the database, the record data may be stored in a separate file on disk,
 * or directly in the database. If this segment is stored in a separate
 * file, then \p on_disk is set to \p 1 (otherwise it is \p 0). If the record
 * is on disk, then \p fd may be a valid file descriptor. If \p on_disk is
 * \p 1, then payload is set to the relative path on disk.
 * If this segment is stored directly in the database, then \p on_disk is
 * set to 0, \p fd is set to \p -1, and \p payload is the
 * contents of the segment.
 * \p length is always the size of segment, regardless of whether it is on
 * disk or in the database.
 */
struct jaldb_segment {
	uint64_t      length;     //!< The size of this hunk of data.
	uint8_t       *payload;   //!< The actual data, or the relative path on disk.
	int           fd;         //!< The file descriptor for the data.
	char          on_disk;    //!< indicates if the payload is the raw content, or if the data exists on disk.
};

#ifdef __cplusplus
}
#endif

#endif
