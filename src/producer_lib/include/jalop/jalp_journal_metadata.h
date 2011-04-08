/**
 * @file jalp_journal_metadata.h This file defines structures and functions for
 * building the "journalMetadata" section of the application metadata.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011 Tresys Technology LLC, Columbia, Maryland, USA
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
#ifndef JALP_JOURNAL_METADATA_H
#define JALP_JOURNAL_METADATA_H
#include <jalp_file_info.h>
#include <jalp_journal_transforms.h>
/**
 * @defgroup JournalMetadata Journal Metadata
 * This contains additional structures and functions to generate information
 * about journal data. Journal Data is typically large, binary files and the
 * APIs in this section allow applications to attach information such as the
 * filename, original file size, or threat level (jalp_threat_level).
 *
 * JALoP (and this library) make no attempt to compress, encrypt or otherwise
 * transform files. Applications may wish to perform any number of transforms
 * before sending the file to the JAL local store, though they should describe
 * any transforms applied by filling approprate jalp_transform structures.
 * @{
 */
/**
 * Structure to provide metadata about the payload, typically only used for
 * journal entries.
 */
struct jalp_journal_metadata {
	/**
	 * Generic metadata about the file.
	 */
	struct jalp_file_info *file_info;
	/**
	 * List of transforms that the application applied before submitting
	 * the entry to the JAL local store
	 */
	struct jalp_journal_transform *transforms;
};
/**
 * Create and initialize a jalp_journal_metadata object
 * @return a newly created journal_metadata entry.
 */
struct jalp_journal_metadata *jalp_journal_metadata_create(void);
/**
 * @ingroup jalp_journal_metadata
 * Release all memory associated with a jalp_journal_metadata object. This
 * calls the appropriate "*_destroy()" functions and "free()" on all members.
 * @param[in,out] journal_meta the object to destroy, this will be set to NULL.
 */
void jalp_journal_metadata_destroy(struct jalp_journal_metadata **journal_meta)

/** @} */
#endif //JALP_JOURNAL_METADATA_H

