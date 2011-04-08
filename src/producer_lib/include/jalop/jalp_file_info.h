/**
 * @file jalp_file_info.h This file defines structures and functions for
 * use building the "fileinfo" section of the application metadata.
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
#ifndef JALP_FILEINFO_H
#define JALP_FILEINFO_H
#include <jalp_content_type.h>

/** Indicates if a given entry is considered malicious. */
enum jalp_threat_level {
	/**
	 * Indications the application didn't check, or could not determine if
	 * the entry is unsafe.
	 */
	JAL_THREAT_UNKNOWN = 0,
	/**
	 * Indicates the application performed some sort of scanning on the
	 * entry and determined it was not a thread.
	 * @note a file could be marked as safe and still contain malicious
	 * code that was undetected.
	 */
	JAL_THREAT_SAFE,
	/**
	 * Indicates the application performed some sort of scanning on the
	 * entry a determined the entry contained malicious code.
	 */
	JAL_THREAT_MALICIOUS,
};


/**
 * Detailed information about the file type, etc. jalp_file_info objects assume
 * ownership of all member pointers.
 * Applications should create/destroy jalp_file_info objects using
 * jalp_file_info_create() and jalp_file_info_destroy()
 */
struct jalp_file_info {
	/** The size of the file (in bytes) before any transforms were applied to it. */
	uint64_t original_size;
	/** The name of the file. */
	char *filename;
	/** Indicator of whether or not this entry is considered malicious. */
	enum jalp_threat_level threat_level;
	/**
	 * An (optional) content type. If NULL, no content-type is added to
	 * the XML.
	 */
	struct jalp_content_type *content_type;
};
/**
 * Create a new jalp_file_info structure
 * @return the newly create file_info structure.
 */
struct jalp_file_info *jalp_file_info_create(void);
/**
 * Release resources associated with ajalp_file_info object. This releases all
 * members with calls the appropriate "*_destroy()" functions or free().
 * @param[in,out] file_info the object to destroy. The pointer is set to NULL.
 */
void jalp_file_info_destroy(struct jalp_file_info **file_info);

#endif // JALP_FILEINFO_H

