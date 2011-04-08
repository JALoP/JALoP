/**
 * @file jalp_content_type.h This file defines structures and functions for
 * building jalp_content_type structures.
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
#ifndef JALP_CONTENT_TYPE_H
#define JALP_CONTENT_TYPE_H
#include <jalop/jalp_params.h>
/**
 * @addtogroup FileInfo
 * @{
 * @defgroup ContentType Content Type
 * Functions and structures releated the adding "content-type" information.
 * @see MIME
 * @{
 */
/**
 * Describes the content-type of a file.
 */
struct jalp_content_type {
	/**
	 * The top level media type. This must be one of following:
	 *  - "application"
	 *  - "audio"
	 *  - "example"
	 *  - "image"
	 *  - "message"
	 *  - "model"
	 *  - "test"
	 *  - "video"
	 *
	 *  The JPL provides functions for each of these.
	 *  @see contentTypeAllocators
	 */
	char *media_type;
	/** A string for the subtype, this may be anything. */
	char *subtype;
	/** A list of optional parameters. */
	struct jalp_param *params;
};
/**
 * Create and initialize a jalp_content_type object.
 * @return the new jalp_content_type object.
 */
struct jalp_content_type *jalp_content_type_create(void);

/**
 * Release all memory associated with a jalp_content_type object.
 * This calls the appropriate "*_destroy()" functions or free() on member
 * elements.
 * @param[in,out] content_type the object to destroy, this will be set to NULL.
 */
void jalp_content_type_destroy(struct jalp_content_type **content_type);

/**
 * @defgroup mediaTypeAllocators Media Type Allocators
 *
 * Functions that allocate strings for use as jalp_content_type::media_type
 * @{
 */
/**
 * Allocate a new string with value "audio", the memory must be released
 * with free().
 * @return "audio"
 */
char *jalp_mt_audio();
/**
 * Allocate a new string with value "application", the memory must be released
 * with free().
 * @return "application"
 */
char *jalp_mt_application();
/**
 * Allocate a new string with value "example", the memory must be released
 * with free().
 * @return "example"
 */
char *jalp_mt_example();
/**
 * Allocate a new string with value "image", the memory must be released
 * with free().
 * @return "image"
 */
char *jalp_mt_image();
/**
 * Allocate a new string with value "message", the memory must be released
 * with free().
 * @return "message"
 */
char *jalp_mt_message();
/**
 * Allocate a new string with value "model", the memory must be released
 * with free().
 * @return "model"
 */
char *jalp_mt_model();
/**
 * Allocate a new string with value "test", the memory must be released
 * with free().
 * @return "test"
 */
char *jalp_mt_test();
/**
 * Allocate a new string with value "video", the memory must be released
 * with free().
 * @return "video"
 */
char *jalp_mt_video();
/** @} */
/** @} */
/** @} */

#endif // JALP_CONTENT_TYPE_H

