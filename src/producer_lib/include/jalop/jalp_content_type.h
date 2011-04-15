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
#include <jalop/jalp_structured_data.h>

/** 
 * Enum covering the IANA MIME types.
 * Although JALoP uses MIME types, the content of a journal record is not
 * expected to conform to MIME, hence the omission of the 'multipart' type.
 */
enum jalp_media_type {
	JALP_MT_APPLICATION,
	JALP_MT_AUDIO,
	JALP_MT_EXAMPLE,
	JALP_MT_IMAGE,
	JALP_MT_MESSAGE,
	JALP_MT_MODEL,
	JALP_MT_TEXT,
	JALP_MT_VIDEO,
};
/**
 * @addtogroup FileInfo
 * @{
 * @defgroup ContentType Content Type
 * Functions and structures related the adding "content-type" information.
 * @see MIME
 * @{
 */
/**
 * Describes the content-type of a file.
 */
struct jalp_content_type {
	/**
	 * The top level media type.
	 */
	enum jalp_media_type media_type;
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

/** @} */
/** @} */
/** @} */

#endif // JALP_CONTENT_TYPE_H

