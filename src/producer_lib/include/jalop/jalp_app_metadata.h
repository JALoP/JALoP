/**
 * @file jalp_app_metadata.h This file defines the top level public structure
 * used to create application metadata.
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
#ifndef JALP_APP_METADATA_H
#define JALP_APP_METADATA_H
#include <jalop/jalp_syslog_metadata.h>
#include <jalop/jalp_logger_metadata.h>
#include <jalop/jalp_digest.h>
#include <jalop/jalp_fileinfo.h>
/**
 * @defgroup AppMetadata Application Metadata
 *
 * Structures and functions related to building application metadata.
 * @{
 */
/** 
 * Enum for the type of embedded metadata in the application metadata
 * structure.
 */
enum jalp_metadata_type {
	/** Indicates the application did not add any extra data */
	JALP_METADATA_NONE = 0,
	/** Indicates the application added a jalp_syslog_metadata structure */
	JALP_METADATA_SYSLOG,
	/** Indicates the application added a jalp_logger_metadata structure */
	JALP_METADATA_LOGGER,
	/** Indicates the application added custom XML */
	JALP_METADATA_CUSTOM,
};

/**
 * Structure that applications may use to generate an applicationMetadata
 * document. The application metadata is optional. Even when provided, most
 * fields are optional any uninitialized or NULL fields are ignored during XML
 * generation.
 *
 * Applications must use jalp_app_meta_create() and jalp_app_metadata_destroy() to
 * create/destroy these objects. The destructor assumes ownership of all
 * pointers and will call the appropriate "*_destory()" functions or "free()".
 */
struct jalp_app_metadata {
	/**
	 * indicates what type of data this contains, syslog metadata,
	 * logger metadata, or some custom format.
	 */
	enum jalp_metadata_type type;
	/**
	 * An application defined event ID. This can be used to correlate
	 * multiple entries, or be NULL. It's has no meaning to JALoP. This is
	 * optional.
	 */
	char *eventId;
	/**
	 * Holds the sys, log, or custom sub-element. The #type member
	 * determines how the library interprets this pointer.
	 */
	union {
		struct jalp_syslog_metadata *sys;
		struct jalp_logger_metadata *log;
		/**
		 * a block of XML data. It may conform to any schema,
		 * or none at all. This may be a complete document, or just a
		 * snippet.
		 */
		char *custom;
	};
	/** The (optional) digest of the payload. */
	struct jalp_digest *payload_digest;
	/**
	 * Optional metadata for the file. Applications are strongly
	 * encouraged to include this for journal entries.
	 */
	struct jalp_file_metadata *file_metadata;
};

/**
 * Create and initialize a jalp_app_metadata object
 *
 * @return a new jalp_app_metadata object
 */
struct jalp_app_metadata *jalp_app_metadata_create(void)
/**
 * Free all resources owned by a jalp_app_metadata structure. This function
 * assumes ownership of all member elements and will call the appropriate
 * "*_destroy()" functions or "free()" as needed.
 *
 * @param[in,out] app_meta The object to destroy. The pointer will be set to
 * NULL.
 */
void jalp_app_metadata_destroy(struct jalp_app_metadata **app_meta)
/** @} */
#endif //JALP_APP_METADATA_H

