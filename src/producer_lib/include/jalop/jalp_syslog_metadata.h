/**
 * @file jalp_syslog_metadata.h This file defines structures and functions to
 * deal with syslog style application metadata.
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
#ifndef _JALP_SYSLOG_METADATA_H_
#define _JALP_SYSLOG_METADATA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <jalop/jalp_structured_data.h>
/**
 * @addtogroup AppMetadata
 * @{
 * @defgroup SyslogMetadata Syslog Metadata
 * Specialized structures and functions to deal with common metadata attached
 * to syslog style logs.
 * @{
 */

/**
 * The syslog_metadata structure should be filled in if an application wishes
 * to generate events that contain data similar to what syslog produces.
 *
 * These correspond to the elements in the JAL application metadata schema
 * (applicationMetadata.xsd).
 *
 * The hostname and application name are taken from the jalp_context, while
 * the process ID (PID) is generated automatically. Timestamps are generated
 * automatically if the timestamp field is NULL.
 */
struct jalp_syslog_metadata {
	/**
	 * The time that should be logged for this record. If NULL, the JAL
	 * library will generate a timestamp itself. The timestamp must conform
	 * to the XML Schema dataTime format.
	 */
	char *timestamp;
	/**
	 * The message ID may be used to identify the 'type' of the log
	 * message. @see the MSGID field in RFC 5424.
	 */
	char *messageId;
	/**
	 * A linked list of structured data elements. If NULL, no elements are
	 * added.
	 */
	struct jalp_structured_data *sd_head;
	/**
	 * The facility, must be between 0 and 23. Value of -1 indicates it should be ignored.
	 * The numeric values of the facility have the same meanings as for
	 * syslog.
	 */
	int8_t facility;
	/**
	 * The severity indicates the level a log messages is grouped in. The
	 * severity must be between 0 and 7. A value of -1 indicates the
	 * severity should be ignored.
	 */
	int8_t severity;
};

/**
 * Allocate and initialize a #jalp_syslog_metadata structure.
 * @return The newly allocated #jalp_syslog_metadata
 */
struct jalp_syslog_metadata *jalp_syslog_metadata_create(void);
/**
 * Destroy a #jalp_syslog_metadata structure and all it's members.
 * @param[in,out] syslog_meta A #jalp_syslog_metadata object to destroy. This will
 * be set to NULL.
 * @return JAL_OK, or JAL_BAD_POINTER
 */
void jalp_syslog_metadata_destroy(struct jalp_syslog_metadata **syslog_meta);
/** @} */
/** @} */
#ifdef __cplusplus
}
#endif
#endif // _JALP_PRODUCER_H_

