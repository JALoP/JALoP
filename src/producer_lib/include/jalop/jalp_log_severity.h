/**
 * @file jalp_log_severity.h This file defines structures related to the
 * jalp_log_severity structure.
 * metadata.
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
#ifndef JALP_LOG_SEVERITY_H
#define JALP_LOG_SEVERITY_H
#include <jalop/jalp_structured_data.h>
#include <jalop/jalp_stack_frame.h>
/**
 * @ingroup LoggerMetadata
 * Structure the encapsulates a severity level. The severity for a log may be
 * described by both an integer and a string. These values only have meaning to
 * the application.
 *
 * Applications must allocate and destroy this structure using
 * jalp_log_severity_create and jalp_log_severity_destroy.
 */
struct jalp_log_severity {
	/** indicates the numeric level */
	int level_val;
	/** an optional, human readable string */
	char *level_str;
};
/**
 * @ingroup LoggerMetadata
 * Create and initialize a jalp_log_severity object
 * @return The newly allocated log_severity object.
 *
 * @returns JAL_OK on success.
 */
struct jalp_log_severity *jalp_log_severity_create(void);
/**
 * @ingroup LoggerMetadata
 * destroy a jalp_log_severity object and any members.
 * @param[in,out] log_severity The object to destroy. This will be set to NULL.
 */
void jalp_log_severity_destroy(struct jalp_log_severity** log_severity);
/** @} */
#endif // JALP_LOG_SEVERITY_H

