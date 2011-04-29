/**
 * @file jalp_structured_data.h This file defines structures and functions to
 * deal with structured_data elements of the syslog metadata.
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
#ifndef JALP_STRUCTURED_DATA_H
#define JALP_STRUCTURED_DATA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/jalp_param.h>
/**
 * @ingroup LoggerMetadata
 * @ingroup SyslogMetadata
 * @{
 * @defgroup StructuredData Structured Data
 * The functions and methods in here are used to generate structured data
 * elements. The concept of structured data is borrowed from the syslog RFC
 * (http://tools.ietf.org/html/rfc5424).
 *
 * Typically, structured data elements are used to provide additional
 * information about the system at the time the log entry was generated. This
 * may be information about the system clock, timezone, data about the process
 * that generated the log, or information about the logging system itself.
 * Applications are free to use structured data to provide any key/value pairs
 * they see fit.
 * @{
 */
/**
 * A linked list of generic jalp_param elements. jalp_param elements are simple key/value 
 * pairs.
 * mechanism to list extra key/value pairs. The elements are namespaced using
 * the sd_id field. This corresponds to the Structured Data section of the
 * syslog RFC (RFC 5424, section 6.3)
 */
struct jalp_param {
	/** The key for this param */
	char *key;
	/** The value of this element.  */
	char *value;
	/** The next element in the list.  */
	struct jalp_param *next;
};
/**
 * @ingroup StructuredData
 * Create a new jalp_param element as the next element in the list.
 * If \p prev already has elements, this is inserted between the 2 existing
 * elements. If \p prev is NULL a new element is created as the start of a new
 * list.
 * @param[in] prev The list to add to, or NULL.
 * @param[in] name The key of this param.
 * @param[in] value The value of this param.
 *
 * @return the newly created param
 */
struct jalp_param *jalp_param_append(struct jalp_param *prev,
				     char *name,
				     char *value);
/**
 * @ingroup StructuredData
 * Free all memory associated with a jalp_param. If the structure has a 'next'
 * element, this will be destroyed as well.
 *
 * @param[in,out] param_list The list to destroy. This will be set to NULL.
 */
void jalp_param_destroy(struct jalp_param **param_list);

/**
 * Represents a set of structured data elements. Applications should use an ID
 * containing an '@' unless using one of the registered IDs.
 *
 * Applications must use the jalp_structured_data_create() and
 * jalp_structured_data_destroy() functions to allocate and destroy structured
 * data objects. The jalp_structured_data objects assume ownership of all
 * pointers and will free them using the appropriate "*_destroy()" functions or
 * free().
 *
 * @see rfc5424
 */
struct jalp_structured_data {
	/** The SD-ID for all param elements in \p param_list. */
	char *sd_id;
	/** A list of params belonging to this SD-ID */
	struct jalp_param *param_list;
	/** The next structured data group */
	struct jalp_structured_data *next;
};
/**
 * Create a jalp_structured_data element.
 *
 * @param[in] prev The location in a list to add the element. If \p prev is not the
 * end of the list, then the new node is created as the next element of \p prev,
 * and \p prev->next becomes the new node's next element.
 * This function may be used to add elements to the end, or middle
 * of a list. When \p prev is NULL this creates a new list.
 * @param[in] sd_id The sd_id to use for the new element.
 *
 * @return a newly created jalp_structred_data pointer. This must be freed with
 * jalp_structured_data_destroy(struct jalp_structured_data*).
 *
 */
struct jalp_structured_data *jalp_structured_data_append(struct jalp_structured_data *prev,
							 char *sd_id);
/**
 * Release all memory associated with this structured data list.
 * This frees all params of \p sd_group and all #jalp_structured_data elements.
 * @param[in,out] sd_group The list of SD groups to destroy. This will be set to
 * NULL.
 */
void jalp_structured_data_destroy(struct jalp_structured_data **sd_group);
/** @} */
/** @} */
#ifdef __cplusplus
}
#endif
#endif //JALP_STRUCTURED_DATA_H

