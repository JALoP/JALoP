/**
 * @file jalp_param.h This file defines the public API for accessing jalp_param
 * objects.
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
#ifndef JALP_PARAM_H
#define JALP_PARAM_H

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
 * Create a new jalp_param element as the next element in the list. If
 * #prev already has elements, this is inserted between the 2 existing
 * elements. If #prev is NULL a new element is created as the start of a new
 * list.
 * @param[in] prev The list to add to, or NULL.
 * @param[in] key The key of this param.
 * @param[in] value The value of this param.
 *
 * @return the newly created param
 */
struct jalp_param *jalp_param_append(struct jalp_param *prev,
				     char *name,
				     char *value);
/**
 * Free all memory associated with a jalp_param. If the structure has a 'next'
 * element, this will be destroyed as well.
 *
 * @param[in,out] param The list to destroy. This will be set to NULL.
 */
void jalp_param_destroy(struct jalp_param **parm_list);

#endif // JALP_PARAM_H

