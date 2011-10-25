/**
 * @file jaln_init_info.h This file contains functions related to a
 * jaln_init_info structure. The jaln_init_info structure is used
 * to store the calculated/receive digest value and serial ID for a
 * record.
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

#ifndef JALN_INIT_INFO_H
#define JALN_INIT_INFO_H
#include <axl.h>
#include <stddef.h>
#include <stdint.h>
#include <jalop/jaln_network_types.h>

struct jaln_init_info {
	enum jaln_role role;
	enum jaln_record_type type;
	char *peer_agent;
	axlList *digest_algs;
	axlList *encodings;
};

/**
 * Create a jaln_init_info structure.
 *
 * @return A new jaln_init_info structure with the contents filled out.
 */
struct jaln_init_info *jaln_init_info_create();

/**
 * Destroy a jaln_init_info structure.
 *
 * @param[in,out] init_info The jaln_init_info structure to destroy. This will be
 * set to NULL.
 */
void jaln_init_info_destroy(struct jaln_init_info **init_info);


#endif //JALN_INIT_INFO_H
