/**
 * @file jaln_digest_resp_info.h This file contains functions related to a
 * jaln_digest_resp_info structure. The jaln_digest_resp_info structure is used
 * to store the response to a 'digest' message.
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

#ifndef JALN_DIGEST_RESP_INFO_H
#define JALN_DIGEST_RESP_INFO_H
#include <axl.h>
#include <jalop/jaln_network_types.h>
#include <stddef.h>
#include <stdint.h>

struct jaln_digest_resp_info {
	char *serial_id;
	enum jaln_digest_status status;
};

/**
 * Create a jaln_digest_resp_info. The jaln_digest_resp_info is used to track
 * result of comparing the locally calculated digest for a record to the digest
 * calculated by the peer.
 *
 * @param[in] serial_id The serial ID of the record. This makes a copy of
 * serial_id.
 * @param[in] status The status of the comparison
 *
 * @return a new jaln_digest_resp_info structure
 */
struct jaln_digest_resp_info *jaln_digest_resp_info_create(const char *serial_id,
		enum jaln_digest_status status);

/**
 * Destroy a jaln_digest_resp_info.
 *
 * @param[in,out] dgst_resp_info The jaln_digest_resp_info structure to destroy. This will be set to NULL.
 */
void jaln_digest_resp_info_destroy(struct jaln_digest_resp_info **dgst_resp_info);

/**
 * Function to use with an \p axlList to destroy jaln_digest_resp_info elements
 *
 * @param[in] ptr A jaln_digest_resp_info object to destroy;
 */
void jaln_axl_destroy_digest_resp_info(axlPointer ptr);

/**
 * Function to use with an \p axlList to check for equality
 *
 * @param[in] a The first jaln_digest_resp_info object to compare
 * @param[in] b The second jaln_digest_resp_info object to compare
 *
 * For this case, only the serial_id member is checked for equality
 */
int jaln_axl_equals_func_digest_resp_info_serial_id(axlPointer a, axlPointer b);

#endif //JALN_DIGEST_RESP_INFO_H
