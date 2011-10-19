/**
 * @file jaln_digest_info.h This file contains functions related to a
 * jaln_digest_info structure. The jaln_digest_info structure is used
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

#ifndef JALN_DIGEST_INFO_H
#define JALN_DIGEST_INFO_H
#include <axl.h>
#include <stddef.h>
#include <stdint.h>

struct jaln_digest_info {
	char *serial_id;
	uint8_t *digest;
	size_t digest_len;
};

/**
 * Create a jaln_digest_info structure.
 *
 * This makes a copy of all the input parameters.
 *
 * @param[in] serial_id the serial id of the record.
 * @param[in] dgst_buf A byte buffer containing the digest of the record
 * @param[in] dgst_len The length (in bytes) of \p dgst_buf.
 *
 * @return A new jaln_digest_info structure with the contents filled out.
 */
struct jaln_digest_info *jaln_digest_info_create(const char *serial_id,
		const uint8_t *dgst_buf,
		const size_t dgst_len);

/**
 * Destroy a jaln_digest_info structure.
 *
 * @param[in,out] dgst_info The dgst_info structure to destroy. This will be
 * set to NULL.
 */
void jaln_digest_info_destroy(struct jaln_digest_info **dgst_info);

/**
 * Function to use with an \p axlList to destroy jaln_digest_info elements
 *
 * @param[in] ptr A jaln_digest_info object to destroy;
 */
void jaln_axl_destroy_digest_info(axlPointer ptr);
#endif //JALN_DIGEST_INFO_H
