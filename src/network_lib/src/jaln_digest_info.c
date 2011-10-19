/**
 * @file jaln_digest_info.c This file contains functions related to a
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
#include <string.h>
#include "jal_alloc.h"
#include "jaln_digest_info.h"

struct jaln_digest_info *jaln_digest_info_create(const char *serial_id,
		const uint8_t *dgst_buf,
		const size_t dgst_len)
{
	if (!serial_id || !dgst_buf || dgst_len == 0) {
		return NULL;
	}

	struct jaln_digest_info *dgst_info = jal_malloc(sizeof(*dgst_info));
	dgst_info->serial_id = jal_strdup(serial_id);
	dgst_info->digest = jal_malloc(dgst_len);
	memcpy(dgst_info->digest, dgst_buf, dgst_len);
	dgst_info->digest_len = dgst_len;
	return dgst_info;
}

void jaln_digest_info_destroy(struct jaln_digest_info **dgst_info)
{
	if (!dgst_info || !*dgst_info) {
		return;
	}
	free((*dgst_info)->serial_id);
	free((*dgst_info)->digest);
	free(*dgst_info);
	*dgst_info = NULL;
}

