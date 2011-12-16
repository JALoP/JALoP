/**
 * @file jaln_record_info.c This file contains function
 * definitions for internal library functions related to the jaln_record_info
 * structure.
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
#include "jaln_record_info.h"
#include "jal_alloc.h"

struct jaln_record_info *jaln_record_info_create()
{
	return (struct jaln_record_info*) jal_calloc(1, sizeof(struct jaln_record_info));
}

void jaln_record_info_destroy(struct jaln_record_info **rec_info) {
	// The channel_info doesn't actually own any of the data members, it just
	// needs pointers back to them.
	if (!rec_info || !*rec_info) {
		return;
	}
	free((*rec_info)->serial_id);
	//jaln_mime_headers_destroy(&(*rec_info)->headers);
	free(*rec_info);
	*rec_info = NULL;
}

axl_bool jaln_record_info_is_valid(struct jaln_record_info *rec_info)
{
	if (!rec_info) {
		return axl_false;;
	}
	if (0 == rec_info->sys_meta_len) {
		return axl_false;;
	}
	if (NULL == rec_info->serial_id) {
		return axl_false;
	}
	switch (rec_info->type) {
	case JALN_RTYPE_AUDIT:
		// fall through
	case JALN_RTYPE_JOURNAL:
		if (0 == rec_info->payload_len) {
			return axl_false;;
		}
		break;
	case JALN_RTYPE_LOG:
		if ((0 == rec_info->payload_len) && (0 == rec_info->app_meta_len)) {
			return axl_false;;
		}
		break;
	default:
		return axl_false;
	}
	return axl_true;;
}

