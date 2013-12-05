/**
 * @file jaln_digest_resp_info.c This file contains functions related to a
 * jaln_digest_resp_info structure. The jaln_digest_resp_info structure is used
 * to store the calculated/receive digest value and nonce for a
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
#include <jalop/jal_status.h>
#include <string.h>

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"
#include "jaln_digest_resp_info.h"

struct jaln_digest_resp_info *jaln_digest_resp_info_create(const char *nonce,
		enum jaln_digest_status status)
{
	if (!nonce) {
		return NULL;
	}

	struct jaln_digest_resp_info *dgst_resp_info = jal_malloc(sizeof(*dgst_resp_info));
	dgst_resp_info->nonce = jal_strdup(nonce);
	dgst_resp_info->status = status;
	return dgst_resp_info;
}

void jaln_digest_resp_info_destroy(struct jaln_digest_resp_info **dgst_resp_info)
{
	if (!dgst_resp_info || !*dgst_resp_info) {
		return;
	}
	free((*dgst_resp_info)->nonce);
	free(*dgst_resp_info);
	*dgst_resp_info = NULL;
}

void jaln_axl_destroy_digest_resp_info(axlPointer ptr)
{
	struct jaln_digest_resp_info* di = (struct jaln_digest_resp_info*) ptr;
	jaln_digest_resp_info_destroy(&di);
}

int jaln_axl_equals_func_digest_resp_info_nonce(axlPointer a, axlPointer b)
{
	struct jaln_digest_resp_info *di_a = (struct jaln_digest_resp_info*) a;
	struct jaln_digest_resp_info *di_b = (struct jaln_digest_resp_info*) b;
	if (!di_a || !di_a->nonce) {
		return -1;
	}
	if (!di_b || !di_b->nonce) {
		return 1;
	}
	return strcmp(di_a->nonce, di_b->nonce);
}

axlList *jaln_digest_resp_list_create()
{
	axlList *resps = axl_list_new(jaln_axl_equals_func_digest_resp_info_nonce,
			jaln_axl_destroy_digest_resp_info);
	if (!resps) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	return resps;
}

