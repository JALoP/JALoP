/**
 * @file jaln_init_info.c This file contains functions related to a
 * jaln_init_info structure. The jaln_init_info structure is used
 * to communicate the contents of an init message.
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
#include "jal_error_callback_internal.h"
#include "jaln_init_info.h"
#include "jaln_encoding.h"

struct jaln_init_info *jaln_init_info_create()
{
	struct jaln_init_info *init_info = jal_calloc(1, sizeof(*init_info));
	init_info->role = JALN_ROLE_SUBSCRIBER;
	init_info->type = JALN_RTYPE_LOG;
	init_info->digest_algs =
		axl_list_new(jaln_string_list_case_insensitive_func, free);
	if (!init_info->digest_algs) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	init_info->encodings =
		axl_list_new(jaln_string_list_case_insensitive_func, free);
	if (!init_info->encodings) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	return init_info;
}

void jaln_init_info_destroy(struct jaln_init_info **init_info)
{
	if (!init_info || !*init_info) {
		return;
	}
	free((*init_info)->peer_agent);
	axl_list_free((*init_info)->digest_algs);
	axl_list_free((*init_info)->encodings);
	free(*init_info);
	*init_info = NULL;
}

void jaln_axl_destroy_init_info(axlPointer ptr)
{
	struct jaln_init_info* di = (struct jaln_init_info*) ptr;
	jaln_init_info_destroy(&di);
}

