/**
 * @file jaln_channel_info.c This file contains function
 * definitions for internal library functions related to a jaln_channel_info
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
#include "jaln_channel_info.h"
#include "jal_alloc.h"

struct jaln_channel_info *jaln_channel_info_create()
{
	return (struct jaln_channel_info*) jal_calloc(1, sizeof(struct jaln_channel_info));
}

void jaln_channel_info_destroy(struct jaln_channel_info **ch_info) {
	if (!ch_info || !*ch_info) {
		return;
	}
	free((*ch_info)->hostname);
	free((*ch_info)->addr);
	free((*ch_info)->compression);
	free((*ch_info)->digest_method);
	free(*ch_info);
	*ch_info = NULL;
}

