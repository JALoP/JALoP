/**
 * @file jaln_connection_request.c This file contains functions related to a
 * jaln_connect_request structure.
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

#include "jal_alloc.h"

#include "jaln_channel_info.h"
#include "jaln_compression.h"
#include "jaln_connection_request.h"

struct jaln_connect_request *jaln_connect_request_create()
{
	struct jaln_connect_request *req = (struct jaln_connect_request*) jal_calloc(1, sizeof(*req));
	req->jaln_version = JALN_JALOP_VERSION_ONE;
	return req;
}

void jaln_connect_request_destroy(struct jaln_connect_request **preq)
{
	if (!preq || !*preq) {
		return;
	}
	struct jaln_connect_request *req = *preq;
	free(req->hostname);
	free(req->addr);

	jaln_channel_info_destroy(&req->ch_info);

	jaln_string_array_destroy(&req->compressions, req->cmp_cnt);
	jaln_string_array_destroy(&req->digests, req->dgst_cnt);

	free(req->jaln_agent);
	free(req);
	*preq = NULL;
}
