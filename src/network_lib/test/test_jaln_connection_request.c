/**
 * @file test_jaln_connection_request.c This file contains tests for
 * jaln_connection_request structure.
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

#include <test-dept.h>

#include "jal_alloc.h"
#include "jaln_connection_request.h"
#include "jaln_channel_info.h"

void test_jaln_connect_request_create()
{
	struct jaln_connect_request *cr = jaln_connect_request_create();
	assert_equals((void*) NULL, cr->hostname);
	assert_equals((void*) NULL, cr->addr);
	assert_equals((void*) NULL, cr->ch_info);
	assert_equals(0, cr->type);
	assert_equals(1, cr->jaln_version);
	assert_equals((void*) NULL, cr->compressions);
	assert_equals((void*) NULL, cr->digests);
	assert_equals(0, cr->cmp_cnt);
	assert_equals(0, cr->dgst_cnt);
	assert_equals(JALN_ROLE_UNSET, cr->role);
	assert_equals((void*) NULL, cr->jaln_agent);

	jaln_connect_request_destroy(&cr);
}

void test_jaln_connect_request_destroy_does_not_crash()
{
	struct jaln_connect_request *cr = NULL;
	jaln_connect_request_destroy(&cr);

	jaln_connect_request_destroy(NULL);
}

void test_jaln_connect_request_destroy_works()
{
	struct jaln_connect_request *cr = jaln_connect_request_create();

	cr->hostname = jal_strdup("a string");
	cr->addr = jal_strdup("a string");
	cr->ch_info = jaln_channel_info_create();
	cr->compressions = jal_calloc(3, sizeof(char*));
	cr->compressions[0] = jal_strdup("cmp 1");
	cr->compressions[1] = jal_strdup("cmp 2");
	cr->compressions[2] = jal_strdup("cmp 3");
	cr->cmp_cnt = 3;

	cr->digests = jal_calloc(2, sizeof(char*));
	cr->digests[0] = jal_strdup("dgst 1");
	cr->digests[1] = jal_strdup("dgst 2");
	cr->dgst_cnt = 2;
	cr->jaln_agent = jal_strdup("an agent");

	jaln_connect_request_destroy(&cr);
}
