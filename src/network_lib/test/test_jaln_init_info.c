/**
 * @file This file contains tests for jaln_init_info.c functions.
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
#include "jaln_init_info.h"

void test_init_info_create_works()
{

	struct jaln_init_info *info = jaln_init_info_create();
	assert_not_equals((void*)NULL, info);
	assert_equals(JALN_ROLE_SUBSCRIBER, info->role);
	assert_equals(JALN_RTYPE_LOG, info->type);
	assert_pointer_equals((void*) NULL, info->peer_agent);
	assert_not_equals((void*) NULL, info->digest_algs);
	assert_not_equals((void*) NULL, info->encodings);
	jaln_init_info_destroy(&info);
	assert_pointer_equals((void*) NULL, info);
}

void test_init_info_destroy_does_not_crash()
{
	struct jaln_init_info *info = NULL;

	jaln_init_info_destroy(&info);
	assert_pointer_equals((void*) NULL, info);
	jaln_init_info_destroy(NULL);
}

