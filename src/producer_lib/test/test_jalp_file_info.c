/**
 * @file test_jalp_file_info.c This file contains tests for jalp_file_info functions.
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
#include <jalop/jalp_journal_metadata.h>
#include "jal_alloc.h"


void test_jalp_file_info_create_initializes_new_jalp_file_info()
{
	struct jalp_file_info *new_file_info;
	new_file_info = jalp_file_info_create();
	assert_not_equals((struct jalp_file_info *)NULL, new_file_info);
	assert_equals(0, new_file_info->original_size);
	assert_equals((char *)NULL, new_file_info->filename);
	assert_equals(JAL_THREAT_UNKNOWN, new_file_info->threat_level);
	assert_equals((struct jalp_content_type *)NULL, new_file_info->content_type);
	jalp_file_info_destroy(&new_file_info);
}

void test_jalp_file_info_destroy_null()
{
	struct jalp_file_info *inval = NULL;
	jalp_file_info_destroy(NULL);
	jalp_file_info_destroy(&inval);
	assert_equals((struct jalp_file_info *)NULL, inval);
}

void test_jalp_file_info_destroy_null_fields()
{
	struct jalp_file_info *new_file_info;
	new_file_info = jalp_file_info_create();
	jalp_file_info_destroy(&new_file_info);
	assert_equals((struct jalp_file_info *)NULL, new_file_info);
}

void test_jalp_file_info_destroy_initialized_fields()
{
	struct jalp_file_info *new_file_info;
	new_file_info = jalp_file_info_create();

	new_file_info->content_type = jalp_content_type_create();
	new_file_info->filename = jal_strdup("name");

	jalp_file_info_destroy(&new_file_info);
	assert_equals((struct jalp_file_info *)NULL, new_file_info);
}
