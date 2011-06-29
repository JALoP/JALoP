/**
 * @file This file contains tests for jalp_log_severity functions.
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
#include <stdlib.h>
#include <jalop/jalp_logger_metadata.h>
#include "jal_alloc.h"

void test_jalp_log_severity_create_returns_struct_with_zeroed_fields()
{
	struct jalp_log_severity *ptr = jalp_log_severity_create();
	assert_not_equals(NULL, ptr);
	assert_equals(0, ptr->level_val);
	assert_equals((char *) NULL, ptr->level_str);
	jalp_log_severity_destroy(&ptr);
}

void test_jalp_log_severity_destroy_frees_struct()
{
	// test to make sure the test doesn't crash
	jalp_log_severity_destroy(NULL);
	struct jalp_log_severity *ptr = NULL;
	jalp_log_severity_destroy(&ptr);

	ptr = jalp_log_severity_create();
	jalp_log_severity_destroy(&ptr);
	assert_equals((struct jalp_log_severity *) NULL, ptr);

	ptr = jalp_log_severity_create();
	ptr->level_val = 100;
	ptr->level_str = jal_calloc(5, sizeof(char));
	jalp_log_severity_destroy(&ptr);
	assert_equals((struct jalp_log_severity *) NULL, ptr);
}


