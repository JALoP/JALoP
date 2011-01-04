/**
 * @file test_jalp_syslog_metadata.c This file contains functions to test jalp_syslog_metadata functions.
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
#include <jalop/jalp_syslog_metadata.h>
#include "jal_alloc.h"

void test_jalp_syslog_metadata_create_returns_struct_with_zeroed_fields()
{
	struct jalp_syslog_metadata *ptr = jalp_syslog_metadata_create();
	assert_not_equals(NULL, ptr);
	assert_equals((void*) NULL, ptr->timestamp);
	assert_equals((void*) NULL, ptr->message_id);
	assert_equals((void*) NULL, ptr->entry);
	assert_equals((void*) NULL, ptr->sd_head);
	assert_equals(-1, ptr->facility);
	assert_equals(-1, ptr->severity);
	jalp_syslog_metadata_destroy(&ptr);
}

void test_jalp_syslog_metadata_destroy_with_null_does_not_crash()
{
	// test to make sure the test doesn't crash
	jalp_syslog_metadata_destroy(NULL);
	struct jalp_syslog_metadata *ptr = NULL;
	jalp_syslog_metadata_destroy(&ptr);

	ptr = jalp_syslog_metadata_create();
	jalp_syslog_metadata_destroy(&ptr);
	assert_equals((struct jalp_syslog_metadata *) NULL, ptr);

}
void test_jalp_syslog_metadata_destroy_frees_struct()
{
	// run under valgrind to check
	struct jalp_syslog_metadata *ptr = jalp_syslog_metadata_create();
	ptr->timestamp = jal_strdup("12:00:23.123");
	ptr->message_id = jal_strdup("foo");
	ptr->sd_head = jalp_structured_data_append(NULL, "some_sd_id");
	jalp_syslog_metadata_destroy(&ptr);
	assert_equals((struct jalp_syslog_metadata *) NULL, ptr);
}
