/**
 * @file This file contains tests for jalp_app_metadata functions.
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

#include <stdlib.h>
#include <test-dept.h>
#include <stdio.h>
#include <jalop/jalp_app_metadata.h>
#include <jalop/jalp_syslog_metadata.h>
#include <jalop/jalp_logger_metadata.h>
#include "jal_alloc.h"

void test_jalp_app_metadata_create_returns_a_non_null_pointer_to_a_struct_with_zeroed_fields()
{	struct jalp_app_metadata *ptr = jalp_app_metadata_create();
	assert_not_equals(NULL, ptr);
	assert_equals(JALP_METADATA_NONE, ptr->type);
	assert_equals((char *) NULL, ptr->event_id);
	assert_equals((char *) NULL, ptr->custom);
	assert_equals((struct jalp_journal_metadata *) NULL, ptr->file_metadata);
	jalp_app_metadata_destroy(&ptr);
}

void test_jalp_app_metadata_destroy_does_nothing_on_null_calls()
{
	// make sure this doesn't crash
	jalp_app_metadata_destroy(NULL);
	struct jalp_app_metadata *ptr = NULL;
	jalp_app_metadata_destroy(&ptr);
}

void test_jalp_app_metadata_sets_pointer_to_null()
{
	struct jalp_app_metadata *ptr = jalp_app_metadata_create();
	assert_not_equals(NULL, ptr);
	jalp_app_metadata_destroy(&ptr);
	assert_equals((struct jalp_app_metadata *) NULL, ptr);
}


void test_jalp_app_metadata_destroy_does_not_leak_syslog_metadata()
{
	//run through valgrind and check for leaks
	struct jalp_app_metadata *ptr = jalp_app_metadata_create();
	assert_not_equals(NULL, ptr);
	ptr->type = JALP_METADATA_SYSLOG;
	ptr->sys = jalp_syslog_metadata_create();
	jalp_app_metadata_destroy(&ptr);
}



void test_jalp_app_metadata_destroy_does_not_leak_app_metadata()
{
	//run through valgrind and check for leaks
	struct jalp_app_metadata *ptr = jalp_app_metadata_create();
	assert_not_equals(NULL, ptr);
	ptr->type = JALP_METADATA_LOGGER;
	ptr->log = jalp_logger_metadata_create();
	jalp_app_metadata_destroy(&ptr);
}

void test_jalp_app_metadata_destroy_does_not_leak_custom()
{
	//run through valgrind and check for leaks
	struct jalp_app_metadata *ptr = jalp_app_metadata_create();
	assert_not_equals(NULL, ptr);
	ptr->type = JALP_METADATA_CUSTOM;
	ptr->custom = jal_malloc(4);
	jalp_app_metadata_destroy(&ptr);
}
