/**
 * @file This file contains tests for jalp_journal_metadata functions.
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
#include <stdio.h>
#include <test-dept.h>

#include <jalop/jalp_journal_metadata.h>

void setup()
{
	// nothing to do
}
void teardown()
{
	// nothing to do
}
void test_jalp_journal_metadata_create_initializes_new_object_to_all_zeros()
{
	struct jalp_journal_metadata *jm = jalp_journal_metadata_create();
	assert_not_equals((void*)NULL, jm);
	assert_pointer_equals((void*)NULL, jm->file_info);
	assert_pointer_equals((void*)NULL, jm->transforms);
	jalp_journal_metadata_destroy(&jm);
}
void test_jalp_journal_metadata_destroy_works_with_null_input()
{
	jalp_journal_metadata_destroy(NULL);
}
void test_jalp_journal_metadata_destroy_works_with_pointer_to_null()
{
	struct jalp_journal_metadata *jm = NULL;
	jalp_journal_metadata_destroy(&jm);
	assert_pointer_equals((void*)NULL, jm);
}
void test_jalp_journal_metadata_destroy_sets_pointer_to_null()
{
	struct jalp_journal_metadata *jm = jalp_journal_metadata_create();
	jalp_journal_metadata_destroy(&jm);
	assert_pointer_equals((void*)NULL, jm);
}
