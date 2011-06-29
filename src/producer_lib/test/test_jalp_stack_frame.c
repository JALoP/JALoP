/**
 * @file This file contains tests for jalp_stack_frame functions.
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
#include "jalp_stack_frame_internal.h"

void test_jalp_stack_frame_append_returns_struct_with_zeroed_fields()
{
	struct jalp_stack_frame *ptr = jalp_stack_frame_append(NULL);
	assert_not_equals(NULL, ptr);
	assert_equals((void *)NULL, ptr->caller_name);
	assert_equals((void *)NULL, ptr->file_name);
	assert_equals(0, ptr->line_number);
	assert_equals((void *)NULL, ptr->class_name);
	assert_equals((void *)NULL, ptr->method_name);
	assert_equals(0, ptr->depth);
	jalp_stack_frame_destroy(&ptr);
}

void test_jalp_stack_frame_append_adds_list_to_list()
{
	struct jalp_stack_frame *head = jalp_stack_frame_append(NULL);
	assert_not_equals((void *)NULL, head);
	struct jalp_stack_frame *curr = jalp_stack_frame_append(head);
	assert_not_equals((void *)NULL, curr);
	assert_not_equals(head, curr);
	assert_equals(curr, head->next);
	jalp_stack_frame_destroy(&head);
}
void test_jalp_stack_frame_append_inserts_between_elements()
{
	struct jalp_stack_frame *head = jalp_stack_frame_append(NULL);
	assert_not_equals((void *)NULL, head);
	struct jalp_stack_frame *curr = jalp_stack_frame_append(head);

	curr = jalp_stack_frame_append(curr);

	struct jalp_stack_frame *tmp = head->next;
	struct jalp_stack_frame *tail = head->next->next;
	// make sure we have 3 unique elments
	assert_not_equals(head, tmp);
	assert_not_equals(head, tail);
	assert_not_equals(tmp, tail);

	curr = jalp_stack_frame_append(head);
	// make sure we got a new element
	assert_not_equals(head, curr);
	assert_not_equals(tmp, curr);
	assert_not_equals(tail, tmp);

	// make sure the list was patched up correctly
	assert_equals(head->next, curr);
	assert_equals(curr->next, tmp);
	// and that it didn't break the tail
	assert_equals(tmp->next, tail);
	jalp_stack_frame_destroy(&head);
}
void test_jalp_stack_frame_destroy_one_frees_struct()
{
	// run under valgrind for to check for leaks
	struct jalp_stack_frame *ptr = jalp_stack_frame_append(NULL);
	ptr->caller_name = strdup("someCaller");
	ptr->file_name = strdup(__FILE__);
	ptr->line_number = __LINE__;
	ptr->class_name = strdup("test-dept-driver");
	ptr->method_name = strdup(__FUNCTION__);
	ptr->depth = 0;
	jalp_stack_frame_destroy_one(ptr);
}
void test_jalp_stack_frame_destroy_does_not_crash_with_null()
{
	jalp_stack_frame_destroy(NULL);

	struct jalp_stack_frame *ptr = NULL;
	jalp_stack_frame_destroy(&ptr);
	assert_equals((void *)NULL, ptr);
}
void test_jalp_stack_frame_destroy_frees_one()
{
	struct jalp_stack_frame *ptr;
	ptr = jalp_stack_frame_append(NULL);
	jalp_stack_frame_destroy(&ptr);
	assert_equals((void *) NULL, ptr);
}
void test_jalp_stack_frame_destroy_frees_a_list()
{
	struct jalp_stack_frame *head;
	head = jalp_stack_frame_append(NULL);

	struct jalp_stack_frame *tmp = jalp_stack_frame_append(head);
	tmp = jalp_stack_frame_append(tmp);
	tmp = jalp_stack_frame_append(tmp);
	tmp = jalp_stack_frame_append(tmp);

	jalp_stack_frame_destroy(&head);
	assert_equals((void *) NULL, head);
}
