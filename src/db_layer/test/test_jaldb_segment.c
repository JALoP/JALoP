/**
 * @file test_jaldb_segment.c This file contains functions to test
 * jaldb_segment.c.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <unistd.h>

#include "jal_alloc.h"

#include "jaldb_segment.h"

static int closed_called;

int mocked_close(int fd) {
	closed_called = 1;
	return 0;
}

void setup()
{
	replace_function(&close, &mocked_close);
	closed_called = 0;
}

void teardown()
{
	closed_called = 1;
	restore_function(&close);
}

void test_jaldb_destroy_segment_does_not_crash()
{
	struct jaldb_segment *segment = NULL;
	jaldb_destroy_segment(&segment);
	jaldb_destroy_segment(NULL);
}

void test_jaldb_create_segment_works()
{
	struct jaldb_segment *segment = jaldb_create_segment();
	assert_not_equals(NULL, segment);
	assert_equals(0, segment->length);
	assert_equals(-1, segment->fd);
	assert_pointer_equals(NULL, segment->payload);
	jaldb_destroy_segment(&segment);
}

void test_jaldb_destroy_segment_closes_fds()
{
	struct jaldb_segment *segment = jaldb_create_segment();
	segment->fd = 12;
	jaldb_destroy_segment(&segment);
	assert_pointer_equals((void*) NULL, segment);
	assert_equals(1, closed_called);
}

void test_jaldb_destroy_segment_does_not_close_invalid_fds()
{
	struct jaldb_segment *segment = jaldb_create_segment();
	jaldb_destroy_segment(&segment);
	assert_pointer_equals((void*) NULL, segment);
	assert_equals(0, closed_called);
}

void test_jaldb_destroy_segment_frees_payload_buffer()
{
	struct jaldb_segment *segment = jaldb_create_segment();
	segment->payload = jal_malloc(100);
	jaldb_destroy_segment(&segment);
	assert_pointer_equals((void*) NULL, segment);
	assert_equals(0, closed_called);
}
