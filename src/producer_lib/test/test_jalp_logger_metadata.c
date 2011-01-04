/**
 * @file test_jalp_logger_metadata.c This file contains tests for jalp_logger_metadata functions.
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
#include <jalop/jalp_logger_metadata.h>
#include <jalop/jalp_structured_data.h>
#include "jalp_stack_frame_internal.h"
#include "jal_alloc.h"

void test_jalp_logger_metadata_create_inits_new_logger_metadata()
{
	struct jalp_logger_metadata *new_logger_metadata = NULL;
	new_logger_metadata = jalp_logger_metadata_create();
	assert_not_equals((void*)NULL, new_logger_metadata);
	assert_equals((void*)NULL, new_logger_metadata->logger_name);
	assert_equals((void*)NULL, new_logger_metadata->timestamp);
	assert_equals((void*)NULL, new_logger_metadata->threadId);
	assert_equals((void*)NULL, new_logger_metadata->message);
	assert_equals((void*)NULL, new_logger_metadata->nested_diagnostic_context);
	assert_equals((void*)NULL, new_logger_metadata->mapped_diagnostic_context);
	assert_equals((void*)NULL, new_logger_metadata->severity);
	assert_equals((void*)NULL, new_logger_metadata->stack);
	assert_equals((void*)NULL, new_logger_metadata->sd);
	free(new_logger_metadata);
}

void test_jalp_logger_metadata_destroy_null()
{
	struct jalp_logger_metadata *new_logger_metadata = NULL;
	jalp_logger_metadata_destroy(NULL);
	jalp_logger_metadata_destroy(&new_logger_metadata);
	assert_equals((void*)NULL, new_logger_metadata);
}

void test_jalp_logger_metadata_destroy_inited_empty_new_logger_metadata()
{
	struct jalp_logger_metadata *new_logger_metadata = NULL;
	new_logger_metadata = jalp_logger_metadata_create();
	assert_not_equals(NULL, new_logger_metadata);
	jalp_logger_metadata_destroy(&new_logger_metadata);
	assert_equals((void*)NULL, new_logger_metadata);
}

void test_jalp_logger_metadata_destroy_inited_nonempty_new_logger_meta()
{
	struct jalp_logger_metadata *new_logger_metadata = NULL;
	new_logger_metadata = jalp_logger_metadata_create();
	new_logger_metadata->logger_name = jal_strdup("test");
	new_logger_metadata->message = jal_strdup("test message");
	new_logger_metadata->severity = jalp_log_severity_create();
	new_logger_metadata->stack = jalp_stack_frame_append(new_logger_metadata->stack);
	jalp_logger_metadata_destroy(&new_logger_metadata);
	assert_equals((void*)NULL, new_logger_metadata);
}
