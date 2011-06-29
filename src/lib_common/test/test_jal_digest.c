/**
 * @file This file contains tests to for jal_digest functions.
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
#include <jalop/jal_digest.h>
#include "jal_alloc.h"

void test_jal_digest_ctx_create_returns_struct_with_zeroed_fields()
{
	struct jal_digest_ctx *ptr = jal_digest_ctx_create();
	assert_not_equals(NULL, ptr);
	assert_equals(0, ptr->len);
	assert_equals((void*)NULL, ptr->create);
	assert_equals((void*)NULL, ptr->init);
	assert_equals((void*)NULL, ptr->update);
	assert_equals((void*)NULL, ptr->final);
	assert_equals((void*)NULL, ptr->destroy);
	jal_digest_ctx_destroy(&ptr);
}

void test_jal_digest_destroy_does_not_crash_on_null()
{
	jal_digest_ctx_destroy(NULL);
	struct jal_digest_ctx *ptr = NULL;
	jal_digest_ctx_destroy(&ptr);
}
void test_jal_digest_destroy_frees_struct()
{
	// run under valgrind to check for leaks
	struct jal_digest_ctx *ptr = jal_digest_ctx_create();
	assert_not_equals(NULL, ptr);
	jal_digest_ctx_destroy(&ptr);
	assert_equals((struct jal_digest_ctx *) NULL, ptr);
}

