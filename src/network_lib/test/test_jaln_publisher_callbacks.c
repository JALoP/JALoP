/**
 * @file This file contains tests for jaln_publisher_callbacks.c functions.
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

#include <jalop/jaln_publisher_callbacks.h>
#include <test-dept.h>
#include <string.h>

void test_publish_callbacks_create()
{
	struct jaln_publisher_callbacks empty_cb;
	memset(&empty_cb, 0, sizeof(empty_cb));
	struct jaln_publisher_callbacks *cb = jaln_publisher_callbacks_create();
	assert_not_equals((void*) NULL, cb);
	assert_equals(0, memcmp(&empty_cb, cb, sizeof(*cb)));
	jaln_publisher_callbacks_destroy(&cb);
}

void test_publish_callbacks_destroy_does_not_crash()
{
	struct jaln_publisher_callbacks *cb = NULL;
	jaln_publisher_callbacks_destroy(NULL);
	jaln_publisher_callbacks_destroy(&cb);
}
