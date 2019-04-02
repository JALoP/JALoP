/**
 * @file test_jaln_connection.c This file contains tests for jaln_connection.c functions.
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

#include <jalop/jaln_network.h>
#include "jaln_connection.h"

#include <test-dept.h>
#include <string.h>

extern void jaln_session_unref(jaln_session **);

void fake_jaln_session_unref(__attribute__((unused))jaln_session **sess)
{
	return;
}

void test_connection_create()
{
	struct jaln_connection * conn;
	conn = jaln_connection_create();
	assert_not_equals((void *) NULL, conn);
	assert_equals((void *) NULL, conn->jaln_ctx);
	assert_equals((void *) NULL, conn->v_conn);
	assert_equals((void *) NULL, conn->user_data);
	jaln_connection_destroy(&conn);
}

void test_connection_destroy()
{
	replace_function(&jaln_session_unref, &fake_jaln_session_unref);
	struct jaln_connection * conn;
	conn = jaln_connection_create();
	jaln_connection_destroy(&conn);
	assert_equals((void *) NULL, conn);
}

void test_connection_destroy_does_not_crash()
{
	struct jaln_connection *conn = NULL;
	jaln_connection_destroy(NULL);
	jaln_connection_destroy(&conn);
	assert_equals((void *) NULL, conn);
}
