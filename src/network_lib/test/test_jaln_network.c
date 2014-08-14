/**
 * @file test_jaln_network.c This file contains tests for jaln_network.c functions.
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
#include <test-dept.h>
#include <string.h>

#include "jal_alloc.h"


#include "jaln_context.h"
#include "jaln_connection.h"
#include "jaln_session.h"

static jaln_context *jaln_ctx;
static jaln_session *sess;
static struct jaln_connection *conn;

void setup()
{
	jaln_ctx = jaln_context_create();
	sess = jaln_session_create();
	conn = jaln_connection_create();
	conn->jaln_ctx = jaln_ctx;
}

void teardown()
{
	jaln_connection_destroy(&conn);
	jaln_context_destroy(&jaln_ctx);
	jaln_session_destroy(&sess);
}

void test_jaln_disconnect_works()
{
	char *key = strdup("hostname");
	axlList *sessions = NULL;
	jaln_session *sess2 = NULL;

	sess2 = jaln_session_create();

	assert_equals(axl_false, sess->closing);
	assert_equals(axl_false, sess2->closing);

	sessions = jaln_session_list_create();
	axl_hash_insert_full(jaln_ctx->sessions_by_conn, key, free, sessions, jaln_axl_list_destroy_wrapper);
	axl_list_append(sessions, sess);
	axl_list_append(sessions, sess2);
	jaln_disconnect(conn);
	assert_equals(axl_true, sess->closing);
	assert_equals(axl_true, sess2->closing);
	jaln_session_destroy(&sess2);
}

void test_jaln_disconnect_fails_cleanly_on_bad_input()
{
	jaln_disconnect(NULL);
	conn->jaln_ctx = NULL;
	jaln_disconnect(conn);
}
