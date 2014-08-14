/**
 * @file test_jaln_push.c This file contains tests for jaln_push.c functions.
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
#include "jaln_push.h"

#define BIG_N "123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789-123456789"
#define SYS_META_BUF "sys_meta_buffer"
#define APP_META_BUF "app_meta_buffer"
#define PAYLOAD_BUF "payload_buffer"

static jaln_context *jaln_ctx;
static jaln_session *sess;
static struct jaln_connection *conn;
static struct jaln_payload_feeder empty_feeder;
static uint8_t *payload_buf;
static uint8_t *sys_meta_buf;
static uint8_t *app_meta_buf;
static uint64_t payload_len;
static uint64_t sys_meta_len;
static uint64_t app_meta_len;

void setup()
{
	jaln_ctx = jaln_context_create();
	sess = jaln_session_create();
	conn = jaln_connection_create();
	conn->jaln_ctx = jaln_ctx;

	memset(&empty_feeder, 0, sizeof(empty_feeder));

	payload_buf = (uint8_t*) jal_strdup(PAYLOAD_BUF);
	sys_meta_buf = (uint8_t*) jal_strdup(SYS_META_BUF);
	app_meta_buf = (uint8_t*) jal_strdup(APP_META_BUF);
	payload_len = (uint64_t) strlen((char*) payload_buf);
	sys_meta_len = (uint64_t) strlen((char*) sys_meta_buf);
	app_meta_len = (uint64_t) strlen((char*) app_meta_buf);
}

void teardown()
{
	jaln_connection_destroy(&conn);
	jaln_context_destroy(&jaln_ctx);
	jaln_session_destroy(&sess);

	free(payload_buf);
	free(sys_meta_buf);
	free(app_meta_buf);
}

void test_jaln_send_record_fails_on_too_large_nonce()
{
	char *nonce = BIG_N;
	enum jal_status ret;

	ret = jaln_send_record(sess, nonce, sys_meta_buf, sys_meta_len, 
				app_meta_buf, app_meta_len, payload_buf, payload_len);

	assert_equals(ret, JAL_E_INVAL_NONCE);
}

void test_jaln_send_record_feeder_fails_on_too_large_nonce()
{
	char *nonce = BIG_N;
	enum jal_status ret;

	ret = jaln_send_record_feeder(sess, nonce, sys_meta_buf, sys_meta_len, app_meta_buf,
				app_meta_len, payload_len, (uint64_t) 0, &empty_feeder);

	assert_equals(ret, JAL_E_INVAL_NONCE);
}
