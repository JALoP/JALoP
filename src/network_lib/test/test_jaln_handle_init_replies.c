/**
 * @file This file contains tests for jaln_handle_init_replies.c functions.
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
 **/

#include "jaln_handle_init_replies.h"
#include "jaln_context.h"
#include "jaln_channel_info.h"
#include "jal_alloc.h"
#include "jaln_strings.h"

#include "jaln_session.h"

#include <test-dept.h>
#include <string.h>

struct jaln_channel_info *info = NULL;
struct jaln_session *sess = NULL;

void teardown()
{
        restore_function(&vortex_frame_get_mime_header);
	jaln_session_destroy(&sess);
}

void setup()
{
	sess = jaln_session_create();
	info = sess->ch_info;
	info->hostname = strdup("hostname");
	info->addr = strdup("addr");
	info->encoding = strdup("encoding");
	info->digest_method = strdup("digest_method");
	info->type = JALN_RTYPE_AUDIT;
}

VortexMimeHeader * mock_vortex_frame_get_mime_header_always_pass( __attribute__((unused)) VortexFrame * frame, __attribute__((unused)) const char * mime_header)
{
	return (VortexMimeHeader *) "dummy";
}

VortexMimeHeader * mock_vortex_frame_get_mime_header_pass_on_unauthorized_mode( __attribute__((unused)) VortexFrame * frame, __attribute__((unused)) const char * mime_header)
{
	if (!strcmp(mime_header, JALN_HDRS_UNAUTHORIZED_MODE))
	{
		return (VortexMimeHeader *) "dummy";
	}
	return NULL;
}

VortexMimeHeader * mock_vortex_frame_get_mime_header_pass_on_unsupported_mode( __attribute__((unused)) VortexFrame * frame, __attribute__((unused)) const char * mime_header)
{
	if (!strcmp(mime_header, JALN_HDRS_UNSUPPORTED_MODE))
	{
		return (VortexMimeHeader *) "dummy";
	}
	return NULL;
}

VortexMimeHeader * mock_vortex_frame_get_mime_header_pass_on_unsupported_encoding( __attribute__((unused)) VortexFrame * frame, __attribute__((unused)) const char * mime_header)
{
	if (!strcmp(mime_header, JALN_HDRS_UNSUPPORTED_ENCODING))
	{
		return (VortexMimeHeader *) "dummy";
	}
	return NULL;
}

VortexMimeHeader * mock_vortex_frame_get_mime_header_pass_on_unsupported_digest( __attribute__((unused)) VortexFrame * frame, __attribute__((unused)) const char * mime_header)
{
	if (!strcmp(mime_header, JALN_HDRS_UNSUPPORTED_DIGEST))
	{
		return (VortexMimeHeader *) "dummy";
	}
	return NULL;
}

VortexMimeHeader * mock_vortex_frame_get_mime_header_always_fail( __attribute__((unused)) VortexFrame * frame, __attribute__((unused)) const char * mime_header)
{
        return NULL;
}

void mock_connect_nack_success( const struct jaln_connect_nack *nack, __attribute__((unused)) void *user_data)
{
	assert_equals(4, nack->error_cnt);
	assert_equals(0, strcmp(nack->error_list[0], JALN_HDRS_UNAUTHORIZED_MODE));
	assert_equals(0, strcmp(nack->error_list[1], JALN_HDRS_UNSUPPORTED_MODE));
	assert_equals(0, strcmp(nack->error_list[2], JALN_HDRS_UNSUPPORTED_ENCODING));
	assert_equals(0, strcmp(nack->error_list[3], JALN_HDRS_UNSUPPORTED_DIGEST));
	assert_equals(0, strcmp("hostname", nack->ch_info->hostname));
	assert_equals(0, strcmp("addr", nack->ch_info->addr));
	assert_equals(0, strcmp("encoding", nack->ch_info->encoding));
	assert_equals(0, strcmp("digest_method", nack->ch_info->digest_method));
	assert_equals(JALN_RTYPE_AUDIT, nack->ch_info->type);
	return;
}

void mock_connect_nack_success_only_unauthorized_mode( const struct jaln_connect_nack *nack, __attribute__((unused)) void *user_data)
{
	assert_equals(1, nack->error_cnt);
	assert_equals(0, strcmp(nack->error_list[0], JALN_HDRS_UNAUTHORIZED_MODE));

	assert_equals(0, strcmp("hostname", nack->ch_info->hostname));
	assert_equals(0, strcmp("addr", nack->ch_info->addr));
	assert_equals(0, strcmp("encoding", nack->ch_info->encoding));
	assert_equals(0, strcmp("digest_method", nack->ch_info->digest_method));
	assert_equals(JALN_RTYPE_AUDIT, nack->ch_info->type);

	return;
}

void mock_connect_nack_success_only_unsupported_mode( const struct jaln_connect_nack *nack, __attribute__((unused)) void *user_data)
{
	assert_equals(1, nack->error_cnt);
	assert_equals(0, strcmp(nack->error_list[0], JALN_HDRS_UNSUPPORTED_MODE));

	assert_equals(0, strcmp("hostname", nack->ch_info->hostname));
	assert_equals(0, strcmp("addr", nack->ch_info->addr));
	assert_equals(0, strcmp("encoding", nack->ch_info->encoding));
	assert_equals(0, strcmp("digest_method", nack->ch_info->digest_method));
	assert_equals(JALN_RTYPE_AUDIT, nack->ch_info->type);

	return;
}

void mock_connect_nack_success_only_unsupported_encoding( const struct jaln_connect_nack *nack, __attribute__((unused)) void *user_data)
{
	assert_equals(1, nack->error_cnt);
	assert_equals(0, strcmp(nack->error_list[0], JALN_HDRS_UNSUPPORTED_ENCODING));

	assert_equals(0, strcmp("hostname", nack->ch_info->hostname));
	assert_equals(0, strcmp("addr", nack->ch_info->addr));
	assert_equals(0, strcmp("encoding", nack->ch_info->encoding));
	assert_equals(0, strcmp("digest_method", nack->ch_info->digest_method));
	assert_equals(JALN_RTYPE_AUDIT, nack->ch_info->type);

	return;
}

void mock_connect_nack_success_only_unsupported_digest( const struct jaln_connect_nack *nack, __attribute__((unused)) void *user_data)
{
	assert_equals(1, nack->error_cnt);
	assert_equals(0, strcmp(nack->error_list[0], JALN_HDRS_UNSUPPORTED_DIGEST));

	assert_equals(0, strcmp("hostname", nack->ch_info->hostname));
	assert_equals(0, strcmp("addr", nack->ch_info->addr));
	assert_equals(0, strcmp("encoding", nack->ch_info->encoding));
	assert_equals(0, strcmp("digest_method", nack->ch_info->digest_method));
	assert_equals(JALN_RTYPE_AUDIT, nack->ch_info->type);

	return;
}


void test_jaln_handle_initialize_nack_null_params_return_0()
{
	VortexFrame *frame = (VortexFrame *) "dummy";
	int ret=0;

	replace_function(&vortex_frame_get_mime_header, &mock_vortex_frame_get_mime_header_always_pass);

	ret = jaln_handle_initialize_nack(NULL, frame);
	assert_equals(0, ret);

	ret = jaln_handle_initialize_nack(sess, NULL);
	assert_equals(0, ret);

	ret = jaln_handle_initialize_nack(sess, frame);
	assert_equals(0, ret);

	sess->jaln_ctx = jaln_context_create();
	ret = jaln_handle_initialize_nack(sess, frame);
        assert_equals(0, ret);
}

void test_jaln_handle_initialize_nack_success_all_supported()
{
	VortexFrame *frame = (VortexFrame *) "dummy";
        int ret=0;
	sess->jaln_ctx = jaln_context_create();
	sess->jaln_ctx->conn_callbacks = jaln_connection_callbacks_create();
	sess->jaln_ctx->conn_callbacks->connect_nack = &mock_connect_nack_success;

	replace_function(&vortex_frame_get_mime_header, &mock_vortex_frame_get_mime_header_always_pass);
	
	ret = jaln_handle_initialize_nack(sess, frame);

	assert_equals(1, ret);
}

void test_jaln_handle_initialize_nack_success_only_unathorized_mode_supported()
{
	VortexFrame *frame = (VortexFrame *) "dummy";
        int ret=0;
	sess->jaln_ctx = jaln_context_create();
	sess->jaln_ctx->conn_callbacks = jaln_connection_callbacks_create();
	sess->jaln_ctx->conn_callbacks->connect_nack = &mock_connect_nack_success_only_unauthorized_mode;

	replace_function(&vortex_frame_get_mime_header, &mock_vortex_frame_get_mime_header_pass_on_unauthorized_mode);
	
	ret = jaln_handle_initialize_nack(sess, frame);

	assert_equals(1, ret);
}

void test_jaln_handle_initialize_nack_success_only_unsupported_mode_supported()
{
	VortexFrame *frame = (VortexFrame *) "dummy";
        int ret=0;
	sess->jaln_ctx = jaln_context_create();
	sess->jaln_ctx->conn_callbacks = jaln_connection_callbacks_create();
	sess->jaln_ctx->conn_callbacks->connect_nack = &mock_connect_nack_success_only_unsupported_mode;

	replace_function(&vortex_frame_get_mime_header, &mock_vortex_frame_get_mime_header_pass_on_unsupported_mode);
	
	ret = jaln_handle_initialize_nack(sess, frame);

	assert_equals(1, ret);
}

void test_jaln_handle_initialize_nack_success_only_unsupported_encoding_supported()
{
	VortexFrame *frame = (VortexFrame *) "dummy";
        int ret=0;
	sess->jaln_ctx = jaln_context_create();
	sess->jaln_ctx->conn_callbacks = jaln_connection_callbacks_create();
	sess->jaln_ctx->conn_callbacks->connect_nack = &mock_connect_nack_success_only_unsupported_encoding;

	replace_function(&vortex_frame_get_mime_header, &mock_vortex_frame_get_mime_header_pass_on_unsupported_encoding);
	
	ret = jaln_handle_initialize_nack(sess, frame);

	assert_equals(1, ret);
}

void test_jaln_handle_initialize_nack_success_only_unsupported_digest_supported()
{
	VortexFrame *frame = (VortexFrame *) "dummy";
        int ret=0;
	sess->jaln_ctx = jaln_context_create();
	sess->jaln_ctx->conn_callbacks = jaln_connection_callbacks_create();
	sess->jaln_ctx->conn_callbacks->connect_nack = &mock_connect_nack_success_only_unsupported_digest;

	replace_function(&vortex_frame_get_mime_header, &mock_vortex_frame_get_mime_header_pass_on_unsupported_digest);
	
	ret = jaln_handle_initialize_nack(sess, frame);

	assert_equals(1, ret);
}
