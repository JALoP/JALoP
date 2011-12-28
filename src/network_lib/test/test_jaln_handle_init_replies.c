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

#include <ctype.h>
#include <inttypes.h>
#include <jalop/jal_status.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_connection_callbacks.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <test-dept.h>
#include <vortex.h>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#include "jaln_channel_info.h"
#include "jaln_connection_callbacks_internal.h"
#include "jaln_context.h"
#include "jaln_digest.h"
#include "jaln_handle_init_replies.h"
#include "jaln_session.h"
#include "jaln_strings.h"

#define CH_NUM 3
#define HOSTNAME_1 "192.168.1.1"
#define HOSTNAME_2 "192.168.1.2"


struct jaln_channel_info *info = NULL;
jaln_session *sess = NULL;
static jaln_context *ctx = NULL;
static struct jaln_connection_callbacks *cb = NULL;
static enum jaln_role role = JALN_ROLE_SUBSCRIBER;
static char *hostname_1 = NULL;
static char *hostname_2 = NULL;

static VortexConnection *vortex_channel_get_connection_returns_null(
	__attribute__((unused)) VortexChannel *rec_chan)
{
	return NULL;
}

void my_connect_ack(
	const struct jaln_connect_ack *ack __attribute__((unused)),
	void *user_data __attribute__((unused)))
{
}

// VALID
static VortexMimeHeader *fake_get_mime_header(
	__attribute__((unused)) VortexFrame *frame,
	const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-message")) {
		return (VortexMimeHeader*) JALN_MSG_INIT_ACK;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_ENCODING)) {
		return (VortexMimeHeader*) JALN_ENC_XML;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_DIGEST)) {
		return (VortexMimeHeader*) JALN_DGST_SHA256;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_AGENT)) {

		return (VortexMimeHeader*) "jalop-ref/1.2.44 openssl/1.0.0d zlib/1.2.2";

	}
	return NULL;
}

static const char *fake_get_mime_content(VortexMimeHeader *header)
{
	return (char*)header;
}



void setup()
{
	ctx = jaln_context_create();

	sess = jaln_session_create();
	info = sess->ch_info;
	info->encoding = strdup("encoding");
	info->type = JALN_RTYPE_AUDIT;
	info->hostname = strdup(HOSTNAME_1);
	info->addr = strdup("addr");
	info->digest_method = strdup("digest_method");

	cb = jaln_connection_callbacks_create();

	cb->connect_ack = my_connect_ack;

	ctx->conn_callbacks = cb;
	ctx->user_data = (char *) "noob_data";

	sess->rec_chan = (VortexChannel*) 0xbadf00d;
	sess->rec_chan_num = CH_NUM;
	sess->jaln_ctx = ctx;

	const char duplicate_enc[] = JALN_ENC_XML;
	jaln_register_encoding(sess->jaln_ctx, duplicate_enc);

	struct jal_digest_ctx *digest = jal_sha256_ctx_create();
	free(digest->algorithm_uri);
	digest->algorithm_uri = NULL;
	digest->algorithm_uri = jal_strdup(JALN_DGST_SHA256);

	jaln_register_digest_algorithm(
		sess->jaln_ctx, digest);

	hostname_1 = strdup(HOSTNAME_1);
	hostname_2 = strdup(HOSTNAME_2);

	jaln_ctx_add_session_no_lock(ctx, sess);

	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_frame_mime_header_content, fake_get_mime_content);
	replace_function(vortex_channel_get_connection,
		vortex_channel_get_connection_returns_null);

}

void teardown()
{
	jaln_session_destroy(&sess);

	free(hostname_1);
	free(hostname_2);
	restore_function(vortex_frame_get_mime_header);
	restore_function(vortex_frame_mime_header_content);
	restore_function(axl_list_lookup);
	restore_function(vortex_channel_get_connection);
	restore_function(axl_list_is_empty);
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

// INVALID, NULL FOR AGENT
static VortexMimeHeader *fake_get_mime_header_returns_null_for_agent(
	__attribute__((unused)) VortexFrame *frame,
	const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-message")) {
		return (VortexMimeHeader*) JALN_MSG_INIT_ACK;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_ENCODING)) {
		return (VortexMimeHeader*) JALN_ENC_XML;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_DIGEST)) {
		return (VortexMimeHeader*) JALN_DGST_SHA256;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_AGENT)) {

		return NULL;

	}
	return NULL;
}

// INVALID, NULL FOR ENCODING
static VortexMimeHeader *fake_get_mime_header_returns_null_for_encoding(
	__attribute__((unused)) VortexFrame *frame,
	const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-message")) {
		return (VortexMimeHeader*) JALN_MSG_INIT_ACK;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_ENCODING)) {
		return (VortexMimeHeader*) NULL;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_DIGEST)) {
		return (VortexMimeHeader*) JALN_DGST_SHA256;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_AGENT)) {

		return (VortexMimeHeader*) "jalop-ref/1.2.44 openssl/1.0.0d zlib/1.2.2";

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

// INVALID, Returned a DIGEST value, expected an ENCODING value.
static VortexMimeHeader *fake_get_mime_header_returns_dgst_for_encoding(
	__attribute__((unused)) VortexFrame *frame,
	const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-message")) {
		return (VortexMimeHeader*) JALN_MSG_INIT_ACK;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_ENCODING)) {
		return (VortexMimeHeader*) JALN_DGST_SHA256;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_DIGEST)) {
		return (VortexMimeHeader*) JALN_DGST_SHA256;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_AGENT)) {

		return (VortexMimeHeader*) "jalop-ref/1.2.44 openssl/1.0.0d zlib/1.2.2";

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

// INVALID, NULL FOR DIGEST
static VortexMimeHeader *fake_get_mime_header_returns_null_for_digest(
	__attribute__((unused)) VortexFrame *frame,
	const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-message")) {
		return (VortexMimeHeader*) JALN_MSG_INIT_ACK;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_ENCODING)) {
		return (VortexMimeHeader*) JALN_ENC_XML;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_DIGEST)) {
		return (VortexMimeHeader*) NULL;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_AGENT)) {

		return (VortexMimeHeader*) "jalop-ref/1.2.44 openssl/1.0.0d zlib/1.2.2";

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

// INVALID, ENC for DIGEST
static VortexMimeHeader *fake_get_mime_header_returns_enc_for_digest(
	__attribute__((unused)) VortexFrame *frame,
	const char *header_name)
{
	if (!frame) {
		return NULL;
	}
	if (0 == strcasecmp(header_name, "jal-message")) {
		return (VortexMimeHeader*) JALN_MSG_INIT_ACK;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_ENCODING)) {
		return (VortexMimeHeader*) JALN_ENC_XML;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_DIGEST)) {
		return (VortexMimeHeader*) JALN_ENC_XML;

	} else if (0 == strcasecmp(header_name, JALN_HDRS_AGENT)) {

		return (VortexMimeHeader*) "jalop-ref/1.2.44 openssl/1.0.0d zlib/1.2.2";

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
	assert_equals(0, strcmp(HOSTNAME_1, nack->ch_info->hostname));
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

	assert_equals(0, strcmp(HOSTNAME_1, nack->ch_info->hostname));
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

	assert_equals(0, strcmp(HOSTNAME_1, nack->ch_info->hostname));
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

	assert_equals(0, strcmp(HOSTNAME_1, nack->ch_info->hostname));
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

	assert_equals(0, strcmp(HOSTNAME_1, nack->ch_info->hostname));
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

	sess->jaln_ctx = NULL;
	ret = jaln_handle_initialize_nack(sess, frame);
	assert_equals(0, ret);
	sess->jaln_ctx = ctx;

	sess->jaln_ctx->conn_callbacks = NULL;
	ret = jaln_handle_initialize_nack(sess, frame);
	sess->jaln_ctx->conn_callbacks = cb;
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
	sess->jaln_ctx->conn_callbacks->connect_nack = &mock_connect_nack_success_only_unauthorized_mode;

	replace_function(&vortex_frame_get_mime_header, &mock_vortex_frame_get_mime_header_pass_on_unauthorized_mode);

	ret = jaln_handle_initialize_nack(sess, frame);

	assert_equals(1, ret);
}

void test_jaln_handle_initialize_nack_success_only_unsupported_mode_supported()
{
	VortexFrame *frame = (VortexFrame *) "dummy";
	int ret=0;
	sess->jaln_ctx->conn_callbacks->connect_nack = &mock_connect_nack_success_only_unsupported_mode;

	replace_function(&vortex_frame_get_mime_header, &mock_vortex_frame_get_mime_header_pass_on_unsupported_mode);

	ret = jaln_handle_initialize_nack(sess, frame);

	assert_equals(1, ret);
}

void test_jaln_handle_initialize_nack_success_only_unsupported_encoding_supported()
{
	VortexFrame *frame = (VortexFrame *) "dummy";
	int ret=0;
	sess->jaln_ctx->conn_callbacks->connect_nack = &mock_connect_nack_success_only_unsupported_encoding;

	replace_function(&vortex_frame_get_mime_header, &mock_vortex_frame_get_mime_header_pass_on_unsupported_encoding);

	ret = jaln_handle_initialize_nack(sess, frame);

	assert_equals(1, ret);
}

void test_jaln_handle_initialize_nack_success_only_unsupported_digest_supported()
{
	VortexFrame *frame = (VortexFrame *) "dummy";
	int ret=0;
	sess->jaln_ctx->conn_callbacks->connect_nack = &mock_connect_nack_success_only_unsupported_digest;

	replace_function(&vortex_frame_get_mime_header, &mock_vortex_frame_get_mime_header_pass_on_unsupported_digest);

	ret = jaln_handle_initialize_nack(sess, frame);

	assert_equals(1, ret);
}

void test_jaln_handle_initialize_ack_succeeds()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_channel_get_connection,
		vortex_channel_get_connection_returns_null);

	assert_equals(axl_true,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_fails_bad_params()
{
	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_channel_get_connection,
		vortex_channel_get_connection_returns_null);

	// ERR1 - NULL jaln_session
	assert_equals(axl_false,
			jaln_handle_initialize_ack(NULL, role,
				(VortexFrame*) 0xbadf00d));

	sess->rec_chan = NULL; // Invalidate rec_chan

	// ERR1 - NULL rec_chan
	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
	sess->rec_chan = (VortexChannel*) 0xbadf00d; // Restore rec_chan

	// ERR2 - NULL VortexFrame
	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				NULL));

	jaln_connection_callbacks_destroy(
		&(sess->jaln_ctx->conn_callbacks)); // Invalidate callbacks

	// ERR2 - NULL callbacks
	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));

	// Restore callbacks
	sess->jaln_ctx->conn_callbacks = jaln_connection_callbacks_create();
	sess->jaln_ctx->conn_callbacks->connect_ack = my_connect_ack;

	// Invalidate context
	jaln_context *tmp = sess->jaln_ctx;
	sess->jaln_ctx = NULL;

	// ERR2 - NULL jaln_ctx
	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));

	sess->jaln_ctx = tmp; // Restore context
	tmp = NULL;

	// Verify complete restore worked
	assert_equals(axl_true,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));

	jaln_channel_info_destroy(&sess->ch_info); // Invalidate ch_info

	// ERR2 - NULL ch_info
	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_fails_null_digest_and_encoding()
{
	replace_function(vortex_channel_get_connection,
		vortex_channel_get_connection_returns_null);

	replace_function(vortex_frame_get_mime_header,
		fake_get_mime_header_returns_null_for_digest);

	// ERR3 - NULL digest
	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));

	replace_function(vortex_frame_get_mime_header,
		fake_get_mime_header_returns_null_for_encoding);

	// ERR3 - NULL encoding
	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_succeeds_null_agent()
{
	replace_function(vortex_frame_get_mime_header,
		fake_get_mime_header_returns_null_for_agent);

	// NO ERR
	assert_equals(axl_true,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_fails_empty_axlLists_bad_encoding()
{
	axl_list_remove(sess->jaln_ctx->xml_encodings, JALN_ENC_XML);

	replace_function(vortex_frame_get_mime_header,
		fake_get_mime_header_returns_dgst_for_encoding);

	// ERR4 - Empty list + unrecognized encoding
	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_succeeds_empty_axlLists_good_encoding()
{
	axl_list_remove(sess->jaln_ctx->xml_encodings, JALN_ENC_XML);

	replace_function(vortex_frame_get_mime_header,
		fake_get_mime_header);

	// NO ERR - Empty list + recognized encoding
	assert_equals(axl_true,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_fails_empty_axlLists_bad_digest()
{
	struct jal_digest_ctx *digest = jal_sha256_ctx_create();
	free(digest->algorithm_uri);
	digest->algorithm_uri = NULL;
	digest->algorithm_uri = jal_strdup(JALN_DGST_SHA256);

	axl_list_remove(sess->jaln_ctx->dgst_algs, digest);

	replace_function(vortex_frame_get_mime_header,
		fake_get_mime_header_returns_enc_for_digest);

	// ERR6 - Empty list + unrecognized digest
	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
	free(digest->algorithm_uri);
	free(digest);
}

void test_jaln_handle_initialize_ack_succeeds_empty_axlLists_good_digest()
{
	struct jal_digest_ctx *digest = jal_sha256_ctx_create();
	free(digest->algorithm_uri);
	digest->algorithm_uri = NULL;
	digest->algorithm_uri = jal_strdup(JALN_DGST_SHA256);

	axl_list_remove(sess->jaln_ctx->dgst_algs, digest);

	replace_function(vortex_frame_get_mime_header,
		fake_get_mime_header);

	// NO ERR - Empty list + recognized digest
	assert_equals(axl_true,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
	free(digest->algorithm_uri);
	free(digest);
}

void test_jaln_handle_initialize_ack_fails_unrecognized_digest()
{
	replace_function(vortex_frame_get_mime_header,
		fake_get_mime_header_returns_enc_for_digest);

	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_fails_unrecognized_encoding()
{
	replace_function(vortex_frame_get_mime_header,
		fake_get_mime_header_returns_dgst_for_encoding);

	assert_equals(axl_false,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_succeeds_null_userdata()
{
	sess->jaln_ctx->user_data = NULL;

	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_channel_get_connection,
		vortex_channel_get_connection_returns_null);

	assert_equals(axl_true,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_succeeds_null_chinfo_addr()
{
	sess->ch_info->addr = NULL;

	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_channel_get_connection,
		vortex_channel_get_connection_returns_null);

	assert_equals(axl_true,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_succeeds_null_chinfo_hostname()
{
	free(sess->ch_info->hostname);
	sess->ch_info->hostname = NULL;

	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_channel_get_connection,
		vortex_channel_get_connection_returns_null);

	assert_equals(axl_true,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

void test_jaln_handle_initialize_ack_succeeds_unset_role()
{
	role = JALN_ROLE_UNSET;

	replace_function(vortex_frame_get_mime_header, fake_get_mime_header);
	replace_function(vortex_channel_get_connection,
		vortex_channel_get_connection_returns_null);

	assert_equals(axl_true,
			jaln_handle_initialize_ack(sess, role,
				(VortexFrame*) 0xbadf00d));
}

