/**
 * @file test_jalp_audit.c This file contains functions to test jalp_audit().
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <stdint.h>
#include <uuid/uuid.h>
#include <ctype.h>

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>
#include <openssl/ssl.h>

#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_audit.h>
#include <jalop/jalp_app_metadata.h>
#include "jal_alloc.h"
#include "jalp_connection_internal.h"

jalp_context *ctx;
static struct jalp_app_metadata *app_meta;

const char* EVENT_ID = "foo-123";

uint8_t *buffer = NULL;
long buff_len = 0;
// Path to the test rsa keys to use.
#define TEST_RSA_KEY  TEST_INPUT_ROOT "rsa_key"
#define TEST_RSA_KEY_WITH_PASS  TEST_INPUT_ROOT "rsa_key_with_pass"

// Path to the test certs to use.
#define TEST_CERT  TEST_INPUT_ROOT "cert"
#define TEST_CERT_AND_KEY  TEST_INPUT_ROOT "cert_and_key"
#define TEST_CERT_AND_KEY_WITH_PASS  TEST_INPUT_ROOT "cert_and_key_with_pass"

// Password for the key that has a password.
#define TEST_KEY_PASSWORD "pass"
#define BAD_BUFFER "<lksdjflsdkj/>"

int ctx_is_null;
int message_type_wrong;
int data_is_null;
int data_len_wrong;
int meta_is_null;
int meta_len_wrong;
int fd_is_set;
uint64_t expected_data_len;
uint64_t expected_meta_len;

enum jal_status jalp_send_buffer(jalp_context *jctx, uint16_t message_type,
		void *data, uint64_t data_len, void *meta, uint64_t meta_len, int fd)
{
	ctx_is_null = !jctx;
	message_type_wrong = (message_type != JALP_AUDIT_MSG);
	data_is_null = !data;
	data_len_wrong = data_len != expected_data_len;
	meta_is_null = !meta;
	if (expected_meta_len == 0) {
		meta_len_wrong = meta_len != 0;
	} else {
		meta_len_wrong = meta_len == 0;
	}
	fd_is_set = fd >= 0;
	return JAL_OK;
}

void setup()
{
	jalp_init();
	app_meta = jalp_app_metadata_create();
	app_meta->type = JALP_METADATA_NONE;
	app_meta->event_id = jal_strdup(EVENT_ID);

	ctx = jalp_context_create();
	struct jal_digest_ctx *dgst_ctx = jal_sha256_ctx_create();
	jalp_context_set_digest_callbacks(ctx, dgst_ctx);
	jal_digest_ctx_destroy(&dgst_ctx);

	jalp_context_load_pem_rsa(ctx, TEST_RSA_KEY, NULL);
	jalp_context_load_pem_cert(ctx, TEST_CERT_AND_KEY);

	jalp_context_init(ctx, NULL, NULL, NULL, SCHEMAS_ROOT);

	int ret = 0;
	FILE *f = NULL;
	f = fopen(TEST_INPUT_ROOT "good_audit_input.xml", "rb");

	ret = fseek(f, 0, SEEK_END);
	assert_equals(0, ret);

	buff_len = ftell(f);
	assert_true(buff_len > 0);

	ret = fseek(f, 0, SEEK_SET);
	assert_equals(0, ret);

	buffer = (uint8_t *)jal_malloc(buff_len);
	assert_not_equals(NULL, buffer);

	ret = fread(buffer, buff_len, 1, f);
	assert_not_equals(0, ret);

	fclose(f);

	ctx_is_null = 0;
	message_type_wrong = 0;
	data_is_null = 0;
	data_len_wrong = 0;
	meta_is_null = 0;
	meta_len_wrong = 0;
	fd_is_set = 0;
	expected_data_len = 0;
	expected_meta_len = 0;
	
	SSL_library_init();
	xmlSecInit();

	xmlSecCryptoDLLoadLibrary(BAD_CAST "openssl");

	xmlSecCryptoAppInit(NULL);
	xmlSecCryptoInit();
}

void teardown()
{
	jalp_app_metadata_destroy(&app_meta);
	jalp_context_destroy(&ctx);
	free(buffer);
	jalp_shutdown();

	xmlSecCryptoShutdown();
	xmlSecCryptoAppShutdown();
	xmlSecShutdown();
}

void test_audit_fails_with_bad_input()
{
	enum jal_status ret;
	ret = jalp_audit(ctx, NULL, NULL, 0);
	assert_equals(JAL_E_INVAL, ret);

	ret = jalp_audit(ctx, app_meta, NULL, 0);
	assert_equals(JAL_E_INVAL, ret);

	ret = jalp_audit(ctx, app_meta, buffer, 0);
	assert_equals(JAL_E_INVAL, ret);

	ret = jalp_audit(ctx, app_meta, (uint8_t*)BAD_BUFFER, strlen(BAD_BUFFER));
	assert_equals(JAL_E_XML_PARSE, ret);
}

#if 0
void test_audit_works_with_good_input()
{
	expected_data_len = buff_len;
	expected_meta_len = 1;
	enum jal_status ret = jalp_audit(ctx, app_meta, buffer, buff_len);
	assert_equals(JAL_OK, ret);
	assert_false(ctx_is_null);
	assert_false(message_type_wrong);
	assert_false(data_is_null);
	assert_false(data_len_wrong);
	assert_false(meta_is_null);
	assert_false(meta_len_wrong);
	assert_false(fd_is_set);
}
#endif
