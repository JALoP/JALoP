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
#define NOT_XML_STRING "WakaWakaWaka"
#define VALID_XML "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?><someNode/>"

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

	// NULL context
	ret = jalp_audit(NULL, app_meta, buffer, strlen((char*)buffer));
	assert_equals(JAL_E_INVAL, ret);

	// NULL app_meta does NOT cause a failure
	ret = jalp_audit(ctx, NULL, buffer, strlen((char*)buffer));
	assert_equals(JAL_OK, ret);

	// NULL buffer
	ret = jalp_audit(ctx, app_meta, NULL, strlen((char*)buffer));
	assert_equals(JAL_E_INVAL, ret);

	// 0 length
	ret = jalp_audit(ctx, app_meta, buffer, 0);
	assert_equals(JAL_E_INVAL, ret);

	// NULL context and app_meta
	ret = jalp_audit(NULL, NULL, buffer, strlen((char*)buffer));
	assert_equals(JAL_E_INVAL, ret);

	// NULL context and buffer
	ret = jalp_audit(NULL, app_meta, NULL, strlen((char*)buffer));
	assert_equals(JAL_E_INVAL, ret);

	// NULL context and 0 length
	ret = jalp_audit(NULL, app_meta, buffer, 0);
	assert_equals(JAL_E_INVAL, ret);

	// NULL app_meta and buffer
	ret = jalp_audit(ctx, NULL, NULL, strlen((char*)buffer));
	assert_equals(JAL_E_INVAL, ret);

	// NULL app_meta and 0 length
	ret = jalp_audit(ctx, NULL, buffer, 0);
	assert_equals(JAL_E_INVAL, ret);

	// NULL buffer and length
	ret = jalp_audit(ctx, app_meta, NULL, 0);
	assert_equals(JAL_E_INVAL, ret);

	// NULL ctx, app_meta, and buffer
	ret = jalp_audit(NULL, NULL, NULL, strlen((char*)buffer));
	assert_equals(JAL_E_INVAL, ret);

	// NULL ctx, app_meta, and 0 length
	ret = jalp_audit(NULL, NULL, buffer, 0);
	assert_equals(JAL_E_INVAL, ret);

	// NULL ctx, buffer, and 0 length
	ret = jalp_audit(NULL, app_meta, NULL, 0);
	assert_equals(JAL_E_INVAL, ret);

	// NULL app_meta, buffer, and 0 length
	ret = jalp_audit(ctx, NULL, NULL, 0);
	assert_equals(JAL_E_INVAL, ret);

	// Flag for validation to trigger XML parsing and validation
	if(!jalp_context_flag_isSet(ctx, JAF_VALIDATE_XML)) {
		jalp_context_set_flag(ctx, JAF_VALIDATE_XML);
	}

	// Demonstrate that non-xml data produces JAL_E_XML_PARSE
	ret = jalp_audit(ctx, app_meta, (uint8_t*)NOT_XML_STRING, strlen(NOT_XML_STRING));
	assert_equals(JAL_E_XML_PARSE, ret);

	// Demonstrate that valid xml that doesn't conform to the schema produces JAL_E_XML_PARSE
	// Must be inspected with a debugger or prints to differentiate from previous
	ret = jalp_audit(ctx, app_meta, (uint8_t*)VALID_XML, strlen(VALID_XML));
	assert_equals(JAL_E_XML_PARSE, ret);

	// Just for kicks, verify that we can get a good return with all valid parameters
	ret = jalp_audit(ctx, app_meta, buffer, strlen((char*)buffer));
	assert_equals(JAL_OK, ret);
}

void test_jalp_digest_audit_record_returns_schema_err_with_invalid_schema_root()
{
	// JALoP will fail to find the desired schemas (eventList.xsd or events.xsd)
	free(ctx->schema_root); // init'd in setup()
	ctx->schema_root = jal_strdup("/");
	ctx->flags = JAF_VALIDATE_XML;
	ctx->jaf_validCtxt = NULL;

	enum jal_status ret = jalp_audit(ctx, app_meta, (uint8_t *)VALID_XML, strlen(VALID_XML));

	free(ctx->schema_root);
	ctx->schema_root = jal_strdup(SCHEMAS_ROOT);

	assert_equals(JAL_E_INVAL, ret);
}

void test_audit_returns_inval_with_null_schema_root()
{
	// Setting schema_root to NULL causes JAL_E_INVAL during NULL checks
	ctx->schema_root = NULL;
	ctx->flags = JAF_VALIDATE_XML;
	ctx->jaf_validCtxt = NULL;

	enum jal_status ret = jalp_audit(ctx, app_meta, (uint8_t *)VALID_XML, strlen(VALID_XML));

	assert_equals(JAL_E_INVAL, ret);
}

void test_audit_works_with_good_input()
{
	ctx->flags = JAF_VALIDATE_XML;
	ctx->jaf_validCtxt = NULL;
	ctx->signing_key = 0;

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

void test_audit_schema_validation_failure()
{
	// Exactly the same as the good_input test, but with xml data that is valid
	// but not matching the schema
	ctx->flags = JAF_VALIDATE_XML;
	ctx->jaf_validCtxt = NULL;
	ctx->signing_key = 0;

	expected_data_len = buff_len;
	expected_meta_len = 1;
	enum jal_status ret = jalp_audit(ctx, app_meta, (uint8_t*)VALID_XML, strlen(VALID_XML));
	assert_equals(JAL_E_XML_PARSE, ret);

	assert_false(ctx_is_null);
	assert_false(message_type_wrong);
	assert_false(data_is_null);
	assert_false(data_len_wrong);
	assert_false(meta_is_null);
	assert_false(meta_len_wrong);
	assert_false(fd_is_set);
}
