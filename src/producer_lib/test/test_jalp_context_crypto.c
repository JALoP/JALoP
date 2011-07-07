/**
 * @file This file contains tests for jalp_context_crypto functions.
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
#include <jalop/jalp_context.h>
#include <jalop/jal_status.h>
#include "jalp_context_internal.h"

// Path to the test rsa keys to use.
#define TEST_RSA_KEY  TEST_INPUT_ROOT "rsa_key"
#define TEST_RSA_KEY_WITH_PASS  TEST_INPUT_ROOT "rsa_key_with_pass"

// Path to the test certs to use.
#define TEST_CERT  TEST_INPUT_ROOT "cert"
#define TEST_CERT_AND_KEY  TEST_INPUT_ROOT "cert_and_key"
#define TEST_CERT_AND_KEY_WITH_PASS  TEST_INPUT_ROOT "cert_and_key_with_pass"

// Path to a file that is not a key to use for negative testing.
// This file will definitely exist, so we will use it as a file
// that is not a key.
#define TEST_NONKEY  TEST_INPUT_ROOT "README_keys"

// Password for the key that has a password.
#define TEST_KEY_PASSWORD "pass"

static jalp_context *context = NULL;

void setup()
{
	jalp_init();
	context = jalp_context_create();
}

void teardown()
{
	jalp_context_destroy(&context);
	jalp_shutdown();
}

/**
 * Password callbacks.
 */

int pass_cb_correct_key(char *buf, int size,
		__attribute__((unused)) int rwflag,
		__attribute__((unused)) void *u)
{
	int len;

	len = strlen(TEST_KEY_PASSWORD);
	if (len < 0) {
		return 0;
	}

	// if too long, truncate
	if (len > size) {
		len = size;
	}

	memcpy(buf, TEST_KEY_PASSWORD, len);
	return len;
}

int pass_cb_incorrect_key(__attribute__((unused)) char *buf,
		__attribute__((unused))int size,
		__attribute__((unused)) int rwflag,
		__attribute__((unused)) void *u)
{
	return 0;
}

/**
 * jalp_context_load_pem_rsa() tests
 */

void test_jalp_context_load_pem_rsa_fails_with_null_input()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_rsa(NULL, NULL, NULL);
	assert_equals(ret, JAL_E_INVAL);

	ret = jalp_context_load_pem_rsa(context, NULL, NULL);
	assert_equals(ret, JAL_E_INVAL);

	ret = jalp_context_load_pem_rsa(NULL, "somekeylocation", NULL);
	assert_equals(ret, JAL_E_INVAL);
}

void test_jalp_context_load_pem_rsa_will_not_load_key_twice()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_rsa(context, TEST_RSA_KEY, NULL);
	assert_equals(ret, JAL_OK);
	assert_not_equals((jalp_context *) NULL, context);
	assert_not_equals((RSA *) NULL, context->signing_key);

	ret = jalp_context_load_pem_rsa(context, TEST_RSA_KEY, NULL);
	assert_equals(ret, JAL_E_EXISTS);
	assert_not_equals((RSA *) NULL, context->signing_key);
}

void test_jalp_context_load_pem_rsa_fails_with_nonexistant_file()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_rsa(context, "/some/file/that/does/not/exist", NULL);
	assert_equals(ret, JAL_E_FILE_OPEN);
}

void test_jalp_context_load_pem_rsa_fails_with_non_key_file()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_rsa(context, TEST_NONKEY, NULL);
	assert_equals(ret, JAL_E_READ_PRIVKEY);
}

void test_jalp_context_load_pem_rsa_suceeds_with_key()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_rsa(context, TEST_RSA_KEY, NULL);
	assert_equals(ret, JAL_OK);
	assert_not_equals((jalp_context *) NULL, context);
	assert_not_equals((RSA *) NULL, context->signing_key);
}

void test_jalp_context_load_pem_rsa_suceeds_with_password_key()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_rsa(context, TEST_RSA_KEY_WITH_PASS, pass_cb_correct_key);
	assert_equals(ret, JAL_OK);
	assert_not_equals((jalp_context *) NULL, context);
	assert_not_equals((RSA *) NULL, context->signing_key);
}

void test_jalp_context_load_pem_rsa_fails_with_password_key_wrong_password()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_rsa(context, TEST_RSA_KEY_WITH_PASS, pass_cb_incorrect_key);
	assert_equals(ret, JAL_E_READ_PRIVKEY);
}

/**
 * jalp_context_load_pem_cert() tests
 */

void test_jalp_context_load_pem_cert_fails_with_null_input()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_cert(NULL, NULL);
	assert_equals(ret, JAL_E_INVAL);

	ret = jalp_context_load_pem_cert(context, NULL);
	assert_equals(ret, JAL_E_INVAL);

	ret = jalp_context_load_pem_cert(NULL, "somekeylocation");
	assert_equals(ret, JAL_E_INVAL);
}

void test_jalp_context_load_pem_cert_fails_with_nonexistant_file()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_cert(context, "/some/file/that/does/not/exist");
	assert_equals(ret, JAL_E_FILE_OPEN);
}

void test_jalp_context_load_pem_cert_fails_with_non_key_file()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_cert(context, TEST_NONKEY);
	assert_equals(ret, JAL_E_READ_X509);
}

void test_jalp_context_load_pem_cert_suceeds_with_cert_with_key()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_cert(context, TEST_CERT_AND_KEY);
	assert_equals(ret, JAL_OK);
	assert_not_equals((jalp_context *) NULL, context);
	assert_not_equals((X509 *) NULL, context->signing_cert);
}

void test_jalp_context_load_pem_cert_suceeds_with_cert_with_key_with_pass()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_cert(context, TEST_CERT_AND_KEY_WITH_PASS);
	assert_equals(ret, JAL_OK);
	assert_not_equals((jalp_context *) NULL, context);
	assert_not_equals((X509 *) NULL, context->signing_cert);
}

void test_jalp_context_load_pem_cert_suceeds_with_cert_without_key()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_cert(context, TEST_CERT);
	assert_equals(ret, JAL_OK);
	assert_not_equals((jalp_context *) NULL, context);
	assert_not_equals((X509 *) NULL, context->signing_cert);
}

void test_jalp_context_load_pem_cert_suceeds_load_cert_twice()
{
	enum jal_status ret;

	ret = jalp_context_load_pem_cert(context, TEST_CERT_AND_KEY);
	assert_equals(ret, JAL_OK);
	assert_not_equals((jalp_context *) NULL, context);
	assert_not_equals((X509 *) NULL, context->signing_cert);

	ret = jalp_context_load_pem_cert(context, TEST_CERT_AND_KEY);
	assert_equals(ret, JAL_OK);
	assert_not_equals((jalp_context *) NULL, context);
	assert_not_equals((X509 *) NULL, context->signing_cert);
}

