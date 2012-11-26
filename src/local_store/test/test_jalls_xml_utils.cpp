/**
 * @file test_jalls_xml_utils.cpp This file contains functions to test the
 * jalls xml utils functions..
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// c++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
extern "C" {
#include <test-dept.h>
}

#include <stdio.h>

#include<list>

#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <jalop/jal_namespaces.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

#include "jal_alloc.h"
#include "jalls_xml_utils.hpp"
#include "jalls_handler.h"

#define BAD_BUFFER "<qwerty/>"
#define EVENT_ID "event-123-xyz"

#define TEST_RSA_KEY  TEST_INPUT_ROOT "rsa_key"
#define TEST_CERT  TEST_INPUT_ROOT "cert"
#define TEST_CERT_AND_KEY  TEST_INPUT_ROOT "cert_and_key"

#define ID_NAME "xml:" LOCLA_ID_NAME
#define LOCAL_ID_NAME "id"
#define ID_NS "http://www.w3.org/XML/1998/namespace"

#define TRANSFORM "Transform"
#define TRANSFORMS "Transforms"
#define CANON_ALG "http://www.w3.org/2006/12/xml-c14n11#WithComments"
#define ALGORITHM "Algorithm"
#define DIGEST_METHOD "DigestMethod"
#define DIGEST_VALUE "DigestValue"
#define REFERENCE "Reference"
#define URI "URI"

#define EXAMPLE_URI "file:///somefile"
#define EXAMPLE_BAD_URI "bad uri"
#define EXAMPLE_DIGEST_METHOD "some digest method"

#define NAMESPACE "http://foo.org/bar/"
#define COMMENT "This is a comment, but should still show up in the canonicalized document"
#define TAG "sometag"

#define ID_STR "foobar_123444"
#define XPOINTER_ID_STR "#xpointer(id('" ID_STR "'))"

#define EXPECTED_SIGNING_DGST_VALUE "Tv+xVpQnAxQYuhWNG8hG2zBXRG5Z5kThWM5UGEaA/jQ="
#define EXPECTED_MODULUS "3PRI+qegjHCd70xtRMPzknUDqY6iH93XJwfuGqXguiEB8n3dxaZu1ZNzMe1BHpGje2RPaRr5EXBK\nAXMPnw6MXQ=="
#define EXPECTED_EXPONENT "AQAB"

static struct jal_digest_ctx *dgst_ctx = NULL;

static X509 *cert;
static RSA *key;

static const uint8_t EXPECTED_DGST[] = { 0xca, 0x60, 0x88, 0xd0, 0xab,
	0x26, 0x59, 0x66, 0xa7, 0x5b, 0xbf, 0xc2, 0x24, 0xc8, 0xb3,
	0xaa, 0x29, 0x85, 0xcb, 0x67, 0xfb, 0x3d, 0xd8, 0xbf, 0x8d,
	0x48, 0xf0, 0x16, 0xff, 0xfd, 0xf7, 0x76};

std::list<const char*> schemas;

uint8_t *buffer = NULL;
long buff_len = 0;

void load_key_and_cert()
{
	FILE *fp;
	fp = fopen(TEST_CERT, "r");
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	fp = fopen(TEST_RSA_KEY, "r");
	key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
}

extern "C" void setup()
{
	SSL_library_init();

	dgst_ctx = jal_sha256_ctx_create();
}

extern "C" void teardown()
{
	free(buffer);
	jal_digest_ctx_destroy(&dgst_ctx);

	X509_free(cert);
	RSA_free(key);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

