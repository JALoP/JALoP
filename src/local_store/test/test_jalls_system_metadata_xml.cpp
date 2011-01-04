/**
 * @file test_jalls_system_metadata_xml.cpp 
 * This file contains functions to test jalls_system_meta_data_xml.
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

// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// c++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
extern "C" {
#include <test-dept.h>
}
#include <jalop/jal_namespaces.h>
#include <iostream>
#include <list>
#include <openssl/ssl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <xercesc/util/PlatformUtils.hpp>
#include <xsec/framework/XSECProvider.hpp>
#include <xsec/framework/XSECException.hpp>

#include "jalls_system_metadata_xml.hpp"
#include "jal_xml_utils.hpp"
#include "xml_test_utils.hpp"
#include "jal_asprintf_internal.h"

XERCES_CPP_NAMESPACE_USE

#define HOSTNAME "some_host.com"
#define HOST_UUID "1b4e28ba-2fa1-11d2-883f-0016d3cca427"
#define FAKE_DIGEST_LEN 10
#define TEST_CERT  TEST_INPUT_ROOT "cert"
#define TEST_RSA_KEY  TEST_INPUT_ROOT "rsa_key"

#define APP_PID 99223
#define APP_UID 0
#define USER_FD -1

static XMLCh *dsig_uri;
static XMLCh *dsig_manifest;
static XMLCh *jid;
static uint8_t fake_dgst[FAKE_DIGEST_LEN] = { 0,1,2,3,4,5,6,7,8,9 };
static DOMDocument *doc;

static X509 *cert;
static RSA *key;
static int socks[2];

std::list<const char*> schemas;

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
	doc = NULL;
	XMLPlatformUtils::Initialize();
	XSECPlatformUtils::Initialise();
	SSL_library_init();

	dsig_uri = XMLString::transcode(JAL_XMLDSIG_URI);
	dsig_manifest = XMLString::transcode("Manifest");
	jid = XMLString::transcode("JID");
	socketpair(AF_UNIX, SOCK_STREAM, 0, socks);

	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_SYS_META_SCHEMA);
	load_key_and_cert();
}
extern "C" void teardown()
{
	schemas.clear();
	if (doc) {
		doc->release();
	}
	RSA_free(key);
	X509_free(cert);
	XMLString::release(&dsig_uri);
	XMLString::release(&dsig_manifest);
	XMLString::release(&jid);
	XSECPlatformUtils::Terminate();
	XMLPlatformUtils::Terminate();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}
extern "C" void test_create_system_metadata_fails_with_bad_input()
{
	int ret;
	ret = jalls_create_system_metadata((jalls_data_type)(JALLS_LOG + 1), HOSTNAME, HOST_UUID,
			USER_FD, APP_PID, APP_UID, &doc);
	assert_not_equals(0, ret);
	ret = jalls_create_system_metadata((jalls_data_type)(JALLS_JOURNAL - 1), HOSTNAME, HOST_UUID,
			USER_FD, APP_PID, APP_UID, &doc);
	assert_not_equals(0, ret);
	ret = jalls_create_system_metadata(JALLS_JOURNAL, NULL, HOST_UUID,
			USER_FD, APP_PID, APP_UID, &doc);
	assert_not_equals(0, ret);
	ret = jalls_create_system_metadata(JALLS_JOURNAL, HOSTNAME, NULL,
			USER_FD, APP_PID, APP_UID, &doc);
	assert_not_equals(0, ret);
	ret = jalls_create_system_metadata(JALLS_JOURNAL, HOSTNAME, HOST_UUID,
			-1, APP_PID, APP_UID, &doc);
	assert_not_equals(0, ret);
	ret = jalls_create_system_metadata(JALLS_JOURNAL, HOSTNAME, HOST_UUID,
			USER_FD, -1, APP_UID, &doc);
	assert_not_equals(0, ret);
	ret = jalls_create_system_metadata(JALLS_JOURNAL, HOSTNAME, HOST_UUID,
			USER_FD, APP_PID, -1, &doc);
	assert_not_equals(0, ret);
	ret = jalls_create_system_metadata(JALLS_JOURNAL, HOSTNAME, HOST_UUID,
			USER_FD, APP_PID, APP_UID, NULL);
	assert_not_equals(0, ret);
	doc = (DOMDocument *)0xdeadbeef;
	ret = jalls_create_system_metadata(JALLS_JOURNAL, HOSTNAME, HOST_UUID,
			USER_FD, APP_PID, APP_UID, &doc);
	assert_not_equals(0, ret);
	doc = NULL;
}

extern "C" void test_create_system_metadata_generates_valid_document()
{
	int ret = -1;
	ret = jalls_create_system_metadata(JALLS_JOURNAL, HOSTNAME, HOST_UUID,
			socks[0], APP_PID, APP_UID, &doc);
	assert_equals(0, ret);

	DOMElement *root = doc->getDocumentElement();
	assert_not_equals((DOMElement*) NULL, root);
	assert_tag_equals("JALRecord", root);

	const XMLCh *id = root->getAttribute(jid);

	DOMElement *manifest = doc->createElementNS(dsig_uri, dsig_manifest);

	DOMElement *ref_elm = NULL;
	ret = jal_create_reference_elem("http://some/reference", "http://digest/method",
			fake_dgst, FAKE_DIGEST_LEN, doc, &ref_elm);
	assert_equals(JAL_OK, ret);

	manifest->appendChild(ref_elm);
	root->appendChild(manifest);

	ret = jal_add_signature_block(key, cert, doc,
		root, manifest, id);
	assert_equals(JAL_OK, ret);

	// With the manifest and signature block, it should validate.
	assert_true(validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_create_system_metadata_adds_correct_info_for_audit()
{
	int ret = -1;
	ret = jalls_create_system_metadata(JALLS_AUDIT, HOSTNAME, HOST_UUID,
			socks[0], APP_PID, APP_UID, &doc);
	assert_equals(0, ret);
	//assert_true(validate(doc, __FUNCTION__, schemas, true));
	// The document won't validate since it's missing the signature and manifest
	// elements. So, we go ahead and add them here.

	DOMElement *root = doc->getDocumentElement();
	assert_not_equals((DOMElement*) NULL, root);
	assert_tag_equals("JALRecord", root);

	DOMElement *data_type = root->getFirstElementChild();
	assert_not_equals((DOMElement*)NULL, data_type);
	assert_content_equals("audit", data_type);

	DOMElement *rec_id = data_type->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, rec_id);
	// rec_id generated randomly, so don't bother checking.

	DOMElement *hostname = rec_id->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, hostname);
	assert_content_equals(HOSTNAME, hostname);

	DOMElement *host_uuid = hostname->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, host_uuid);
	assert_content_equals(HOST_UUID, host_uuid);

	DOMElement *timestamp = host_uuid->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, timestamp);
	// timestamp generated automatically, cannot really check it here.

	char *str = NULL;
	jal_asprintf(&str, "%d", APP_PID);
	DOMElement *pid = timestamp->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, pid);
	assert_content_equals(str, pid);
	free(str);
	str = NULL;

	DOMElement *user = pid->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, user);
	assert_content_equals("0", user);
	assert_attr_equals("name", "root", user);

	DOMElement *is_null = user->getNextElementSibling();

#ifdef __HAVE_SELINUX
	security_context_t ctx;
	int err = getpeercon(socks[0], &ctx);
	assert_equals(0, err);

	DOMElement *sec_label = is_null;
	assert_not_equals((DOMElement*)NULL, sec_label);
	assert_content_equals(ctx, sec_label);
	freecon(ctx);
	is_null = sec_label->getNextElementSibling();
#endif

	assert_pointer_equals((DOMElement*)NULL, is_null);

}
extern "C" void test_create_system_metadata_adds_correct_info_for_journal()
{
	int ret = -1;
	ret = jalls_create_system_metadata(JALLS_JOURNAL, HOSTNAME, HOST_UUID,
			socks[0], APP_PID, APP_UID, &doc);
	assert_equals(0, ret);
	//assert_true(validate(doc, __FUNCTION__, schemas, true));
	// The document won't validate since it's missing the signature and manifest
	// elements. So, we go ahead and add them here.

	DOMElement *root = doc->getDocumentElement();
	assert_not_equals((DOMElement*) NULL, root);
	assert_tag_equals("JALRecord", root);

	DOMElement *data_type = root->getFirstElementChild();
	assert_not_equals((DOMElement*)NULL, data_type);
	assert_content_equals("journal", data_type);

	DOMElement *rec_id = data_type->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, rec_id);
	// rec_id generated randomly, so don't bother checking.

	DOMElement *hostname = rec_id->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, hostname);
	assert_content_equals(HOSTNAME, hostname);

	DOMElement *host_uuid = hostname->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, host_uuid);
	assert_content_equals(HOST_UUID, host_uuid);

	DOMElement *timestamp = host_uuid->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, timestamp);
	// timestamp generated automatically, cannot really check it here.

	char *str = NULL;
	jal_asprintf(&str, "%d", APP_PID);
	DOMElement *pid = timestamp->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, pid);
	assert_content_equals(str, pid);
	free(str);
	str = NULL;

	DOMElement *user = pid->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, user);
	assert_content_equals("0", user);
	assert_attr_equals("name", "root", user);

	DOMElement *is_null = user->getNextElementSibling();

#ifdef __HAVE_SELINUX
	security_context_t ctx;
	int err = getpeercon(socks[0], &ctx);
	assert_equals(0, err);

	DOMElement *sec_label = is_null;
	assert_not_equals((DOMElement*)NULL, sec_label);
	assert_content_equals(ctx, sec_label);
	freecon(ctx);
	is_null = sec_label->getNextElementSibling();
#endif

	assert_pointer_equals((DOMElement*)NULL, is_null);

}
extern "C" void test_create_system_metadata_adds_correct_info_for_log()
{
	int ret = -1;
	ret = jalls_create_system_metadata(JALLS_LOG, HOSTNAME, HOST_UUID,
			socks[0], APP_PID, APP_UID, &doc);
	assert_equals(0, ret);
	//assert_true(validate(doc, __FUNCTION__, schemas, true));
	// The document won't validate since it's missing the signature and manifest
	// elements. So, we go ahead and add them here.

	DOMElement *root = doc->getDocumentElement();
	assert_not_equals((DOMElement*) NULL, root);
	assert_tag_equals("JALRecord", root);

	DOMElement *data_type = root->getFirstElementChild();
	assert_not_equals((DOMElement*)NULL, data_type);
	assert_content_equals("log", data_type);

	DOMElement *rec_id = data_type->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, rec_id);
	// rec_id generated randomly, so don't bother checking.

	DOMElement *hostname = rec_id->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, hostname);
	assert_content_equals(HOSTNAME, hostname);

	DOMElement *host_uuid = hostname->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, host_uuid);
	assert_content_equals(HOST_UUID, host_uuid);

	DOMElement *timestamp = host_uuid->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, timestamp);
	// timestamp generated automatically, cannot really check it here.

	char *str = NULL;
	jal_asprintf(&str, "%d", APP_PID);
	DOMElement *pid = timestamp->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, pid);
	assert_content_equals(str, pid);
	free(str);
	str = NULL;

	DOMElement *user = pid->getNextElementSibling();
	assert_not_equals((DOMElement*)NULL, user);
	assert_content_equals("0", user);
	assert_attr_equals("name", "root", user);

	DOMElement *is_null = user->getNextElementSibling();

#ifdef __HAVE_SELINUX
	security_context_t ctx;
	int err = getpeercon(socks[0], &ctx);
	assert_equals(0, err);

	DOMElement *sec_label = is_null;
	assert_not_equals((DOMElement*)NULL, sec_label);
	assert_content_equals(ctx, sec_label);
	freecon(ctx);
	is_null = sec_label->getNextElementSibling();
#endif

	assert_pointer_equals((DOMElement*)NULL, is_null);

}
