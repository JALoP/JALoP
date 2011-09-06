/**
 * @file test_jaldb_context.cpp This file contains functions to test
 * jaldb_context.cpp.
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
// C++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif

extern "C" {
#include <test-dept.h>
}

#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/dom/DOM.hpp>
#include "xml_test_utils.hpp"
#include "jal_alloc.h"
#include "jaldb_context.h"
#include "jaldb_context.hpp"
#include "jaldb_strings.h"
#include "jaldb_utils.h"

#define OTHER_DB_ROOT "./testdb/"
#define OTHER_SCHEMA_ROOT "./schemas/"
#define JOURNAL_ROOT "/journal/"
#define AUDIT_SYS_TEST_XML_DOC "./test-input/domwriter_audit_sys.xml"
#define AUDIT_APP_TEST_XML_DOC "./test-input/domwriter_audit_app.xml"
#define AUDIT_TEST_XML_DOC "./test-input/domwriter_audit.xml"

XERCES_CPP_NAMESPACE_USE
using namespace DbXml;

static DOMLSParser *parser = NULL;
static DOMDocument *audit_sys_meta_doc = NULL;
static DOMDocument *audit_app_meta_doc = NULL;
static DOMDocument *audit_doc = NULL;
static jaldb_context *context = NULL;

extern "C" void setup()
{
	XMLPlatformUtils::Initialize();
	struct stat st;
	if (stat(OTHER_DB_ROOT, &st) != 0) {
		int status;
		status = mkdir(OTHER_DB_ROOT, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}
	else {
		struct dirent *d;
		DIR *dir;
		char buf[256];
		dir = opendir(OTHER_DB_ROOT);
		while ((d = readdir(dir)) != NULL) {
			sprintf(buf, "%s/%s", OTHER_DB_ROOT, d->d_name);
			remove(buf);
		}
		int ret_val;
		ret_val = closedir(dir);
	}
	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	parser = impl->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	DOMConfiguration *config = parser->getDomConfig();
	config->setParameter(XMLUni::fgDOMDatatypeNormalization, true);
	config->setParameter(XMLUni::fgDOMEntities, true);
	config->setParameter(XMLUni::fgDOMNamespaces, true);
	config->setParameter(XMLUni::fgDOMValidate, false);
	config->setParameter(XMLUni::fgXercesSchema, false);
	config->setParameter(XMLUni::fgXercesSchemaFullChecking, false);
	config->setParameter(XMLUni::fgXercesUseCachedGrammarInParse, true);
	config->setParameter(XMLUni::fgXercesCacheGrammarFromParse, false);
	config->setParameter(XMLUni::fgXercesLoadSchema, false);
	config->setParameter(XMLUni::fgXercesHandleMultipleImports, true);
	config->setParameter(XMLUni::fgXercesUserAdoptsDOMDocument, false);
	audit_sys_meta_doc = parser->parseURI(AUDIT_SYS_TEST_XML_DOC);
	audit_app_meta_doc = parser->parseURI(AUDIT_APP_TEST_XML_DOC);
	audit_doc = parser->parseURI(AUDIT_TEST_XML_DOC);
	context = jaldb_context_create();
	jaldb_context_init(context, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, true);
}

extern "C" void teardown()
{
	delete parser;
	parser = NULL;
	audit_sys_meta_doc = NULL;
	audit_app_meta_doc = NULL;
	audit_doc = NULL;
	jaldb_context_destroy(&context);
	XMLPlatformUtils::Terminate();
}

extern "C" void test_db_destroy_does_not_crash()
{
	jaldb_context *ctx = NULL;
	jaldb_context_destroy(&ctx);

	jaldb_context_destroy(NULL);
}

extern "C" void test_db_destroy_sets_ctx_to_null()
{
	jaldb_context *ctx = jaldb_context_create();
	assert_not_equals((void*) NULL, ctx);
	enum jaldb_status ret = jaldb_context_init(ctx, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, false);
	assert_equals(JALDB_OK, ret);
	jaldb_context_destroy(&ctx);
	assert_pointer_equals((void*) NULL, ctx);
}

extern "C" void test_store_confed_journal_sid_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_journal_sid(NULL, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *tmp_mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_store_confed_journal_sid(context, rhost, ser_id, &db_error_out);
	context->manager = tmp_mgr;
	free(rhost);
	free(ser_id);
	rhost = NULL;
	ser_id = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_store_confed_audit_sid_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_audit_sid(NULL, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *tmp_mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_store_confed_audit_sid(context, rhost, ser_id, &db_error_out);
	context->manager = tmp_mgr;
	assert_equals(JALDB_E_INVAL, ret);

	XmlContainer *tmp_cont = context->audit_sys_cont;
	context->audit_sys_cont = NULL;
	ret = jaldb_store_confed_audit_sid(context, rhost, ser_id, &db_error_out);
	context->audit_sys_cont = tmp_cont;
	free(rhost);
	free(ser_id);
	rhost = NULL;
	ser_id = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_store_confed_log_sid_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_log_sid(NULL, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *tmp_mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_store_confed_log_sid(context, rhost, ser_id, &db_error_out);
	context->manager = tmp_mgr;
	free(rhost);
	free(ser_id);
	rhost = NULL;
	ser_id = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_store_confed_sid_helper_returns_ok_with_valid_input()
{
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlDocument doc = context->audit_sys_cont->getDocument(JALDB_SERIAL_ID_DOC_NAME, 0);
	XmlValue attrVal(XmlValue::STRING, "12345");
	doc.setMetaData(JALDB_NS, JALDB_SERIAL_ID_NAME, attrVal);
	context->audit_sys_cont->updateDocument(doc, uc);
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("123");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_OK, ret);

	char *serid = jal_strdup("124");
	ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, serid, &db_error_out);
	free(rhost);
	free(ser_id);
	free(serid);
	rhost = NULL;
	ser_id = NULL;
	serid = NULL;
	assert_equals(JALDB_OK, ret);
}

extern "C" void test_store_confed_sid_helper_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_sid_helper(
		NULL, context->audit_conf_db, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, NULL, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, ser_id, NULL);
	free(rhost);
	free(ser_id);
	rhost = NULL;
	ser_id = NULL;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_store_confed_sid_helper_fails_with_sid_greater_than_or_equal_to_next_sid()
{
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlDocument doc = context->audit_sys_cont->getDocument(JALDB_SERIAL_ID_DOC_NAME, 0);
	XmlValue attrVal(XmlValue::STRING, "12345");
	doc.setMetaData(JALDB_NS, JALDB_SERIAL_ID_NAME, attrVal);
	context->audit_sys_cont->updateDocument(doc, uc);
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("123456");
	int db_error_out = 0;
	enum jaldb_status ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, ser_id, &db_error_out);
	assert_equals(JALDB_E_SID, ret);

	char *serid = jal_strdup("12345");
	ret = jaldb_store_confed_sid_helper(
		context->audit_sys_cont, context->audit_conf_db, rhost, serid, &db_error_out);
	free(rhost);
	free(ser_id);
	free(serid);
	rhost = NULL;
	ser_id = NULL;
	serid = NULL;
	assert_equals(JALDB_E_SID, ret);
}

extern "C" void test_insert_audit_helper_returns_ok()
{
	std::string src = "";
	XmlTransaction transaction = context->manager->createTransaction();
	XmlUpdateContext update_ctx = context->manager->createUpdateContext();
	std::string ser_id = "1";
	jaldb_status ret;
	ret = jaldb_insert_audit_helper(src, transaction, *(context->manager), update_ctx,
		*(context->audit_sys_cont), *(context->audit_app_cont), *(context->audit_cont),
		audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_OK, ret);

	XmlDocument audit_sys_document = context->audit_sys_cont->getDocument(transaction, ser_id);
	std::string content = "";
	MemBufInputSource *audit_sys_mbis = NULL;
	Wrapper4InputSource *audit_sys_wfis = NULL;
	DOMDocument *audit_sys_dom_doc = NULL;
	DOMElement *audit_sys_elem = NULL;
	content = audit_sys_document.getContent(content);
	audit_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	audit_sys_wfis = new Wrapper4InputSource(audit_sys_mbis);
	audit_sys_dom_doc = parser->parse(audit_sys_wfis);
	audit_sys_elem = audit_sys_dom_doc->getDocumentElement();
	assert_tag_equals("audit_sys", audit_sys_elem);
	delete audit_sys_wfis;
	audit_sys_wfis = NULL;

	XmlDocument audit_app_document = context->audit_app_cont->getDocument(transaction, ser_id);
	content = "";
	MemBufInputSource *audit_app_mbis = NULL;
	Wrapper4InputSource *audit_app_wfis = NULL;
	DOMDocument *audit_app_dom_doc = NULL;
	DOMElement *audit_app_elem = NULL;
	content = audit_app_document.getContent(content);
	audit_app_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	audit_app_wfis = new Wrapper4InputSource(audit_app_mbis);
	audit_app_dom_doc = parser->parse(audit_app_wfis);
	audit_app_elem = audit_app_dom_doc->getDocumentElement();
	assert_tag_equals("audit_app", audit_app_elem);
	delete audit_app_wfis;
	audit_app_wfis = NULL;

	XmlDocument audit_document = context->audit_cont->getDocument(transaction, ser_id);
	content = "";
	MemBufInputSource *audit_mbis = NULL;
	Wrapper4InputSource *audit_wfis = NULL;
	DOMDocument *audit_dom_doc = NULL;
	DOMElement *audit_elem = NULL;
	content = audit_document.getContent(content);
	audit_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	audit_wfis = new Wrapper4InputSource(audit_mbis);
	audit_dom_doc = parser->parse(audit_wfis);
	audit_elem = audit_dom_doc->getDocumentElement();
	assert_tag_equals("audit", audit_elem);
	delete audit_wfis;
	audit_wfis = NULL;
}

extern "C" void test_insert_audit_helper_returns_ok_with_source_set()
{
	std::string src = "remotehost";
	XmlTransaction transaction = context->manager->createTransaction();
	XmlUpdateContext update_ctx = context->manager->createUpdateContext();
	std::string ser_id = "1";
	jaldb_status ret;
	ret = jaldb_insert_audit_helper(src, transaction, *(context->manager), update_ctx,
		*(context->audit_sys_cont), *(context->audit_app_cont), *(context->audit_cont),
		audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_OK, ret);

	bool metadataFound = false;
	XmlValue val;
	XmlDocument audit_sys_document = context->audit_sys_cont->getDocument(transaction, ser_id);
	metadataFound = audit_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(src.c_str(), source.c_str());
}

extern "C" void test_insert_audit_helper_fails_with_no_sid()
{
	std::string src = "";
	XmlTransaction transaction = context->manager->createTransaction();
	XmlUpdateContext update_ctx = context->manager->createUpdateContext();
	std::string ser_id = "";
	jaldb_status ret;
	ret = jaldb_insert_audit_helper(src, transaction, *(context->manager), update_ctx,
		*(context->audit_sys_cont), *(context->audit_app_cont), *(context->audit_cont),
		audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_insert_audit_record_returns_ok()
{
	std::string src = "";
	std::string ser_id = "1";
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
		context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_OK, ret);

	bool metadataFound = false;
	XmlValue val;
	XmlDocument audit_sys_document = context->audit_sys_cont->getDocument(ser_id);
	metadataFound = audit_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(JALDB_LOCALHOST, source.c_str());

	std::string doc_name = "";
	doc_name = audit_sys_document.getName();
	assert_string_equals("1", doc_name.c_str());

	doc_name = "";
	XmlDocument audit_app_document = context->audit_app_cont->getDocument(ser_id);
	doc_name = audit_app_document.getName();
	assert_string_equals("1", doc_name.c_str());

	doc_name = "";
	XmlDocument audit_document = context->audit_cont->getDocument(ser_id);
	doc_name = audit_document.getName();
	assert_string_equals("1", doc_name.c_str());

	std::string content = "";
	MemBufInputSource *audit_sys_mbis = NULL;
	Wrapper4InputSource *audit_sys_wfis = NULL;
	DOMDocument *audit_sys_dom_doc = NULL;
	DOMElement *audit_sys_elem = NULL;
	content = audit_sys_document.getContent(content);
	audit_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	audit_sys_wfis = new Wrapper4InputSource(audit_sys_mbis);
	audit_sys_dom_doc = parser->parse(audit_sys_wfis);
	audit_sys_elem = audit_sys_dom_doc->getDocumentElement();
	assert_tag_equals("audit_sys", audit_sys_elem);
	delete audit_sys_wfis;
	audit_sys_wfis = NULL;

	content = "";
	MemBufInputSource *audit_app_mbis = NULL;
	Wrapper4InputSource *audit_app_wfis = NULL;
	DOMDocument *audit_app_dom_doc = NULL;
	DOMElement *audit_app_elem = NULL;
	content = audit_app_document.getContent(content);
	audit_app_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	audit_app_wfis = new Wrapper4InputSource(audit_app_mbis);
	audit_app_dom_doc = parser->parse(audit_app_wfis);
	audit_app_elem = audit_app_dom_doc->getDocumentElement();
	assert_tag_equals("audit_app", audit_app_elem);
	delete audit_app_wfis;
	audit_app_wfis = NULL;

	content = "";
	MemBufInputSource *audit_mbis = NULL;
	Wrapper4InputSource *audit_wfis = NULL;
	DOMDocument *audit_dom_doc = NULL;
	DOMElement *audit_elem = NULL;
	content = audit_document.getContent(content);
	audit_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	audit_wfis = new Wrapper4InputSource(audit_mbis);
	audit_dom_doc = parser->parse(audit_wfis);
	audit_elem = audit_dom_doc->getDocumentElement();
	assert_tag_equals("audit", audit_elem);
	delete audit_wfis;
	audit_wfis = NULL;
}

extern "C" void test_insert_audit_record_returns_ok_with_source_set()
{
	std::string src = "remotehost";
	std::string ser_id = "1";
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
		context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_OK, ret);

	bool metadataFound = false;
	XmlValue val;
	XmlDocument audit_sys_document = context->audit_sys_cont->getDocument(ser_id);
	metadataFound = audit_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(src.c_str(), source.c_str());
}

extern "C" void test_insert_audit_record_returns_ok_with_no_app_metadata()
{
	std::string src = "";
	audit_app_meta_doc = NULL;
	std::string ser_id = "1";
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
		context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_OK, ret);

	bool metadataFound = false;
	XmlValue src_val;
	XmlDocument audit_sys_document = context->audit_sys_cont->getDocument(ser_id);
	metadataFound = audit_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, src_val);
	std::string source = src_val.asString();
	assert_string_equals(JALDB_LOCALHOST, source.c_str());

	std::string doc_name = "";
	doc_name = audit_sys_document.getName();
	assert_string_equals("1", doc_name.c_str());

	XmlValue has_app_meta_val;
	audit_sys_document.getMetaData(JALDB_NS, JALDB_HAS_APP_META, has_app_meta_val);
	assert_false(has_app_meta_val.asBoolean());

	doc_name = "";
	XmlDocument audit_document = context->audit_cont->getDocument(ser_id);
	doc_name = audit_document.getName();
	assert_string_equals("1", doc_name.c_str());

	XmlDocument audit_app_document;
	try {
		audit_app_document = context->audit_app_cont->getDocument(ser_id);
	}
	catch (XmlException &e) {
		return;
	}
	assert_true(0);
}

extern "C" void test_insert_audit_record_fails_with_invalid_input()
{
	std::string src = "";
	std::string ser_id = "1";
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
		NULL, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_insert_audit_record(
		context, src, NULL, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_insert_audit_record(
		context, src, audit_sys_meta_doc, audit_app_meta_doc, NULL, ser_id);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *tmp_mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_insert_audit_record(
		context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	context->manager = tmp_mgr;
	assert_equals(JALDB_E_INVAL, ret);

	XmlContainer *tmp_audit_sys_cont = context->audit_sys_cont;
	context->audit_sys_cont = NULL;
	ret = jaldb_insert_audit_record(
		context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	context->audit_sys_cont = tmp_audit_sys_cont;
	assert_equals(JALDB_E_INVAL, ret);

	XmlContainer *tmp_audit_app_cont = context->audit_app_cont;
	context->audit_app_cont = NULL;
	ret = jaldb_insert_audit_record(
		context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	context->audit_app_cont = tmp_audit_app_cont;
	assert_equals(JALDB_E_INVAL, ret);

	XmlContainer *tmp_audit_cont = context->audit_cont;
	context->audit_cont = NULL;
	ret = jaldb_insert_audit_record(
		context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	context->audit_cont = tmp_audit_cont;
	assert_equals(JALDB_E_INVAL, ret);
}
