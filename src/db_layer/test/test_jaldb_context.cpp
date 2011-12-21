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

#define __STDC_FORMAT_MACROS
#include <db.h>
#include <dbxml/DbXml.hpp>
#include <dirent.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/util/PlatformUtils.hpp>
#include <dbxml/DbXml.hpp>
#include <dbxml/XmlContainer.hpp>
#include <inttypes.h>
#include "jal_alloc.h"
#include "jaldb_context.hpp"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "xml_test_utils.hpp"

XERCES_CPP_NAMESPACE_USE;
using namespace DbXml;
using namespace std;

#define OTHER_DB_ROOT "./testdb/"
#define OTHER_SCHEMA_ROOT "./schemas/"
#define JOURNAL_ROOT "/journal/"
#define AUDIT_SYS_TEST_XML_DOC "./test-input/domwriter_audit_sys.xml"
#define AUDIT_APP_TEST_XML_DOC "./test-input/domwriter_audit_app.xml"
#define FAKE_SID "12341234"
#define AUDIT_TEST_XML_DOC "./test-input/domwriter_audit.xml"
#define LOG_SYS_TEST_XML_DOC "./test-input/domwriter_log_sys.xml"
#define LOG_APP_TEST_XML_DOC "./test-input/domwriter_log_app.xml"
#define REMOTE_HOST "remote_host"
#define TEST_XML_DOC "./test-input/domwriter.xml"
#define LOG_DATA_X "Log Buffer\nLog Entry 1\n"
#define LOG_DATA_Y "Log Buffer\nLog Entry 1\nLog Entry 2\n"
#define PAYLOAD "SoMe_data   is here\nMoreData is Here!\n"

static DOMLSParser *parser = NULL;
static DOMDocument *audit_sys_meta_doc = NULL;
static DOMDocument *audit_app_meta_doc = NULL;
static DOMDocument *audit_doc = NULL;
static DOMDocument *log_sys_meta_doc = NULL;
static DOMDocument *log_app_meta_doc = NULL;
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
	log_sys_meta_doc = parser->parseURI(LOG_SYS_TEST_XML_DOC);
	log_app_meta_doc = parser->parseURI(LOG_APP_TEST_XML_DOC);
	context = jaldb_context_create();
	jaldb_context_init(context, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, true, false);
}

extern "C" void teardown()
{
	delete parser;
	parser = NULL;
	audit_sys_meta_doc = NULL;
	audit_app_meta_doc = NULL;
	audit_doc = NULL;
	log_sys_meta_doc = NULL;
	log_app_meta_doc = NULL;
	jaldb_context_destroy(&context);
	XMLPlatformUtils::Terminate();
}

// Use for debugging exceptions
extern "C" void print_xml_exception(XmlException e)
{
	switch (e.getExceptionCode()) {
		case XmlException::DATABASE_ERROR:
			printf("DATABASE_ERROR\n");
			break;
		case XmlException::INDEXER_PARSER_ERROR:
			printf("INDEXER_PARSER_ERROR\n");
			break;
		case XmlException::UNIQUE_ERROR:
			printf("UNIQUE_ERROR\n");
			break;
		case XmlException::CONTAINER_CLOSED:
			printf("CONTAINER_CLOSED\n");
			break;
		case XmlException::CONTAINER_EXISTS:
			printf("CONTAINER_EXISTS\n");
			break;
		case XmlException::CONTAINER_NOT_FOUND:
			printf("CONTAINER_NOT_FOUND\n");
			break;
		case XmlException::CONTAINER_OPEN:
			printf("CONTAINER_OPEN\n");
			break;
		case XmlException::DOCUMENT_NOT_FOUND:
			printf("DOCUMENT_NOT_FOUND\n");
			break;
		case XmlException::EVENT_ERROR:
			printf("EVENT_ERROR\n");
			break;
		case XmlException::INTERNAL_ERROR:
			printf("INTERNAL_ERROR\n");
			break;
		case XmlException::INVALID_VALUE:
			printf("INVALID_VALUE\n");
			break;
		case XmlException::LAZY_EVALUATION:
			printf("LAZY_EVALUATION\n");
			break;
		case XmlException::NO_MEMORY_ERROR:
			printf("NO_MEMORY_ERROR\n");
			break;
		case XmlException::NULL_POINTER:
			printf("NULL_POINTER\n");
			break;
		case XmlException::OPERATION_INTERRUPTED:
			printf("OPERATION_INTERRUPTED\n");
			break;
		case XmlException::OPERATION_TIMEOUT:
			printf("OPERATION_TIMEOUT\n");
			break;
		case XmlException::TRANSACTION_ERROR:
			printf("TRANSACTION_ERROR\n");
			break;
		case XmlException::UNKNOWN_INDEX:
			printf("UNKNOWN_INDEX\n");
			break;
		default:
			printf("UNKNOWN!\n");
	}
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
	assert_not_equals((void *)NULL, ctx);
	enum jaldb_status ret = jaldb_context_init(ctx, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, false, false);
	assert_equals(JALDB_OK, ret);
	jaldb_context_destroy(&ctx);
	assert_pointer_equals((void *)NULL, ctx);
}

extern "C" void test_store_confed_journal_sid_fails_with_invalid_input()
{
	char *rhost = jal_strdup("remote_host");
	char *ser_id = jal_strdup("1234");
	int db_error_out = 0;
	enum jaldb_status ret =
		jaldb_store_confed_journal_sid(NULL, rhost, ser_id, &db_error_out);
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
	enum jaldb_status ret =
		jaldb_store_confed_audit_sid(NULL, rhost, ser_id, &db_error_out);
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
	enum jaldb_status ret =
		jaldb_store_confed_log_sid(NULL, rhost, ser_id, &db_error_out);
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

extern "C" void test_store_confed_sid_helper_returns_ok()
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

extern "C" void test_make_temp_db_name_returns_ok()
{
	std::string dbase_name = "__remote_host_audit_sys_meta.dbxml";
	std::string db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_SYS_META_CONT_NAME);
	assert_string_equals(dbase_name.c_str(), db_name.c_str());

	dbase_name = "__remote_host_audit_app_meta.dbxml";
	db_name = jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_APP_META_CONT_NAME);
	assert_string_equals(dbase_name.c_str(), db_name.c_str());

	dbase_name = "__remote_host_audit.dbxml";
	db_name = jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_CONT_NAME);
	assert_string_equals(dbase_name.c_str(), db_name.c_str());
}

extern "C" void test_open_temp_container_returns_ok()
{
	std::string audit_sys_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_SYS_META_CONT_NAME);
	XmlContainer temp_audit_sys_cont;
	enum jaldb_status ret = jaldb_open_temp_container(
		context, audit_sys_db_name, temp_audit_sys_cont);
	assert_equals(JALDB_OK, ret);

	std::string audit_app_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_APP_META_CONT_NAME);
	XmlContainer temp_audit_app_cont;
	ret = jaldb_open_temp_container(context, audit_app_db_name, temp_audit_app_cont);
	assert_equals(JALDB_OK, ret);

	std::string audit_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_CONT_NAME);
	XmlContainer temp_audit_cont;
	ret = jaldb_open_temp_container(context, audit_db_name, temp_audit_cont);
	assert_equals(JALDB_OK, ret);

	int containerExists = context->manager->existsContainer(audit_sys_db_name);
	assert_not_equals(0, containerExists);

	containerExists = context->manager->existsContainer(audit_app_db_name);
	assert_not_equals(0, containerExists);

	containerExists = context->manager->existsContainer(audit_db_name);
	assert_not_equals(0, containerExists);
}

extern "C" void test_open_temp_container_fails_with_invalid_input()
{
	std::string dbase_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_APP_META_CONT_NAME);
	XmlContainer temp_container;
	enum jaldb_status ret = jaldb_open_temp_container(NULL, dbase_name, temp_container);
	assert_equals(JALDB_E_INVAL, ret);

	string_to_container_map *tmp_containers = context->temp_containers;
	context->temp_containers = NULL;
	XmlContainer temp_cont;
	ret = jaldb_open_temp_container(context, "", temp_cont);
	context->temp_containers = tmp_containers;
	assert_equals(JALDB_E_INVAL, ret);

	XmlContainer tmp_container;
	ret = jaldb_open_temp_container(context, "", tmp_container);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_insert_audit_record_into_temp_returns_ok()
{
	std::string src = REMOTE_HOST;
	std::string ser_id = "1";
	enum jaldb_status ret = jaldb_insert_audit_record_into_temp(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_OK, ret);

	std::string audit_sys_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_SYS_META_CONT_NAME);
	XmlContainer temp_audit_sys_cont;
	ret = jaldb_open_temp_container(context, audit_sys_db_name, temp_audit_sys_cont);
	bool metadataFound = false;
	XmlValue val;
	XmlDocument audit_sys_document = temp_audit_sys_cont.getDocument(ser_id);
	metadataFound = audit_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(REMOTE_HOST, source.c_str());

	std::string doc_name = audit_sys_document.getName();
	assert_string_equals(ser_id.c_str(), doc_name.c_str());

	std::string audit_app_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_APP_META_CONT_NAME);
	XmlContainer temp_audit_app_cont;
	ret = jaldb_open_temp_container(context, audit_app_db_name, temp_audit_app_cont);
	XmlDocument audit_app_document = temp_audit_app_cont.getDocument(ser_id);
	doc_name = audit_app_document.getName();
	assert_string_equals(ser_id.c_str(), doc_name.c_str());

	std::string audit_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_CONT_NAME);
	XmlContainer temp_audit_cont;
	ret = jaldb_open_temp_container(context, audit_db_name, temp_audit_cont);
	XmlDocument audit_document = temp_audit_cont.getDocument(ser_id);
	doc_name = audit_document.getName();
	assert_string_equals(ser_id.c_str(), doc_name.c_str());

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
	delete audit_sys_wfis;
	audit_sys_wfis = NULL;
	assert_tag_equals("audit_sys", audit_sys_elem);

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
	delete audit_app_wfis;
	audit_app_wfis = NULL;
	assert_tag_equals("audit_app", audit_app_elem);

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
	delete audit_wfis;
	audit_wfis = NULL;
	assert_tag_equals("audit", audit_elem);
}

extern "C" void test_insert_audit_record_into_temp_with_no_app_metadata_returns_ok()
{
	std::string src = REMOTE_HOST;
	std::string ser_id = "1";
	enum jaldb_status ret = jaldb_insert_audit_record_into_temp(context, src,
		audit_sys_meta_doc, NULL, audit_doc, ser_id);
	assert_equals(JALDB_OK, ret);

	std::string audit_sys_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_SYS_META_CONT_NAME);
	XmlContainer temp_audit_sys_cont;
	ret = jaldb_open_temp_container(context, audit_sys_db_name, temp_audit_sys_cont);
	bool metadataFound = false;
	XmlValue val;
	XmlDocument audit_sys_document = temp_audit_sys_cont.getDocument(ser_id);
	metadataFound = audit_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(REMOTE_HOST, source.c_str());

	std::string doc_name = audit_sys_document.getName();
	assert_string_equals(ser_id.c_str(), doc_name.c_str());

	XmlValue has_app_meta_val;
	audit_sys_document.getMetaData(JALDB_NS, JALDB_HAS_APP_META, has_app_meta_val);
	assert_false(has_app_meta_val.asBoolean());

	std::string audit_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_AUDIT_CONT_NAME);
	XmlContainer temp_audit_cont;
	ret = jaldb_open_temp_container(context, audit_db_name, temp_audit_cont);
	XmlDocument audit_document = temp_audit_cont.getDocument(ser_id);
	doc_name = audit_document.getName();
	assert_string_equals(ser_id.c_str(), doc_name.c_str());

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
	delete audit_sys_wfis;
	audit_sys_wfis = NULL;
	assert_tag_equals("audit_sys", audit_sys_elem);

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
	delete audit_wfis;
	audit_wfis = NULL;
	assert_tag_equals("audit", audit_elem);
}

extern "C" void test_insert_audit_record_into_temp_fails_with_invalid_input()
{
	std::string src = REMOTE_HOST;
	std::string ser_id = "1";
	enum jaldb_status ret = jaldb_insert_audit_record_into_temp(NULL, src,
		audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_insert_audit_record_into_temp(context, src, NULL, audit_app_meta_doc,
		audit_doc, ser_id);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_insert_audit_record_into_temp(context, src, audit_sys_meta_doc,
		audit_app_meta_doc, NULL, ser_id);
	assert_equals(JALDB_E_INVAL, ret);

	src = "";
	ret = jaldb_insert_audit_record_into_temp(context, src, audit_sys_meta_doc,
		audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_E_INVAL, ret);

	ser_id = "";
	src = REMOTE_HOST;
	ret = jaldb_insert_audit_record_into_temp(context, src, audit_sys_meta_doc,
		audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_insert_log_record_helper_returns_ok()
{
	std::string src = "";
	XmlTransaction transaction = context->manager->createTransaction();
	XmlUpdateContext update_ctx = context->manager->createUpdateContext();
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	std::string ser_id = "1";
	int db_error = 0;
	enum jaldb_status ret = jaldb_insert_log_record_helper(src, transaction,
		*context->manager, update_ctx, *context->log_sys_cont,
		*context->log_app_cont, context->log_dbp, log_sys_meta_doc,
		log_app_meta_doc, logbuf, loglen, ser_id, &db_error);
	assert_equals(JALDB_OK, ret);

	DBT key;
	DBT data;
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));
	key.data = jal_strdup(ser_id.c_str());
	key.size = ser_id.length();
	key.flags = DB_DBT_USERMEM;
	data.flags = DB_DBT_MALLOC;
	int db_err;
	db_err = context->log_dbp->get(context->log_dbp, transaction.getDB_TXN(), &key,
		&data, 0);
	assert_equals(0, db_err);
	assert_equals(strlen(LOG_DATA_X), data.size);
	int result = strncmp(LOG_DATA_X, (char *)data.data, strlen(LOG_DATA_X));
	assert_equals(0, result);
	free(key.data);
	free(data.data);
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	const char *log_buffer_y = LOG_DATA_Y;
	logbuf = (uint8_t *)log_buffer_y;
	loglen = strlen(log_buffer_y);
	std::string next_ser_id = "2";
	ret = jaldb_insert_log_record_helper(src, transaction, *context->manager,
		update_ctx, *context->log_sys_cont, *context->log_app_cont,
		context->log_dbp, log_sys_meta_doc, log_app_meta_doc, logbuf, loglen,
		next_ser_id, &db_error);
	assert_equals(JALDB_OK, ret);

	key.data = jal_strdup(next_ser_id.c_str());
	key.size = next_ser_id.length();
	key.flags = DB_DBT_USERMEM;
	data.flags = DB_DBT_MALLOC;
	db_err = context->log_dbp->get(context->log_dbp, transaction.getDB_TXN(), &key,
		&data, 0);
	assert_equals(0, db_err);
	assert_equals(strlen(LOG_DATA_Y), data.size);
	result = strncmp(LOG_DATA_Y, (char *)data.data, strlen(LOG_DATA_Y));
	free(key.data);
	free(data.data);
	key.data = NULL;
	data.data = NULL;
	assert_equals(0, result);

	XmlDocument log_sys_document =
		context->log_sys_cont->getDocument(transaction, next_ser_id);
	std::string content = "";
	MemBufInputSource *log_sys_mbis = NULL;
	Wrapper4InputSource *log_sys_wfis = NULL;
	DOMDocument *log_sys_dom_doc = NULL;
	DOMElement *log_sys_elem = NULL;
	content = log_sys_document.getContent(content);
	log_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), next_ser_id.c_str(), false);
	log_sys_wfis = new Wrapper4InputSource(log_sys_mbis);
	log_sys_dom_doc = parser->parse(log_sys_wfis);
	log_sys_elem = log_sys_dom_doc->getDocumentElement();
	delete log_sys_wfis;
	log_sys_wfis = NULL;
	assert_tag_equals("log_sys", log_sys_elem);

	XmlDocument log_app_document =
		context->log_app_cont->getDocument(transaction, next_ser_id);
	content = "";
	MemBufInputSource *log_app_mbis = NULL;
	Wrapper4InputSource *log_app_wfis = NULL;
	DOMDocument *log_app_dom_doc = NULL;
	DOMElement *log_app_elem = NULL;
	content = log_app_document.getContent(content);
	log_app_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), next_ser_id.c_str(), false);
	log_app_wfis = new Wrapper4InputSource(log_app_mbis);
	log_app_dom_doc = parser->parse(log_app_wfis);
	log_app_elem = log_app_dom_doc->getDocumentElement();
	delete log_app_wfis;
	log_app_wfis = NULL;
	assert_tag_equals("log_app", log_app_elem);
}

extern "C" void test_insert_log_record_helper_fails_when_trying_to_insert_same_sid_twice()
{
	std::string src = "";
	XmlTransaction transaction = context->manager->createTransaction();
	XmlUpdateContext update_ctx = context->manager->createUpdateContext();
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	std::string ser_id = "1";
	int db_error = 0;
	enum jaldb_status ret = jaldb_insert_log_record_helper(src, transaction,
		*context->manager, update_ctx, *context->log_sys_cont,
		*context->log_app_cont, context->log_dbp, log_sys_meta_doc,
		log_app_meta_doc, logbuf, loglen, ser_id, &db_error);
	assert_equals(JALDB_OK, ret);

	const char *log_buffer_y = LOG_DATA_Y;
	logbuf = (uint8_t *)log_buffer_y;
	loglen = strlen(log_buffer_y);
	try {
		ret = jaldb_insert_log_record_helper(src, transaction, *context->manager,
			update_ctx, *context->log_sys_cont, *context->log_app_cont,
			context->log_dbp, log_sys_meta_doc, log_app_meta_doc, logbuf,
			loglen,	ser_id, &db_error);
	}
	catch (XmlException &e) {
		return;
	}
	assert_true(0);
}

extern "C" void test_insert_log_record_helper_fails_with_invalid_input()
{
	std::string src = "";
	XmlTransaction transaction = context->manager->createTransaction();
	XmlUpdateContext update_ctx = context->manager->createUpdateContext();
	const char *log_buffer = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer;
	size_t loglen = strlen(log_buffer);
	std::string ser_id = "1";
	int db_error = 0;
	DB *tmp_log_dbp = context->log_dbp;
	context->log_dbp = NULL;
	enum jaldb_status ret = jaldb_insert_log_record_helper(src, transaction,
		*context->manager, update_ctx, *context->log_sys_cont,
		*context->log_app_cont, context->log_dbp, log_sys_meta_doc,
		log_app_meta_doc, logbuf, loglen, ser_id, &db_error);
	context->log_dbp = tmp_log_dbp;
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_insert_log_record_helper(src, transaction, *context->manager,
		update_ctx, *context->log_sys_cont, *context->log_app_cont,
		context->log_dbp, NULL,	log_app_meta_doc, logbuf, loglen, ser_id,
		&db_error);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_insert_log_record_helper(src, transaction, *context->manager,
		update_ctx, *context->log_sys_cont, *context->log_app_cont,
		context->log_dbp, log_sys_meta_doc, log_app_meta_doc, logbuf,
		loglen, ser_id, NULL);
	assert_equals(JALDB_E_INVAL, ret);

	ser_id = "";
	ret = jaldb_insert_log_record_helper(src, transaction, *context->manager,
		update_ctx, *context->log_sys_cont, *context->log_app_cont,
		context->log_dbp, log_sys_meta_doc, log_app_meta_doc, logbuf, loglen,
		ser_id, &db_error);
	assert_equals(JALDB_E_INVAL, ret);

	loglen = 0;
	ret = jaldb_insert_log_record_helper(src, transaction, *context->manager,
		update_ctx, *context->log_sys_cont, *context->log_app_cont,
		context->log_dbp, log_sys_meta_doc, NULL, logbuf, loglen, ser_id,
		&db_error);
	assert_equals(JALDB_E_INVAL, ret);

	logbuf = NULL;
	loglen = 11;
	ret = jaldb_insert_log_record_helper(src, transaction, *context->manager,
		update_ctx, *context->log_sys_cont, *context->log_app_cont,
		context->log_dbp, log_sys_meta_doc, NULL, logbuf, loglen, ser_id,
		&db_error);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_insert_log_record_returns_ok()
{
	std::string src = "";
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	std::string ser_id = "1";
	int db_error = 0;
	enum jaldb_status ret = jaldb_insert_log_record(context, src, log_sys_meta_doc,
		log_app_meta_doc, logbuf, loglen, ser_id, &db_error);
	assert_equals(JALDB_OK, ret);

	DBT key;
	DBT data;
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));
	key.data = jal_strdup(ser_id.c_str());
	key.size = ser_id.length();
	key.flags = DB_DBT_USERMEM;
	data.flags = DB_DBT_MALLOC;
	int db_err;
	db_err = context->log_dbp->get(context->log_dbp, NULL, &key, &data, 0);
	assert_equals(0, db_err);
	assert_equals(strlen(LOG_DATA_X), data.size);
	int result = strncmp(LOG_DATA_X, (char *)data.data, strlen(LOG_DATA_X));
	assert_equals(0, result);
	free(key.data);
	free(data.data);
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));

	const char *log_buffer_y = LOG_DATA_Y;
	logbuf = (uint8_t *)log_buffer_y;
	loglen = strlen(log_buffer_y);
	std::string next_ser_id = "2";
	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
		logbuf, loglen, next_ser_id, &db_error);
	assert_equals(JALDB_OK, ret);

	key.data = jal_strdup(next_ser_id.c_str());
	key.size = next_ser_id.length();
	key.flags = DB_DBT_USERMEM;
	data.flags = DB_DBT_MALLOC;
	db_err = context->log_dbp->get(context->log_dbp, NULL, &key, &data, 0);
	assert_equals(0, db_err);
	assert_equals(strlen(LOG_DATA_Y), data.size);
	result = strncmp(LOG_DATA_Y, (char *)data.data, strlen(LOG_DATA_Y));
	free(key.data);
	free(data.data);
	key.data = NULL;
	data.data = NULL;
	assert_equals(0, result);

	XmlDocument log_sys_document = context->log_sys_cont->getDocument(ser_id);
	std::string content = "";
	MemBufInputSource *log_sys_mbis = NULL;
	Wrapper4InputSource *log_sys_wfis = NULL;
	DOMDocument *log_sys_dom_doc = NULL;
	DOMElement *log_sys_elem = NULL;
	content = log_sys_document.getContent(content);
	log_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), ser_id.c_str(), false);
	log_sys_wfis = new Wrapper4InputSource(log_sys_mbis);
	log_sys_dom_doc = parser->parse(log_sys_wfis);
	log_sys_elem = log_sys_dom_doc->getDocumentElement();
	delete log_sys_wfis;
	log_sys_wfis = NULL;
	assert_tag_equals("log_sys", log_sys_elem);

	XmlDocument log_app_document = context->log_app_cont->getDocument(ser_id);
	content = "";
	MemBufInputSource *log_app_mbis = NULL;
	Wrapper4InputSource *log_app_wfis = NULL;
	DOMDocument *log_app_dom_doc = NULL;
	DOMElement *log_app_elem = NULL;
	content = log_app_document.getContent(content);
	log_app_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), ser_id.c_str(), false);
	log_app_wfis = new Wrapper4InputSource(log_app_mbis);
	log_app_dom_doc = parser->parse(log_app_wfis);
	log_app_elem = log_app_dom_doc->getDocumentElement();
	delete log_app_wfis;
	log_app_wfis = NULL;
	assert_tag_equals("log_app", log_app_elem);
}

extern "C" void test_insert_log_record_does_not_insert_same_sid_twice()
{
	std::string src = "";
	XmlTransaction transaction = context->manager->createTransaction();
	XmlUpdateContext update_ctx = context->manager->createUpdateContext();
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	std::string ser_id = "1";
	int db_error = 0;
	enum jaldb_status ret = jaldb_insert_log_record(context, src, log_sys_meta_doc,
		log_app_meta_doc, logbuf, loglen, ser_id, &db_error);
	assert_equals(JALDB_OK, ret);

	assert_string_equals("1", ser_id.c_str());

	const char *log_buffer_y = LOG_DATA_Y;
	logbuf = (uint8_t *)log_buffer_y;
	loglen = strlen(log_buffer_y);
	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
		logbuf,	loglen, ser_id, &db_error);
	assert_equals(JALDB_OK, ret);

	assert_string_equals("2", ser_id.c_str());

	assert_equals(3, context->log_sys_cont->getNumDocuments());

	assert_equals(2, context->log_app_cont->getNumDocuments());
}

extern "C" void test_insert_log_record_fails_with_invalid_input()
{
	std::string src = "";
	const char *log_buffer = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer;
	size_t loglen = strlen(log_buffer);
	std::string ser_id = "1";
	int db_error = 0;
	enum jaldb_status ret = jaldb_insert_log_record(NULL, src, log_sys_meta_doc,
		log_app_meta_doc, logbuf, loglen, ser_id, &db_error);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *tmp_mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
		logbuf, loglen, ser_id, &db_error);
	context->manager = tmp_mgr;
	assert_equals(JALDB_E_INVAL, ret);

	XmlContainer *tmp_log_sys_cont = context->log_sys_cont;
	context->log_sys_cont = NULL;
	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
		logbuf,	loglen, ser_id, &db_error);
	context->log_sys_cont = tmp_log_sys_cont;
	assert_equals(JALDB_E_INVAL, ret);

	XmlContainer *tmp_log_app_cont = context->log_app_cont;
	context->log_app_cont = NULL;
	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
		logbuf,	loglen, ser_id, &db_error);
	context->log_app_cont = tmp_log_app_cont;
	assert_equals(JALDB_E_INVAL, ret);

	DB *tmp_log_dbp = context->log_dbp;
	context->log_dbp = NULL;
	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
		logbuf, loglen, ser_id, &db_error);
	context->log_dbp = tmp_log_dbp;
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
		logbuf,	loglen, ser_id, NULL);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_db_create_journal_file()
{
	char *path = NULL;
	int fd;
	jaldb_create_journal_file(context, &path, &fd);
	free(path);
	close(fd);
}

extern "C" void test_open_temp_db_returns_ok()
{
	std::string log_db_name = jaldb_make_temp_db_name(REMOTE_HOST, JALDB_LOG_DB_NAME);
	DB *dbase_out = NULL;
	int db_error_out = 0;
	enum jaldb_status ret =
		jaldb_open_temp_db(context, log_db_name, &dbase_out, &db_error_out);
	assert_equals(JALDB_OK, ret);

	const char *file_name;
	int db_error;
	db_error = dbase_out->get_dbname(dbase_out, &file_name, NULL);
	assert_equals(0, db_error);
	assert_string_equals(log_db_name.c_str(), file_name);
}

extern "C" void test_open_temp_db_fails_with_invalid_input()
{
	std::string log_db_name = jaldb_make_temp_db_name(REMOTE_HOST, JALDB_LOG_DB_NAME);
	DB *dbase_out = NULL;
	int db_error_out = 0;
	enum jaldb_status ret =
		jaldb_open_temp_db(NULL, log_db_name, &dbase_out, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);

	string_to_db_map *tmp_temp_dbs = context->temp_dbs;
	context->temp_dbs = NULL;
	ret = jaldb_open_temp_db(context, log_db_name, &dbase_out, &db_error_out);
	context->temp_dbs = tmp_temp_dbs;
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);

	XmlManager *tmp_mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_open_temp_db(context, log_db_name, &dbase_out, &db_error_out);
	context->manager = tmp_mgr;
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);

	ret = jaldb_open_temp_db(context, log_db_name, NULL, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);

	dbase_out = (DB*) 0xDEADBEEF;
	ret = jaldb_open_temp_db(context, log_db_name, &dbase_out, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) 0xDEADBEEF, dbase_out);
	dbase_out = NULL;
	ret = jaldb_open_temp_db(context, log_db_name, &dbase_out, NULL);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);

	log_db_name = "";
	ret = jaldb_open_temp_db(context, log_db_name, &dbase_out, &db_error_out);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, dbase_out);
}

extern "C" void test_insert_log_record_into_temp_returns_ok()
{
	std::string src = REMOTE_HOST;
	const char *log_buffer = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer;
	size_t loglen = strlen(log_buffer);
	std::string ser_id = "1";
	int db_error = 0;
	enum jaldb_status ret = jaldb_insert_log_record_into_temp(context, src,
		log_sys_meta_doc, log_app_meta_doc, logbuf, loglen, ser_id, &db_error);
	assert_equals(JALDB_OK, ret);

	std::string log_sys_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer temp_log_sys_cont;
	ret = jaldb_open_temp_container(context, log_sys_db_name, temp_log_sys_cont);
	bool metadataFound = false;
	XmlValue val;
	XmlDocument log_sys_document = temp_log_sys_cont.getDocument(ser_id);
	metadataFound = log_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(REMOTE_HOST, source.c_str());

	std::string doc_name = log_sys_document.getName();
	assert_string_equals(ser_id.c_str(), doc_name.c_str());

	std::string log_app_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_LOG_APP_META_CONT_NAME);
	XmlContainer temp_log_app_cont;
	ret = jaldb_open_temp_container(context, log_app_db_name, temp_log_app_cont);
	XmlDocument log_app_document = temp_log_app_cont.getDocument(ser_id);
	doc_name = log_app_document.getName();
	assert_string_equals(ser_id.c_str(), doc_name.c_str());

	std::string content = "";
	MemBufInputSource *log_sys_mbis = NULL;
	Wrapper4InputSource *log_sys_wfis = NULL;
	DOMDocument *log_sys_dom_doc = NULL;
	DOMElement *log_sys_elem = NULL;
	content = log_sys_document.getContent(content);
	log_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	log_sys_wfis = new Wrapper4InputSource(log_sys_mbis);
	log_sys_dom_doc = parser->parse(log_sys_wfis);
	log_sys_elem = log_sys_dom_doc->getDocumentElement();
	delete log_sys_wfis;
	log_sys_wfis = NULL;
	assert_tag_equals("log_sys", log_sys_elem);

	content = "";
	MemBufInputSource *log_app_mbis = NULL;
	Wrapper4InputSource *log_app_wfis = NULL;
	DOMDocument *log_app_dom_doc = NULL;
	DOMElement *log_app_elem = NULL;
	content = log_app_document.getContent(content);
	log_app_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	log_app_wfis = new Wrapper4InputSource(log_app_mbis);
	log_app_dom_doc = parser->parse(log_app_wfis);
	log_app_elem = log_app_dom_doc->getDocumentElement();
	delete log_app_wfis;
	log_app_wfis = NULL;
	assert_tag_equals("log_app", log_app_elem);

	DBT key;
	DBT data;
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));
	key.data = jal_strdup(ser_id.c_str());
	key.size = ser_id.length();
	key.flags = DB_DBT_USERMEM;
	data.flags = DB_DBT_MALLOC;
	int db_err;
	std::string log_db_name = jaldb_make_temp_db_name(REMOTE_HOST, JALDB_LOG_DB_NAME);
	XmlTransaction txn = context->manager->createTransaction();
	db_err = (*context->temp_dbs)[log_db_name]->get((*context->temp_dbs)[log_db_name],
		txn.getDB_TXN(), &key, &data, 0);
	assert_equals(strlen(LOG_DATA_X), data.size);
	int result = strncmp(LOG_DATA_X, (char *)(data.data), strlen(LOG_DATA_X));
	free(key.data);
	free(data.data);
	key.data = NULL;
	data.data = NULL;
	assert_equals(0, result);
}

extern "C" void test_insert_log_record_into_temp_with_no_app_metadata_returns_ok()
{
	std::string src = REMOTE_HOST;
	const char *log_buffer = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer;
	size_t loglen = strlen(log_buffer);
	std::string ser_id = "1";
	int db_error = 0;
	enum jaldb_status ret = jaldb_insert_log_record_into_temp(context, src,
		log_sys_meta_doc, NULL, logbuf, loglen, ser_id, &db_error);
	assert_equals(JALDB_OK, ret);

	std::string log_sys_db_name =
		jaldb_make_temp_db_name(REMOTE_HOST, JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer temp_log_sys_cont;
	ret = jaldb_open_temp_container(context, log_sys_db_name, temp_log_sys_cont);
	bool metadataFound = false;
	XmlValue val;
	XmlDocument log_sys_document = temp_log_sys_cont.getDocument(ser_id);
	metadataFound = log_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(REMOTE_HOST, source.c_str());

	std::string doc_name = log_sys_document.getName();
	assert_string_equals(ser_id.c_str(), doc_name.c_str());

	XmlValue has_app_meta_val;
	log_sys_document.getMetaData(JALDB_NS, JALDB_HAS_APP_META, has_app_meta_val);
	assert_false(has_app_meta_val.asBoolean());

	std::string content = "";
	MemBufInputSource *log_sys_mbis = NULL;
	Wrapper4InputSource *log_sys_wfis = NULL;
	DOMDocument *log_sys_dom_doc = NULL;
	DOMElement *log_sys_elem = NULL;
	content = log_sys_document.getContent(content);
	log_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	log_sys_wfis = new Wrapper4InputSource(log_sys_mbis);
	log_sys_dom_doc = parser->parse(log_sys_wfis);
	log_sys_elem = log_sys_dom_doc->getDocumentElement();
	delete log_sys_wfis;
	log_sys_wfis = NULL;
	assert_tag_equals("log_sys", log_sys_elem);

	DBT key;
	DBT data;
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));
	key.data = jal_strdup(ser_id.c_str());
	key.size = ser_id.length();
	key.flags = DB_DBT_USERMEM;
	data.flags = DB_DBT_MALLOC;
	int db_err;
	std::string log_db_name = jaldb_make_temp_db_name(REMOTE_HOST, JALDB_LOG_DB_NAME);
	XmlTransaction txn = context->manager->createTransaction();
	db_err = (*context->temp_dbs)[log_db_name]->get((*context->temp_dbs)[log_db_name],
		txn.getDB_TXN(), &key, &data, 0);
	assert_equals(0, db_err);
	assert_equals(strlen(LOG_DATA_X), data.size);
	int result = strncmp(LOG_DATA_X, (char *)(data.data), strlen(LOG_DATA_X));
	free(key.data);
	free(data.data);
	key.data = NULL;
	data.data = NULL;
	assert_equals(0, result);
}

extern "C" void test_insert_log_record_into_temp_fails_with_invalid_input()
{
	std::string src = REMOTE_HOST;
	const char *log_buffer = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer;
	size_t loglen = strlen(log_buffer);
	std::string ser_id = "1";
	int db_error = 0;
	enum jaldb_status ret = jaldb_insert_log_record_into_temp(NULL, src,
		log_sys_meta_doc, log_app_meta_doc, logbuf, loglen, ser_id, &db_error);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *tmp_mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_insert_log_record_into_temp(context, src, log_sys_meta_doc,
		log_app_meta_doc, logbuf, loglen, ser_id, &db_error);
	context->manager = tmp_mgr;
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_insert_journal_metadata_returns_inval_when_ctx_is_null()
{
	std::string sid = FAKE_SID;

	enum jaldb_status ret = jaldb_insert_journal_metadata(NULL, JALDB_LOCALHOST,
			audit_sys_meta_doc, audit_app_meta_doc, JOURNAL_ROOT, sid);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_insert_journal_metadata_returns_inval_when_ctx_journal_sys_cont_is_null()
{
	std::string sid = FAKE_SID;

	delete context->journal_sys_cont;
	context->journal_sys_cont = NULL;

	enum jaldb_status ret = jaldb_insert_journal_metadata(context, JALDB_LOCALHOST,
			audit_sys_meta_doc, audit_app_meta_doc, JOURNAL_ROOT, sid);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_insert_journal_metadata_helper_returns_inval_when_ctx_journal_app_cont_is_null()
{
	std::string sid = FAKE_SID;

	delete context->journal_app_cont;
	context->journal_app_cont = NULL;

	enum jaldb_status ret = jaldb_insert_journal_metadata(context, JALDB_LOCALHOST,
			audit_sys_meta_doc, audit_app_meta_doc, JOURNAL_ROOT, sid);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_insert_journal_metadata_returns_inval_when_sys_meta_doc_is_null()
{
	std::string sid = FAKE_SID;

	enum jaldb_status ret = jaldb_insert_journal_metadata(context, JALDB_LOCALHOST,
			NULL, audit_app_meta_doc, JOURNAL_ROOT, sid);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_insert_journal_metadata_returns_inval_when_path_len_zero()
{
	std::string sid = FAKE_SID;
	std::string path = "";

	enum jaldb_status ret = jaldb_insert_journal_metadata(context, JALDB_LOCALHOST,
			audit_sys_meta_doc, audit_app_meta_doc, path, sid);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_insert_journal_metadata_helper_returns_inval_when_sys_meta_doc_null()
{
	std::string sid = FAKE_SID;
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();

	enum jaldb_status ret = jaldb_insert_journal_metadata_helper(JALDB_LOCALHOST,
								txn,
								*context->manager,
								uc,
								*context->journal_sys_cont,
								*context->journal_app_cont,
								NULL,
								audit_app_meta_doc,
								JOURNAL_ROOT,
								sid);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_insert_journal_metadata_helper_returns_inval_when_path_len_zero()
{
	std::string sid = FAKE_SID;
	std::string path = "";
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();

	enum jaldb_status ret = jaldb_insert_journal_metadata_helper(JALDB_LOCALHOST,
								txn,
								*context->manager,
								uc,
								*context->journal_sys_cont,
								*context->journal_app_cont,
								audit_sys_meta_doc,
								audit_app_meta_doc,
								path,
								sid);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_insert_journal_metadata_helper_returns_inval_when_sid_len_zero()
{
	std::string sid = "";
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();

	enum jaldb_status ret = jaldb_insert_journal_metadata_helper(JALDB_LOCALHOST,
								txn,
								*context->manager,
								uc,
								*context->journal_sys_cont,
								*context->journal_app_cont,
								audit_sys_meta_doc,
								audit_app_meta_doc,
								JOURNAL_ROOT,
								sid);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_insert_journal_metadata_helper_returns_success()
{
	std::string sid = FAKE_SID;
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();

	enum jaldb_status ret = jaldb_insert_journal_metadata_helper(JALDB_LOCALHOST,
								txn,
								*context->manager,
								uc,
								*context->journal_sys_cont,
								*context->journal_app_cont,
								audit_sys_meta_doc,
								audit_app_meta_doc,
								JOURNAL_ROOT,
								sid);
	assert_equals(JALDB_OK, ret);
	txn.commit();

	bool metadataFound = false;
	XmlValue val;
	XmlDocument journal_sys_document = context->journal_sys_cont->getDocument(sid);
	metadataFound = journal_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(JALDB_LOCALHOST, source.c_str());

	std::string doc_name = "";
	doc_name = journal_sys_document.getName();
	assert_string_equals(FAKE_SID, doc_name.c_str());

	std::string content = "";
	MemBufInputSource *journal_sys_mbis = NULL;
	Wrapper4InputSource *journal_sys_wfis = NULL;
	DOMDocument *journal_sys_dom_doc = NULL;
	DOMElement *journal_sys_elem = NULL;
	content = journal_sys_document.getContent(content);
	journal_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), FAKE_SID, false);
	journal_sys_wfis = new Wrapper4InputSource(journal_sys_mbis);
	journal_sys_dom_doc = parser->parse(journal_sys_wfis);
	journal_sys_elem = journal_sys_dom_doc->getDocumentElement();
	assert_tag_equals("audit_sys", journal_sys_elem);
	delete journal_sys_wfis;
	journal_sys_wfis = NULL;

	doc_name = "";
	XmlDocument journal_app_document = context->journal_app_cont->getDocument(sid);
	doc_name = journal_app_document.getName();
	assert_string_equals(FAKE_SID, doc_name.c_str());

	content = "";
	MemBufInputSource *journal_app_mbis = NULL;
	Wrapper4InputSource *journal_app_wfis = NULL;
	DOMDocument *journal_app_dom_doc = NULL;
	DOMElement *journal_app_elem = NULL;
	content = journal_app_document.getContent(content);
	journal_app_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), FAKE_SID, false);
	journal_app_wfis = new Wrapper4InputSource(journal_app_mbis);
	journal_app_dom_doc = parser->parse(journal_app_wfis);
	journal_app_elem = journal_app_dom_doc->getDocumentElement();
	assert_tag_equals("audit_app", journal_app_elem);
	delete journal_app_wfis;
	journal_app_wfis = NULL;
}

extern "C" void test_jaldb_insert_journal_metadata_helper_returns_ok_when_app_meta_doc_null()
{
	std::string sid = FAKE_SID;
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();

	enum jaldb_status ret = jaldb_insert_journal_metadata_helper(JALDB_LOCALHOST,
								txn,
								*context->manager,
								uc,
								*context->journal_sys_cont,
								*context->journal_app_cont,
								audit_sys_meta_doc,
								NULL,
								JOURNAL_ROOT,
								sid);
	assert_equals(JALDB_OK, ret);
	txn.commit();

	bool metadataFound = false;
	XmlValue val;
	XmlDocument journal_sys_document = context->journal_sys_cont->getDocument(sid);
	metadataFound = journal_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(JALDB_LOCALHOST, source.c_str());

	std::string doc_name = "";
	doc_name = journal_sys_document.getName();
	assert_string_equals(FAKE_SID, doc_name.c_str());

	std::string content = "";
	MemBufInputSource *journal_sys_mbis = NULL;
	Wrapper4InputSource *journal_sys_wfis = NULL;
	DOMDocument *journal_sys_dom_doc = NULL;
	DOMElement *journal_sys_elem = NULL;
	content = journal_sys_document.getContent(content);
	journal_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), FAKE_SID, false);
	journal_sys_wfis = new Wrapper4InputSource(journal_sys_mbis);
	journal_sys_dom_doc = parser->parse(journal_sys_wfis);
	journal_sys_elem = journal_sys_dom_doc->getDocumentElement();
	assert_tag_equals("audit_sys", journal_sys_elem);
	delete journal_sys_wfis;
	journal_sys_wfis = NULL;

	try {
		XmlDocument journal_app_document = context->journal_app_cont->getDocument(sid);
	} catch (XmlException &e) {
		assert_equals(XmlException::DOCUMENT_NOT_FOUND, e.getExceptionCode());
	}
}

extern "C" void test_jaldb_insert_journal_metadata_returns_success()
{
	std::string src = "";
	std::string sid = "1";
	jaldb_status ret;
	ret = jaldb_insert_journal_metadata(
		context, src, audit_sys_meta_doc, audit_app_meta_doc, JOURNAL_ROOT, sid);
	assert_equals(JALDB_OK, ret);

	bool metadataFound = false;
	XmlValue val;
	XmlDocument journal_sys_document = context->journal_sys_cont->getDocument(sid);
	metadataFound = journal_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(JALDB_LOCALHOST, source.c_str());

	std::string doc_name = "";
	doc_name = journal_sys_document.getName();
	assert_string_equals("1", doc_name.c_str());

	std::string content = "";
	MemBufInputSource *journal_sys_mbis = NULL;
	Wrapper4InputSource *journal_sys_wfis = NULL;
	DOMDocument *journal_sys_dom_doc = NULL;
	DOMElement *journal_sys_elem = NULL;
	content = journal_sys_document.getContent(content);
	journal_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	journal_sys_wfis = new Wrapper4InputSource(journal_sys_mbis);
	journal_sys_dom_doc = parser->parse(journal_sys_wfis);
	journal_sys_elem = journal_sys_dom_doc->getDocumentElement();
	assert_tag_equals("audit_sys", journal_sys_elem);
	delete journal_sys_wfis;
	journal_sys_wfis = NULL;

	doc_name = "";
	XmlDocument journal_app_document = context->journal_app_cont->getDocument(sid);
	doc_name = journal_app_document.getName();
	assert_string_equals("1", doc_name.c_str());

	content = "";
	MemBufInputSource *journal_app_mbis = NULL;
	Wrapper4InputSource *journal_app_wfis = NULL;
	DOMDocument *journal_app_dom_doc = NULL;
	DOMElement *journal_app_elem = NULL;
	content = journal_app_document.getContent(content);
	journal_app_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	journal_app_wfis = new Wrapper4InputSource(journal_app_mbis);
	journal_app_dom_doc = parser->parse(journal_app_wfis);
	journal_app_elem = journal_app_dom_doc->getDocumentElement();
	assert_tag_equals("audit_app", journal_app_elem);
	delete journal_app_wfis;
	journal_app_wfis = NULL;
}
extern "C" void test_audit_record_lookup_returns_ok()
{
	std::string src = "";
	std::string ser_id = "2";
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, NULL, audit_doc, ser_id);
	assert_equals(JALDB_OK, ret);

	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *audit_buf = NULL;
	size_t audit_len = 0;

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		 &app_meta_buf, &app_meta_len, &audit_buf, &audit_len);

	assert_equals(JALDB_OK, ret);
	assert_equals(NULL, app_meta_buf);
	assert_equals(0, app_meta_len);
	assert_not_equals(NULL, sys_meta_buf);
	assert_not_equals(0, sys_meta_len);
	assert_not_equals(NULL, audit_buf);
	assert_not_equals(0, audit_len);

	XmlDocument audit_sys_document = context->audit_sys_cont->getDocument(ser_id);

	std::string content = "";

	content = audit_sys_document.getContent(content);
	assert_string_equals(content.c_str(), sys_meta_buf);

	XmlDocument audit_app_document;
	try {
		audit_app_document = context->audit_app_cont->getDocument(ser_id);
		// document should not exist in the database.
		assert_false(true);
	} catch (XmlException &e) {
		// a thrown exception is expected since no app data was added.
	}

	XmlDocument audit_document = context->audit_cont->getDocument(ser_id);

	content = "";
	content = audit_document.getContent(content);
	assert_string_equals(content.c_str(), audit_buf);
	free(app_meta_buf);
	free(sys_meta_buf);
	free(audit_buf);
}
extern "C" void test_audit_record_lookup_returns_ok_with_app_metadata()
{
	std::string src = "fake_host";
	std::string ser_id = "2";
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_OK, ret);

	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *audit_buf = NULL;
	size_t audit_len = 0;

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, app_meta_buf);
	assert_not_equals(0, app_meta_len);
	assert_not_equals(NULL, sys_meta_buf);
	assert_not_equals(0, sys_meta_len);
	assert_not_equals(NULL, audit_buf);
	assert_not_equals(0, audit_len);

	XmlValue src_val;
	XmlDocument audit_sys_document = context->audit_sys_cont->getDocument(ser_id);
	audit_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, src_val);
	assert_string_equals(src.c_str(), src_val.asString().c_str());

	std::string content = "";

	content = audit_sys_document.getContent(content);
	assert_string_equals(content.c_str(), sys_meta_buf);

	XmlDocument audit_app_document;
	audit_app_document = context->audit_app_cont->getDocument(ser_id);

	content = "";
	content = audit_app_document.getContent(content);
	assert_string_equals(content.c_str(), app_meta_buf);

	XmlDocument audit_document = context->audit_cont->getDocument(ser_id);
	audit_document.getMetaData(JALDB_NS, JALDB_SOURCE, src_val);

	content = "";
	content = audit_document.getContent(content);
	assert_string_equals(content.c_str(), audit_buf);
	free(app_meta_buf);
	free(sys_meta_buf);
	free(audit_buf);
}

extern "C" void test_audit_record_lookup_fails_on_invalid_input()
{

	std::string src = "";
	audit_app_meta_doc = NULL;
	std::string ser_id = "2";
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_OK, ret);

	//Test Vars
	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *audit_buf = NULL;
	uint8_t *bad_pointer = (uint8_t*)0xDEADBEEF;
	size_t audit_len = 0;

	ret = jaldb_lookup_audit_record(NULL, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, NULL, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), NULL, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &bad_pointer, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &sys_meta_buf, NULL,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		NULL, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&bad_pointer, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, NULL, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, NULL, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &bad_pointer, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, NULL);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_audit_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, NULL, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_lookup_log_record_fails_on_invalid_input()
{
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	int db_err = 0;
	std::string src = "";
	audit_app_meta_doc = NULL;
	std::string ser_id = "3";
	jaldb_status ret;

	ret = jaldb_insert_log_record(
			context, src, log_sys_meta_doc, log_app_meta_doc, logbuf, loglen, ser_id, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	//Test Vars
	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *log_buf = NULL;
	uint8_t *bad_pointer = (uint8_t*)0xDEADBEEF;
	size_t log_len = 0;

	ret = jaldb_lookup_log_record(NULL, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, NULL, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, ser_id.c_str(), NULL, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, ser_id.c_str(), &bad_pointer, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, ser_id.c_str(), &sys_meta_buf, NULL,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		NULL, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&bad_pointer, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, NULL, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, NULL, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &bad_pointer, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, NULL, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_lookup_log_record(context, ser_id.c_str(), &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, NULL);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_lookup_log_record_succeeds()
{
	std::string src;
	std::string sid;
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	int db_err = 0;
	enum jaldb_status ret;

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
				logbuf, loglen, sid, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;

	ret = jaldb_lookup_log_record(context, sid.c_str(), &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_not_equals(NULL, app_buf);
	assert_true(app_sz > 0);
	assert_not_equals(NULL, log_buf);
	assert_true(log_sz > 0);
	assert_equals(0, db_err);

	free(sys_buf);
	free(app_buf);
	free(log_buf);
}

extern "C" void test_jaldb_lookup_log_record_succeeds_with_no_app_meta()
{
	std::string src;
	std::string sid;
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	int db_err = 0;
	enum jaldb_status ret;

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, NULL,
				logbuf, loglen, sid, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);


	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;

	ret = jaldb_lookup_log_record(context, sid.c_str(), &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_not_equals(NULL, log_buf);
	assert_true(log_sz > 0);
	assert_equals(0, db_err);
	free(sys_buf);
	free(log_buf);
}

extern "C" void test_jaldb_lookup_log_record_returns_not_found()
{
	std::string sid = "1";
	enum jaldb_status ret;
	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;
	int db_err = 0;

	ret = jaldb_lookup_log_record(context, sid.c_str(), &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_equals(NULL, log_buf);
	assert_true(log_sz == 0);
}

extern "C" void test_jaldb_lookup_log_record_succeeds_when_no_log_meta()
{
	std::string src;
	std::string sid;
	int db_err = 0;
	enum jaldb_status ret;

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
				NULL, 0, sid, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);


	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;

	ret = jaldb_lookup_log_record(context, sid.c_str(), &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_not_equals(NULL, app_buf);
	assert_true(app_sz > 0);
	assert_equals(NULL, log_buf);
	assert_true(log_sz == 0);
	assert_equals(0, db_err);
	free(sys_buf);
	free(app_buf);
}

extern "C" void test_jaldb_lookup_journal_record_fails_on_invalid_input()
{
	enum jaldb_status ret;
	int fd = -1;
	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	std::string sid = "12341234";

	ret = jaldb_lookup_journal_record(context, sid.c_str(), NULL,
				&sys_sz, &app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_lookup_journal_record(context, NULL, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_lookup_journal_record(NULL, sid.c_str(), &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_lookup_journal_record(context, sid.c_str(), &sys_buf, &sys_sz,
				NULL, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_lookup_journal_record(context, sid.c_str(), NULL, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	sys_buf = (uint8_t *)malloc(sizeof(*sys_buf));
	ret = jaldb_lookup_journal_record(context, sid.c_str(), &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	free(sys_buf);
	sys_buf = NULL;

	app_buf = (uint8_t *)malloc(sizeof(*sys_buf));
	ret = jaldb_lookup_journal_record(context, sid.c_str(), &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_not_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	free(app_buf);
	app_buf = NULL;


	fd = 0;
	ret = jaldb_lookup_journal_record(context, sid.c_str(), &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == 0);
}

extern "C" void test_jaldb_lookup_journal_record_succeeds()
{
	int rc = 0;
	int fd = -1;
	std::string source;
	std::string sid;
	std::string msg = "journal";
	char *buf = NULL;
	char *path = NULL;
	enum jaldb_status ret;

	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					audit_app_meta_doc,
					path,
					sid);

	assert_equals(JALDB_OK, ret);

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	fd = -1;

	ret = jaldb_lookup_journal_record(context,
				sid.c_str(),
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_not_equals(NULL, app_buf);
	assert_true(app_sz > 0);
	assert_true(fd > -1);
	assert_true(fd_sz > 0);

	buf = (char *)malloc(fd_sz);
	rc = read(fd, buf, fd_sz);
	assert_not_equals(-1, rc);
	size_t len1 = strlen(buf);
	assert_equals(len1, msg.length());
	assert_true(!memcmp(buf, msg.c_str(), len1));
	close(fd);
	free(path);
	free(buf);
	free(sys_buf);
	free(app_buf);
}

extern "C" void test_jaldb_lookup_journal_record_succeeds_with_no_app_meta()
{
	int rc = 0;
	int fd = -1;
	std::string source;
	std::string sid;
	std::string msg = "journal";
	char *buf = NULL;
	char *path = NULL;
	enum jaldb_status ret;

	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					NULL,
					path,
					sid);

	assert_equals(JALDB_OK, ret);

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	fd = -1;

	ret = jaldb_lookup_journal_record(context,
				sid.c_str(),
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd > -1);
	assert_true(fd_sz > 0);

	buf = (char *)malloc(fd_sz);
	rc = read(fd, buf, fd_sz);
	assert_not_equals(-1, rc);
	size_t len1 = strlen(buf);
	size_t len2 = strlen(msg.c_str());
	assert_equals(len1, len2);
	assert_true(!memcmp(buf, msg.c_str(), len1));
	close(fd);
	free(path);
	free(buf);
	free(sys_buf);
}

extern "C" void test_jaldb_lookup_journal_record_returns_not_found()
{
	int fd = -1;
	std::string sid;
	enum jaldb_status ret;

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;

	ret = jaldb_lookup_journal_record(context,
				sid.c_str(),
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	assert_true(fd_sz == 0);
}

extern "C" void test_jaldb_lookup_journal_record_returns_corrupted_when_no_journal_file()
{
	int fd = -1;
	std::string source;
	std::string sid;
	char *path = strdup("/foo/bar/journal.asdf");
	enum jaldb_status ret;

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					audit_app_meta_doc,
					path,
					sid);

	assert_equals(JALDB_OK, ret);

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	fd = -1;

	ret = jaldb_lookup_journal_record(context,
				sid.c_str(),
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_E_CORRUPTED, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	assert_true(fd_sz == 0);
	free(path);
}

extern "C" void test_jaldb_insert_journal_metadata_into_temp_succeeds()
{
	XMLPlatformUtils::Initialize();
	std::string sid = "1";
	std::string src = "localhost";
	char *path = NULL;
	int rc = 0;
	int fd = -1;
	std::string msg = "journal";
	enum jaldb_status ret;

	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata_into_temp(context, src, log_sys_meta_doc,
						log_app_meta_doc, path, sid);
	assert_equals(JALDB_OK, ret);

	std::string sys_meta_name = jaldb_make_temp_db_name(src, JALDB_JOURNAL_SYS_META_CONT_NAME);
	assert_not_equals("", sys_meta_name);

	std::string app_meta_name = jaldb_make_temp_db_name(src, JALDB_JOURNAL_APP_META_CONT_NAME);
	assert_not_equals("", app_meta_name);

	XmlContainer sys_cont;
	XmlContainer app_cont;

	ret = jaldb_open_temp_container(context, sys_meta_name, sys_cont);
	assert_equals(ret, JALDB_OK);

	ret = jaldb_open_temp_container(context, app_meta_name, app_cont);
	assert_equals(ret, JALDB_OK);

	bool metadataFound = false;
	XmlValue val;
	XmlDocument journal_sys_document = sys_cont.getDocument(sid);
	metadataFound = journal_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(JALDB_LOCALHOST, source.c_str());

	std::string doc_name = "";
	doc_name = journal_sys_document.getName();
	assert_string_equals("1", doc_name.c_str());

	std::string content = "";
	MemBufInputSource *journal_sys_mbis = NULL;
	Wrapper4InputSource *journal_sys_wfis = NULL;
	DOMDocument *journal_sys_dom_doc = NULL;
	DOMElement *journal_sys_elem = NULL;
	content = journal_sys_document.getContent(content);
	journal_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	journal_sys_wfis = new Wrapper4InputSource(journal_sys_mbis);
	journal_sys_dom_doc = parser->parse(journal_sys_wfis);
	journal_sys_elem = journal_sys_dom_doc->getDocumentElement();
	assert_tag_equals("log_sys", journal_sys_elem);
	delete journal_sys_wfis;
	journal_sys_wfis = NULL;

	doc_name = "";
	XmlDocument journal_app_document = app_cont.getDocument(sid);
	doc_name = journal_app_document.getName();
	assert_string_equals("1", doc_name.c_str());

	content = "";
	MemBufInputSource *journal_app_mbis = NULL;
	Wrapper4InputSource *journal_app_wfis = NULL;
	DOMDocument *journal_app_dom_doc = NULL;
	DOMElement *journal_app_elem = NULL;
	content = journal_app_document.getContent(content);
	journal_app_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	journal_app_wfis = new Wrapper4InputSource(journal_app_mbis);
	journal_app_dom_doc = parser->parse(journal_app_wfis);
	journal_app_elem = journal_app_dom_doc->getDocumentElement();
	assert_tag_equals("log_app", journal_app_elem);
	delete journal_app_wfis;
	journal_app_wfis = NULL;
}

extern "C" void test_jaldb_insert_journal_metadata_into_temp_succeeds_with_no_app_meta()
{
	XMLPlatformUtils::Initialize();
	std::string sid = "1";
	std::string src = "localhost";
	char *path = NULL;
	int rc = 0;
	int fd = -1;
	std::string msg = "journal";
	enum jaldb_status ret;

	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata_into_temp(context, src, log_sys_meta_doc,
						NULL, JOURNAL_ROOT, sid);
	assert_equals(JALDB_OK, ret);

	std::string sys_meta_name = jaldb_make_temp_db_name(src, JALDB_JOURNAL_SYS_META_CONT_NAME);
	assert_not_equals("", sys_meta_name);

	std::string app_meta_name = jaldb_make_temp_db_name(src, JALDB_JOURNAL_APP_META_CONT_NAME);
	assert_not_equals("", app_meta_name);

	XmlContainer sys_cont;
	XmlContainer app_cont;

	ret = jaldb_open_temp_container(context, sys_meta_name, sys_cont);
	assert_equals(ret, JALDB_OK);

	ret = jaldb_open_temp_container(context, app_meta_name, app_cont);
	assert_equals(ret, JALDB_OK);

	bool metadataFound = false;
	XmlValue val;
	XmlDocument journal_sys_document = sys_cont.getDocument(sid);
	metadataFound = journal_sys_document.getMetaData(JALDB_NS, JALDB_SOURCE, val);
	std::string source = val.asString();
	assert_string_equals(JALDB_LOCALHOST, source.c_str());

	std::string doc_name = "";
	doc_name = journal_sys_document.getName();
	assert_string_equals("1", doc_name.c_str());

	std::string content = "";
	MemBufInputSource *journal_sys_mbis = NULL;
	Wrapper4InputSource *journal_sys_wfis = NULL;
	DOMDocument *journal_sys_dom_doc = NULL;
	DOMElement *journal_sys_elem = NULL;
	content = journal_sys_document.getContent(content);
	journal_sys_mbis = new MemBufInputSource(reinterpret_cast<const XMLByte *>(content.c_str()),
		strlen(content.c_str()), "1", false);
	journal_sys_wfis = new Wrapper4InputSource(journal_sys_mbis);
	journal_sys_dom_doc = parser->parse(journal_sys_wfis);
	journal_sys_elem = journal_sys_dom_doc->getDocumentElement();
	assert_tag_equals("log_sys", journal_sys_elem);
	delete journal_sys_wfis;
	journal_sys_wfis = NULL;

	try {
		XmlDocument journal_app_document = context->journal_app_cont->getDocument(sid);
		assert_false(true);
	} catch (XmlException &e) {
		assert_equals(XmlException::DOCUMENT_NOT_FOUND, e.getExceptionCode());
	}
}

extern "C" void test_jaldb_insert_journal_metadata_into_temp_fails_on_invalid_data()
{
	XMLPlatformUtils::Initialize();
	std::string sid = "1";
	std::string src = "localhost";

	enum jaldb_status ret;

	ret = jaldb_insert_journal_metadata_into_temp(NULL, src, log_sys_meta_doc,
						log_app_meta_doc, JOURNAL_ROOT, sid);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_insert_journal_metadata_into_temp(context, "", log_sys_meta_doc,
						log_app_meta_doc, JOURNAL_ROOT, sid);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_insert_journal_metadata_into_temp(context, src, NULL,
						log_app_meta_doc, JOURNAL_ROOT, sid);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_insert_journal_metadata_into_temp(context, src, log_sys_meta_doc,
						log_app_meta_doc, "", sid);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_read_only_flag_prevents_writing_to_db()
{
	jaldb_context *ctx = jaldb_context_create();
	enum jaldb_status ret;
	int db_err;
	ret = jaldb_context_init(ctx, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, 0, 1);
	assert_equals(JALDB_OK, ret);

	std::string src = "foo";
	XmlTransaction transaction = ctx->manager->createTransaction();
	XmlUpdateContext update_ctx = ctx->manager->createUpdateContext();
	std::string ser_id = "1";

	ret = jaldb_insert_audit_record(ctx, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_E_READ_ONLY, ret);

	ret = jaldb_insert_audit_record_into_temp(ctx, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, ser_id);
	assert_equals(JALDB_E_READ_ONLY, ret);

	ret = jaldb_insert_log_record(ctx, src, audit_sys_meta_doc, audit_app_meta_doc, (uint8_t*) LOG_DATA_X, strlen(LOG_DATA_X), ser_id, &db_err);
	assert_equals(JALDB_E_READ_ONLY, ret);

	ret = jaldb_insert_log_record_into_temp(ctx, src, audit_sys_meta_doc, audit_app_meta_doc, (uint8_t*) LOG_DATA_X, strlen(LOG_DATA_X), ser_id, &db_err);
	assert_equals(JALDB_E_READ_ONLY, ret);

	ret = jaldb_insert_journal_metadata(ctx, src, audit_sys_meta_doc, audit_app_meta_doc, JOURNAL_ROOT, ser_id);
	assert_equals(JALDB_E_READ_ONLY, ret);

	ret = jaldb_insert_journal_metadata_into_temp(ctx, src, audit_sys_meta_doc, audit_app_meta_doc, JOURNAL_ROOT, ser_id);
	assert_equals(JALDB_E_READ_ONLY, ret);

	jaldb_context_destroy(&ctx);
}

extern "C" void test_next_audit_record_returns_ok()
{
	std::string src = "";
	std::string last_sid;
	std::string sid;
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, NULL, audit_doc, last_sid);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, NULL, audit_doc, sid);
	assert_equals(JALDB_OK, ret);

	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *audit_buf = NULL;
	size_t audit_len = 0;
	char *next_sid = NULL;

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		 &app_meta_buf, &app_meta_len, &audit_buf, &audit_len);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, next_sid);
	assert_equals(0, strcmp(next_sid, sid.c_str()));
	assert_equals(NULL, app_meta_buf);
	assert_equals(0, app_meta_len);
	assert_not_equals(NULL, sys_meta_buf);
	assert_not_equals(0, sys_meta_len);
	assert_not_equals(NULL, audit_buf);
	assert_not_equals(0, audit_len);

	free(next_sid);
	free(app_meta_buf);
	free(sys_meta_buf);
	free(audit_buf);
}

extern "C" void test_next_audit_record_returns_ok_with_app_metadata()
{
	std::string src = "fake_host";
	std::string last_sid;
	std::string sid;
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, last_sid);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, sid);
	assert_equals(JALDB_OK, ret);

	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *audit_buf = NULL;
	size_t audit_len = 0;
	char *next_sid = NULL;

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, app_meta_buf);
	assert_not_equals(0, app_meta_len);
	assert_not_equals(NULL, sys_meta_buf);
	assert_not_equals(0, sys_meta_len);
	assert_not_equals(NULL, audit_buf);
	assert_not_equals(0, audit_len);

	free(next_sid);
	free(app_meta_buf);
	free(sys_meta_buf);
	free(audit_buf);
}

extern "C" void test_next_audit_fails_on_invalid_input()
{

	std::string src = "";
	audit_app_meta_doc = NULL;
	std::string last_sid;
	jaldb_status ret;
	ret = jaldb_insert_audit_record(
			context, src, audit_sys_meta_doc, audit_app_meta_doc, audit_doc, last_sid);
	assert_equals(JALDB_OK, ret);

	//Test Vars
	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *audit_buf = NULL;
	uint8_t *bad_pointer = (uint8_t*)0xDEADBEEF;
	size_t audit_len = 0;
	char *next_sid = NULL;

	ret = jaldb_next_audit_record(NULL, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, NULL, &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_sid.c_str(), NULL, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	next_sid = (char*) 0xbadf00d;
	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);
	next_sid = NULL;

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, NULL, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &bad_pointer, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, NULL,
		&app_meta_buf, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		NULL, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&bad_pointer, &app_meta_len, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, NULL, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, NULL, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &bad_pointer, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &audit_buf, NULL);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_audit_record(context, last_sid.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, NULL, &audit_buf, &audit_len);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_next_log_record_fails_on_invalid_input()
{
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	int db_err = 0;
	char *next_sid;
	std::string src = "";
	audit_app_meta_doc = NULL;
	std::string ser_id = "3";
	jaldb_status ret;

	ret = jaldb_insert_log_record(
			context, src, log_sys_meta_doc, log_app_meta_doc, logbuf, loglen, ser_id, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	//Test Vars
	uint8_t *sys_meta_buf = NULL;
	size_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	size_t app_meta_len = 0;
	uint8_t *log_buf = NULL;
	uint8_t *bad_pointer = (uint8_t*)0xDEADBEEF;
	size_t log_len = 0;

	ret = jaldb_next_log_record(NULL, ser_id.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, NULL, &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, ser_id.c_str(), NULL, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	next_sid = (char*) 0xbadf00d;
	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, &sys_meta_buf,
			&sys_meta_len, &app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);
	next_sid = NULL;

	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, NULL, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, &bad_pointer, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, &sys_meta_buf, NULL,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		NULL, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&bad_pointer, &app_meta_len, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, NULL, &log_buf, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, NULL, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &bad_pointer, &log_len, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, NULL, &db_err);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_next_log_record(context, ser_id.c_str(), &next_sid, &sys_meta_buf, &sys_meta_len,
		&app_meta_buf, &app_meta_len, &log_buf, &log_len, NULL);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_next_log_record_succeeds()
{
	std::string src;
	std::string last_sid;
	std::string sid;
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	int db_err = 0;
	enum jaldb_status ret;

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
				logbuf, loglen, last_sid, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
				logbuf, loglen, sid, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	char *next_sid = NULL;
	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;

	ret = jaldb_next_log_record(context, last_sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, next_sid);
	assert_equals(0, strcmp(next_sid, sid.c_str()));
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_not_equals(NULL, app_buf);
	assert_true(app_sz > 0);
	assert_not_equals(NULL, log_buf);
	assert_true(log_sz > 0);
	assert_equals(0, db_err);

	free(next_sid);
	free(sys_buf);
	free(app_buf);
	free(log_buf);
}

extern "C" void test_jaldb_next_log_record_succeeds_with_no_app_meta()
{
	std::string src;
	std::string last_sid;
	std::string sid;
	char *next_sid = NULL;
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	int db_err = 0;
	enum jaldb_status ret;

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, NULL,
				logbuf, loglen, last_sid, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, NULL,
				logbuf, loglen, sid, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);


	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;

	ret = jaldb_next_log_record(context, last_sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, next_sid);
	assert_equals(0, strcmp(sid.c_str(), next_sid));
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_not_equals(NULL, log_buf);
	assert_true(log_sz > 0);
	assert_equals(0, db_err);

	free(next_sid);
	free(sys_buf);
	free(log_buf);
}

extern "C" void test_jaldb_next_log_record_returns_not_found()
{
	std::string src;
	std::string sid = "1";
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *logbuf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	char *next_sid = NULL;
	enum jaldb_status ret;
	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;
	int db_err = 0;

	ret = jaldb_next_log_record(context, sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_equals(NULL, log_buf);
	assert_true(log_sz == 0);

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, NULL,
				logbuf, loglen, sid, &db_err);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_next_log_record(context, sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_equals(NULL, log_buf);
	assert_true(log_sz == 0);
}

extern "C" void test_jaldb_next_log_record_succeeds_when_no_log_meta()
{
	std::string src;
	std::string last_sid;
	std::string sid;
	char *next_sid = NULL;
	int db_err = 0;
	enum jaldb_status ret;

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
				NULL, 0, last_sid, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);

	ret = jaldb_insert_log_record(context, src, log_sys_meta_doc, log_app_meta_doc,
				NULL, 0, sid, &db_err);
	assert_equals(JALDB_OK, ret);
	assert_equals(0, db_err);


	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	uint8_t *log_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t log_sz = 0;

	ret = jaldb_next_log_record(context, last_sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &log_buf, &log_sz, &db_err);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, next_sid);
	assert_equals(0, strcmp(sid.c_str(), next_sid));
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz > 0);
	assert_not_equals(NULL, app_buf);
	assert_true(app_sz > 0);
	assert_equals(NULL, log_buf);
	assert_true(log_sz == 0);
	assert_equals(0, db_err);
	free(next_sid);
	free(sys_buf);
	free(app_buf);
}

extern "C" void test_jaldb_next_journal_record_fails_on_invalid_input()
{
	enum jaldb_status ret;
	int fd = -1;
	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	char *next_sid = NULL;
	std::string sid = "12341234";

	ret = jaldb_next_journal_record(context, sid.c_str(), &next_sid, NULL,
				&sys_sz, &app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_next_journal_record(context, NULL, &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_next_journal_record(NULL, sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_next_journal_record(context, sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				NULL, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	ret = jaldb_next_journal_record(context, sid.c_str(), &next_sid, NULL, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	sys_buf = (uint8_t *)malloc(sizeof(*sys_buf));
	ret = jaldb_next_journal_record(context, sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_not_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	free(sys_buf);
	sys_buf = NULL;

	app_buf = (uint8_t *)malloc(sizeof(*sys_buf));
	ret = jaldb_next_journal_record(context, sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_not_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	free(app_buf);
	app_buf = NULL;


	fd = 0;
	ret = jaldb_next_journal_record(context, sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == 0);
	fd = -1;

	ret = jaldb_next_journal_record(context, sid.c_str(), NULL, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);

	next_sid = (char*) 0xbadf00d;
	ret = jaldb_next_journal_record(context, sid.c_str(), &next_sid, &sys_buf, &sys_sz,
				&app_buf, &app_sz, &fd, &fd_sz);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
}

extern "C" void test_jaldb_next_journal_record_succeeds()
{
	int rc = 0;
	int fd = -1;
	std::string source;
	std::string last_sid;
	std::string sid;
	char *next_sid = NULL;
	std::string msg = "journal";
	char *buf = NULL;
	char *path = NULL;
	enum jaldb_status ret;

	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					audit_app_meta_doc,
					path,
					last_sid);

	assert_equals(JALDB_OK, ret);
	fd = -1;
	free(path);
	path = NULL;
	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					NULL,
					path,
					sid);

	assert_equals(JALDB_OK, ret);

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	fd = -1;

	ret = jaldb_next_journal_record(context,
				last_sid.c_str(),
				&next_sid,
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, sys_buf);
	assert_not_equals(NULL, next_sid);
	assert_equals(0, strcmp(sid.c_str(), next_sid));
	assert_true(sys_sz > 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd > -1);
	assert_true(fd_sz > 0);

	buf = (char *)malloc(fd_sz);
	rc = read(fd, buf, fd_sz);
	assert_not_equals(-1, rc);
	assert_true(!strcmp(buf, msg.c_str()));
	close(fd);
	free(next_sid);
	free(path);
	free(buf);
	free(sys_buf);
	free(app_buf);
}

extern "C" void test_jaldb_next_journal_record_succeeds_with_no_app_meta()
{
	int rc = 0;
	int fd = -1;
	std::string source;
	std::string last_sid;
	std::string sid;
	char *next_sid = NULL;
	std::string msg = "journal";
	char *buf = NULL;
	char *path = NULL;
	enum jaldb_status ret;

	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					audit_app_meta_doc,
					path,
					last_sid);

	assert_equals(JALDB_OK, ret);
	fd = -1;
	free(path);
	path = NULL;
	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					NULL,
					path,
					sid);

	assert_equals(JALDB_OK, ret);

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	fd = -1;

	ret = jaldb_next_journal_record(context,
				last_sid.c_str(),
				&next_sid,
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, next_sid);
	assert_equals(0, strcmp(sid.c_str(), next_sid));
	assert_not_equals(NULL, sys_buf);
	assert_equals(0, strcmp(sid.c_str(), next_sid));
	assert_true(sys_sz > 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd > -1);
	assert_true(fd_sz > 0);

	buf = (char *)malloc(fd_sz);
	rc = read(fd, buf, fd_sz);
	assert_not_equals(-1, rc);
	assert_true(!strcmp(buf, msg.c_str()));
	free(next_sid);
	close(fd);
	free(path);
	free(buf);
	free(sys_buf);
}

extern "C" void test_jaldb_next_journal_record_returns_not_found()
{
	int rc = 0;
	int fd = -1;
	std::string sid = "1";
	std::string source;
	enum jaldb_status ret;
	char *next_sid = NULL;
	char *path = NULL;
	std::string msg = "journal";

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;

	ret = jaldb_next_journal_record(context,
				sid.c_str(),
				&next_sid,
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals(NULL, next_sid);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	assert_true(fd_sz == 0);

	ret = jaldb_create_journal_file(context, &path, &fd);

	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path);
	assert_not_equals(-1, fd);

	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					NULL,
					path,
					sid);

	assert_equals(JALDB_OK, ret);
	fd = -1;

	ret = jaldb_next_journal_record(context,
				sid.c_str(),
				&next_sid,
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_E_NOT_FOUND, ret);
	assert_equals(NULL, next_sid);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	assert_true(fd_sz == 0);
}

extern "C" void test_jaldb_next_journal_record_returns_corrupted_when_no_journal_file()
{
	int fd = -1;
	std::string source;
	std::string last_sid;
	std::string sid;
	char *next_sid = NULL;
	char *path = strdup("/foo/bar/journal.asdf");
	enum jaldb_status ret;

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					audit_app_meta_doc,
					path,
					last_sid);

	assert_equals(JALDB_OK, ret);

	ret = jaldb_insert_journal_metadata(context,
					source,
					audit_sys_meta_doc,
					audit_app_meta_doc,
					path,
					sid);

	assert_equals(JALDB_OK, ret);

	uint8_t *sys_buf = NULL;
	uint8_t *app_buf = NULL;
	size_t sys_sz = 0;
	size_t app_sz = 0;
	size_t fd_sz = 0;
	fd = -1;

	ret = jaldb_next_journal_record(context,
				last_sid.c_str(),
				&next_sid,
				&sys_buf,
				&sys_sz,
				&app_buf,
				&app_sz,
				&fd,
				&fd_sz);

	assert_equals(JALDB_E_CORRUPTED, ret);
	assert_equals(NULL, next_sid);
	assert_equals(NULL, sys_buf);
	assert_true(sys_sz == 0);
	assert_equals(NULL, app_buf);
	assert_true(app_sz == 0);
	assert_true(fd == -1);
	assert_true(fd_sz == 0);
	free(path);
}

extern "C" void test_jaldb_update_sync_works()
{
	XmlManager mgr = *(context->manager);
	XmlContainer cont = mgr.createContainer("update_sync_test");
	XmlDocument doc;
	XmlUpdateContext uc = mgr.createUpdateContext();

	string sync_id(JALDB_REMOTE_META_PREFIX REMOTE_HOST JALDB_SYNC_META_SUFFIX);
	string sent_id(JALDB_REMOTE_META_PREFIX REMOTE_HOST JALDB_SENT_META_SUFFIX);

	cont.putDocument(JALDB_SERIAL_ID_DOC_NAME, "<doc>serial_id</doc>", uc);

	cont.putDocument("1", "<doc>1</doc>", uc);
	doc = cont.getDocument("1");
	doc.setMetaData(JALDB_NS, sent_id, false);
	doc.setMetaData(JALDB_NS, sync_id, false);
	cont.updateDocument(doc, uc);

	cont.putDocument("2", "<doc>2</doc>", uc);
	doc = cont.getDocument("2");
	doc.setMetaData(JALDB_NS, sent_id, false);
	doc.setMetaData(JALDB_NS, sync_id, true);
	cont.updateDocument(doc, uc);

	cont.putDocument("A", "<doc>A</doc>", uc);
	doc = cont.getDocument("A");
	doc.setMetaData(JALDB_NS, sent_id, true);
	doc.setMetaData(JALDB_NS, sync_id, false);
	cont.updateDocument(doc, uc);

	cont.putDocument("Z", "<doc>Z</doc>", uc);
	doc = cont.getDocument("Z");
	doc.setMetaData(JALDB_NS, sent_id, true);
	doc.setMetaData(JALDB_NS, sync_id, true);
	cont.updateDocument(doc, uc);

	cont.putDocument("a", "<doc>a</doc>", uc);
	doc = cont.getDocument("a");
	doc.setMetaData(JALDB_NS, sent_id, true);
	cont.updateDocument(doc, uc);

	cont.putDocument("z", "<doc>z</doc>", uc);
	doc = cont.getDocument("z");
	doc.setMetaData(JALDB_NS, sync_id, false);
	cont.updateDocument(doc, uc);

	cont.putDocument("10", "<doc>10</doc>", uc);

	cont.putDocument("12", "<doc>12</doc>", uc);

	cont.putDocument("13", "<doc>13</doc>", uc);
	doc = cont.getDocument("13");
	doc.setMetaData(JALDB_NS, sent_id, true);
	cont.updateDocument(doc, uc);

	XmlValue v;
	enum jaldb_status ret = jaldb_mark_synced_common(context, &cont, "12", REMOTE_HOST);
	assert_equals(JALDB_OK, ret);

	// never sent correctly, so don't mark synced
	doc = cont.getDocument("1");
	assert_true(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_true(v.isBoolean());
	assert_false(v.asBoolean());
	assert_true(doc.getMetaData(JALDB_NS, sync_id, v));
	assert_true(v.isBoolean());
	assert_false(v.asBoolean());

	// not sent correctly, but already synced (shouldn't happen, but shouldn't modify either).
	doc = cont.getDocument("2");
	assert_true(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_false(v.asBoolean());
	assert_true(doc.getMetaData(JALDB_NS, sync_id, v));
	assert_true(v.asBoolean());

	// sent correctly, never synced, should now be marked as 'synced'
	doc = cont.getDocument("A");
	assert_true(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_true(v.asBoolean());
	assert_true(v = doc.getMetaData(JALDB_NS, sync_id, v));
	assert_true(v.asBoolean());

	// sent & synced, shouldn't be changed
	doc = cont.getDocument("Z");
	assert_true(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_true(v.asBoolean());
	assert_true(doc.getMetaData(JALDB_NS, sync_id, v));
	assert_true(v.asBoolean());

	// sent correctly, missing sync, should now be marked as 'synced'
	doc = cont.getDocument("a");
	assert_true(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_true(v.asBoolean());
	assert_true(doc.getMetaData(JALDB_NS, sync_id, v));
	assert_true(v.asBoolean());

	// missing sent, marked as not synced, should remain not 'synced'
	doc = cont.getDocument("z");
	assert_false(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_true(doc.getMetaData(JALDB_NS, sync_id, v));
	assert_false(v.asBoolean());

	// missing sent, missing sync, no change.
	doc = cont.getDocument("10");
	assert_false(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_false(doc.getMetaData(JALDB_NS, sync_id, v));

	// missing sent, missing sync, no change.
	doc = cont.getDocument("12");
	assert_false(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_false(doc.getMetaData(JALDB_NS, sync_id, v));

	// serial ID is after the one we were looking for, so shouldn't 
	// be modified
	doc = cont.getDocument("13");
	assert_true(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_true(v.asBoolean());
	assert_false(doc.getMetaData(JALDB_NS, sync_id, v));
}

extern "C" void test_jaldb_update_sync_returns_error_on_bad_input()
{
	enum jaldb_status ret;
	XmlContainer *cont = (XmlContainer*) 0xbadf00d;

	ret = jaldb_mark_synced_common(NULL, cont, "12", REMOTE_HOST);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_mark_synced_common(context, cont, "12", REMOTE_HOST);
	assert_equals(JALDB_E_INVAL, ret);
	context->manager = mgr;

	ret = jaldb_mark_synced_common(context, NULL, "12", REMOTE_HOST);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_mark_synced_common(context, cont, NULL, REMOTE_HOST);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_mark_synced_common(context, cont, "12", NULL);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_mark_sent_ok_common_overwrites_existing_data()
{
	XmlManager mgr = *(context->manager);
	XmlContainer cont = mgr.createContainer("update_sync_test");
	XmlDocument doc;
	XmlUpdateContext uc = mgr.createUpdateContext();

	string sent_id(JALDB_REMOTE_META_PREFIX REMOTE_HOST JALDB_SENT_META_SUFFIX);

	cont.putDocument("1", "<doc>1</doc>", uc);
	doc = cont.getDocument("1");
	doc.setMetaData(JALDB_NS, sent_id, false);
	cont.updateDocument(doc, uc);

	enum jaldb_status ret = jaldb_mark_sent_ok_common(context, &cont, "1", REMOTE_HOST);
	assert_equals(JALDB_OK, ret);

	XmlValue v;
	doc = cont.getDocument("1");
	assert_true(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_true(v.isBoolean());
}

extern "C" void test_jaldb_mark_sent_ok_common_creates_key_as_needed()
{
	XmlManager mgr = *(context->manager);
	XmlContainer cont = mgr.createContainer("update_sync_test");
	XmlDocument doc;
	XmlUpdateContext uc = mgr.createUpdateContext();

	string sent_id(JALDB_REMOTE_META_PREFIX REMOTE_HOST JALDB_SENT_META_SUFFIX);

	cont.putDocument("1", "<doc>1</doc>", uc);
	doc = cont.getDocument("1");
	cont.updateDocument(doc, uc);

	enum jaldb_status ret = jaldb_mark_sent_ok_common(context, &cont, "1", REMOTE_HOST);
	assert_equals(JALDB_OK, ret);

	XmlValue v;
	doc = cont.getDocument("1");
	assert_true(doc.getMetaData(JALDB_NS, sent_id, v));
	assert_true(v.isBoolean());
}

extern "C" void test_jaldb_mark_sent_ok_returns_not_found_when_document_lookup_fails()
{
	XmlManager mgr = *(context->manager);
	XmlContainer cont = mgr.createContainer("update_sync_test");
	XmlDocument doc;
	XmlUpdateContext uc = mgr.createUpdateContext();

	string sent_id(JALDB_REMOTE_META_PREFIX REMOTE_HOST JALDB_SENT_META_SUFFIX);

	cont.putDocument("1", "<doc>1</doc>", uc);
	doc = cont.getDocument("1");
	cont.updateDocument(doc, uc);

	enum jaldb_status ret = jaldb_mark_sent_ok_common(context, &cont, "2", REMOTE_HOST);
	assert_equals(JALDB_E_NOT_FOUND, ret);

	XmlValue v;
	doc = cont.getDocument("1");
	assert_false(doc.getMetaData(JALDB_NS, sent_id, v));
}

extern "C" void test_jaldb_mark_sent_ok_common_returns_error_on_bad_input()
{
	enum jaldb_status ret;
	XmlContainer *cont = (XmlContainer*) 0xbadf00d;

	ret = jaldb_mark_sent_ok_common(NULL, cont, "12", REMOTE_HOST);
	assert_equals(JALDB_E_INVAL, ret);

	XmlManager *mgr = context->manager;
	context->manager = NULL;
	ret = jaldb_mark_sent_ok_common(context, cont, "12", REMOTE_HOST);
	assert_equals(JALDB_E_INVAL, ret);
	context->manager = mgr;

	ret = jaldb_mark_sent_ok_common(context, NULL, "12", REMOTE_HOST);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_mark_sent_ok_common(context, cont, NULL, REMOTE_HOST);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_mark_sent_ok_common(context, cont, "12", NULL);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_delete_log_works()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	DB *log_db = context->log_dbp;
	uint8_t *log_buf = (uint8_t *) strdup(LOG_DATA_X);
	std::string sid_out = "test_delete_log_works";
	int db_err_out;
	jaldb_status ret;
	XmlValue true_val(true);

	// Insert a dummy log record
	XmlTransaction txn = context->manager->createTransaction();
	XmlDocument sys_doc = context->manager->createDocument();
	XmlDocument app_doc = context->manager->createDocument();
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, true_val);
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_LOG, true_val);
	sys_doc.setName(sid_out);
	app_doc.setName(sid_out);
	DBT key;
	DBT data;
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));
	key.data = jal_strdup(sid_out.c_str());
	key.size = sid_out.length();
	//key.flags = 0;
	data.data = log_buf;
	data.size = strlen((char *)log_buf);

	try {
		sys_cont->putDocument(txn, sys_doc, uc);
		app_cont->putDocument(txn, app_doc, uc);
		int db_ret = log_db->put(log_db,
			txn.getDB_TXN(), &key, &data,
			0);
		if (0 != db_ret ) {
			ret = JALDB_E_DB;
			txn.abort();
		} else {
			ret = JALDB_OK;
			txn.commit();
		}
	} catch (XmlException &e){
		txn.abort();
		if (e.getExceptionCode()
			== XmlException::DOCUMENT_NOT_FOUND) {
			ret = JALDB_E_NOT_FOUND;
		}
		else {
			ret = JALDB_E_INVAL;
		}
	}
	free(key.data);
	assert_equals(JALDB_OK, ret);

	// Retrieve sys_doc, app_doc and log
	XmlTransaction txn2 = context->manager->createTransaction();
	XmlDocument sys_doc1;
	XmlDocument app_doc1;
	DBT key1;
	DBT data1;
	key1.data = jal_strdup(sid_out.c_str());
	key1.size = sid_out.length();
	key1.flags = 0;
	data1.flags = DB_DBT_MALLOC;
	try {
		sys_doc1 = sys_cont->getDocument(txn2, sid_out, 0);
		app_doc1 = app_cont->getDocument(txn2, sid_out, 0);
		int db_ret = log_db->get(log_db,
			txn2.getDB_TXN(), &key1, &data1,
			DB_READ_COMMITTED);
		if (0 != db_ret ) {
			ret = JALDB_E_DB;
			txn2.abort();
		} else {
			ret = JALDB_OK;
			txn2.commit();
		}
	} catch (XmlException &e){
		txn2.abort();
		if (e.getExceptionCode()
			== XmlException::DOCUMENT_NOT_FOUND) {
			ret = JALDB_E_NOT_FOUND;
		}
		else {
			ret = JALDB_E_INVAL;
		}
	}
	free(key1.data);
	assert_equals(JALDB_OK, ret);

	// Call delete using sid_out
	XmlTransaction txn3 = context->manager->createTransaction();
	ret = jaldb_delete_log(txn3, uc, *sys_cont, *app_cont,
		log_db, sid_out, &sys_doc, &app_doc, &db_err_out);
	assert_equals(JALDB_OK, ret);
	txn3.commit();

	// Verify sys_doc was deleted
	XmlTransaction txn4 = context->manager->createTransaction();
	XmlDocument sys_doc2;
	XmlDocument app_doc2;
	try {
		sys_doc2 = sys_cont->getDocument(txn4, sid_out, 0);
		txn4.commit();
		ret = JALDB_E_INVAL;
	} catch (XmlException &e){
		txn4.abort();
		if (e.getExceptionCode()
			== XmlException::DOCUMENT_NOT_FOUND) {
			ret = JALDB_OK;
		}
		else {
			ret = JALDB_E_INVAL;
		}
	}
	assert_equals(JALDB_OK, ret);

	// Verify app_doc was deleted
	XmlTransaction txn5 = context->manager->createTransaction();
	try {
		app_doc2 = app_cont->getDocument(txn5, sid_out, 0);
		txn5.commit();
		ret = JALDB_E_INVAL;
	} catch (XmlException &e){
		txn5.abort();
		if (e.getExceptionCode()
			== XmlException::DOCUMENT_NOT_FOUND) {
			ret = JALDB_OK;
		}
		else {
			ret = JALDB_E_INVAL;
		}
	}
	assert_equals(JALDB_OK, ret);

	// Verify LOG was deleted
	XmlTransaction txn6 = context->manager->createTransaction();
	DBT key2;
	DBT data2;
	memset(&key2, 0, sizeof(DBT));
	memset(&data2, 0, sizeof(DBT));
	key2.data = jal_strdup(sid_out.c_str());
	key2.size = sid_out.length();
	data2.flags = DB_DBT_MALLOC;
	int db_ret = log_db->get(log_db,
		txn6.getDB_TXN(), &key2, &data2,
		DB_READ_COMMITTED);
	if (0 != db_ret ) {
		ret = JALDB_E_DB;
		txn6.abort();
	} else {
		ret = JALDB_OK;
		txn6.commit();
	}
	free(key2.data);
	assert_equals(JALDB_E_DB, ret);
	free(log_buf);
}

extern "C" void test_jaldb_delete_log_fails_bad_input()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc = context->manager->createDocument();
	XmlDocument app_doc = context->manager->createDocument();
	uint8_t *log_buf = (uint8_t *) strdup(LOG_DATA_X);
	std::string sid_out = "some_sid";
	std::string empty_sid = "";
	int db_err_out;
	jaldb_status ret;

	XmlTransaction txn = context->manager->createTransaction();
	ret = jaldb_delete_log(txn, uc, *sys_cont, *app_cont,
		NULL, sid_out, &sys_doc, &app_doc,
		&db_err_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_delete_log(txn, uc, *sys_cont, *app_cont,
		context->log_dbp, sid_out, NULL, &app_doc,
		&db_err_out);
	assert_equals(JALDB_E_INVAL, ret);

	// No need to test if app_doc is NULL as jaldb_delete_log
	//	checks if the sys_doc's HAS_APP_META flag is true.

	ret = jaldb_delete_log(txn, uc, *sys_cont, *app_cont,
		context->log_dbp, sid_out, &sys_doc, &app_doc,
		NULL);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_delete_log(txn, uc, *sys_cont, *app_cont,
		context->log_dbp, empty_sid, &sys_doc, &app_doc,
		&db_err_out);
	assert_equals(JALDB_E_INVAL, ret);

	free(log_buf);
}

extern "C" void test_jaldb_delete_log_fails_corrupted()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc = context->manager->createDocument();
	XmlDocument app_doc = context->manager->createDocument();
	std::string sid_out = "some_sid";
	int db_err_out;
	jaldb_status ret;
	XmlValue false_val(false);
	XmlValue true_val(true);
	XmlValue val;

	assert_false(sys_doc.getMetaData(JALDB_NS,
		JALDB_HAS_APP_META, val));
	assert_false(sys_doc.getMetaData(JALDB_NS,
		JALDB_HAS_LOG, val));

	// No HAS_APP_META and HAS_LOG
	ret = jaldb_delete_log(txn, uc, *sys_cont, *app_cont,
		context->log_dbp, sid_out, &sys_doc, &app_doc,
		&db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);

	// HAS_APP_META exists but true, No HAS_LOG
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, true_val);
	ret = jaldb_delete_log(txn, uc, *sys_cont, *app_cont,
		context->log_dbp, sid_out, &sys_doc, &app_doc,
		&db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);

	// HAS_APP_META exists but false, No HAS_LOG
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, false_val);
	ret = jaldb_delete_log(txn, uc, *sys_cont, *app_cont,
		context->log_dbp, sid_out, &sys_doc, &app_doc,
		&db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);

	// Set HAS_APP_META and HAS_LOG to FALSE
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, false_val);
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_LOG, false_val);
	ret = jaldb_delete_log(txn, uc, *sys_cont, *app_cont,
		context->log_dbp, sid_out, &sys_doc, &app_doc,
		&db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);
}

extern "C" void test_jaldb_delete_log_fails_doc_not_found()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc = context->manager->createDocument();
	XmlDocument app_doc = context->manager->createDocument();
	std::string sid = "some_sid_not_there";
	std::string doc_name ="added_doc";
	int db_err_out;
	jaldb_status ret;
	XmlValue true_val(true);

	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, true_val);
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_LOG, true_val);

	// Call delete using sid
	ret = jaldb_delete_log(txn, uc, *sys_cont, *app_cont,
		context->log_dbp, sid, &sys_doc, &app_doc,
		&db_err_out);
	assert_equals(JALDB_E_NOT_FOUND, ret);

	// Insert sys_doc
	sys_doc.setName(doc_name);
	sys_cont->putDocument(txn, sys_doc, uc);
	txn.commit();

	XmlTransaction txn2 = context->manager->createTransaction();
	// Call delete, passes for sys_doc should fail for app_doc
	ret = jaldb_delete_log(txn2, uc, *sys_cont, *app_cont,
		context->log_dbp, doc_name, &sys_doc, &app_doc,
		&db_err_out);
	assert_equals(JALDB_E_NOT_FOUND, ret);
}

extern "C" void test_jaldb_delete_log_fails_log_not_found()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc = context->manager->createDocument();
	XmlDocument app_doc = context->manager->createDocument();
	std::string doc_name ="added_doc";
	int db_err_out;
	jaldb_status ret;
	XmlValue true_val(true);

	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, true_val);
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_LOG, true_val);

	// Insert sys_doc and app_doc
	sys_doc.setName(doc_name);
	app_doc.setName(doc_name);
	sys_cont->putDocument(txn, sys_doc, uc);
	app_cont->putDocument(txn, app_doc, uc);
	txn.commit();

	XmlTransaction txn2 = context->manager->createTransaction();
	// Call delete, passes for sys_doc and app_doc
	//	should fail for log
	ret = jaldb_delete_log(txn2, uc, *sys_cont, *app_cont,
		context->log_dbp, doc_name, &sys_doc, &app_doc,
		&db_err_out);
	assert_equals(JALDB_E_DB, ret);
}

extern "C" void test_jaldb_save_log_works()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc = context->manager->createDocument();
	XmlDocument app_doc = context->manager->createDocument();
	DB *log_db = context->log_dbp;
	uint8_t *log_buf = (uint8_t *) strdup(LOG_DATA_X);
	size_t log_len = strlen((char *)log_buf);
	std::string doc_name ="test_save_log_works";
	int db_err_out;
	jaldb_status ret;
	XmlValue true_val(true);

	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, true_val);
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_LOG, true_val);
	sys_doc.setName(doc_name);
	app_doc.setName(doc_name);

	ret = jaldb_save_log(txn, uc, *sys_cont, *app_cont,
		log_db, doc_name, &sys_doc, &app_doc,
		log_buf, log_len, &db_err_out);
	assert_equals(JALDB_OK, ret);
	txn.commit();

	XmlTransaction txn2 = context->manager->createTransaction();
	XmlDocument sys_doc2;
	XmlDocument app_doc2;
	DBT key2;
	DBT data2;
	memset(&key2, 0, sizeof(DBT));
	memset(&data2, 0, sizeof(DBT));
	key2.data = jal_strdup(doc_name.c_str());
	key2.size = doc_name.length();
	data2.flags = DB_DBT_MALLOC;
	try {
		sys_doc2 = sys_cont->getDocument(txn2, doc_name, 0);
		app_doc2 = app_cont->getDocument(txn2, doc_name, 0);

		int db_ret = log_db->get(log_db,
			txn2.getDB_TXN(), &key2, &data2,
			DB_READ_COMMITTED);
		if (0 != db_ret ) {
			ret = JALDB_E_DB;
			txn2.abort();
		} else {
			ret = JALDB_OK;
			txn2.commit();
		}
		ret = JALDB_OK;
	} catch (XmlException &e){
		txn2.abort();
		if (e.getExceptionCode()
			== XmlException::DOCUMENT_NOT_FOUND) {
			ret = JALDB_E_INVAL;
		}
		else {
			ret = JALDB_E_INVAL;
		}
	}
	free(key2.data);
	assert_equals(JALDB_OK, ret);
	assert_equals(sys_doc, sys_doc2);
	assert_equals(app_doc, app_doc2);
	size_t len1 = strlen((char *)log_buf);
	size_t len2 = data2.size;
	assert_equals(len1, len2);
	assert_equals(0, memcmp((char *)log_buf,
				(char *)data2.data, len1));
	free(log_buf);
}

extern "C" void test_jaldb_save_log_fails_bad_input()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc = context->manager->createDocument();
	XmlDocument app_doc = context->manager->createDocument();
	DB *log_db = context->log_dbp;
	uint8_t *log_buf = (uint8_t *) strdup(LOG_DATA_X);
	size_t log_len = strlen((char *)log_buf);
	std::string doc_name ="";
	int db_err_out;
	jaldb_status ret;

	// sid length = 0
	ret = jaldb_save_log(txn, uc, *sys_cont, *app_cont,
			     log_db, doc_name, &sys_doc, &app_doc,
			     log_buf, log_len, &db_err_out);
	assert_equals(JALDB_E_INVAL, ret);

	doc_name = "some_sid";

	// log_db is NULL
	ret = jaldb_save_log(txn, uc, *sys_cont, *app_cont,
			     NULL, doc_name, &sys_doc, &app_doc,
			     log_buf, log_len, &db_err_out);
	assert_equals(JALDB_E_INVAL, ret);

	// db_err_out is NULL
	ret = jaldb_save_log(txn, uc, *sys_cont, *app_cont,
			     log_db, doc_name, &sys_doc, &app_doc,
			     log_buf, log_len, NULL);
	assert_equals(JALDB_E_INVAL, ret);

	// sys_doc is NULL
	ret = jaldb_save_log(txn, uc, *sys_cont, *app_cont,
			     log_db, doc_name, NULL, &app_doc,
			     log_buf, log_len, &db_err_out);
	assert_equals(JALDB_E_INVAL, ret);

	// No need to test app_doc is NULL as save_log looks at
	//	the application meta of sys_doc to determine if
	//	the app_doc should even be used.

	// No need to test log_buf is NULL as save_log looks at
	//	the application meta of sys_doc to determine if
	//	the log data should even be used.
	free(log_buf);
}

extern "C" void test_jaldb_save_log_fails_corrupted()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc = context->manager->createDocument();
	XmlDocument app_doc = context->manager->createDocument();
	std::string doc_name = "some_sid";;
	DB *log_db = context->log_dbp;
	uint8_t *log_buf = (uint8_t *) strdup(LOG_DATA_X);
	size_t log_len = strlen((char *)log_buf);
	int db_err_out;
	jaldb_status ret;
	XmlValue false_val(false);
	XmlValue true_val(true);
	XmlValue val;

	assert_false(sys_doc.getMetaData(JALDB_NS,
		JALDB_HAS_APP_META, val));
	assert_false(sys_doc.getMetaData(JALDB_NS,
		JALDB_HAS_LOG, val));

	// No HAS_APP_META and HAS_LOG
	ret = jaldb_save_log(txn, uc, *sys_cont, *app_cont,
			     log_db, doc_name, &sys_doc, &app_doc,
			     log_buf, log_len, &db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);

	// HAS_APP_META exists but true, No HAS_LOG
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, true_val);
	ret = jaldb_save_log(txn, uc, *sys_cont, *app_cont,
			     log_db, doc_name, &sys_doc, &app_doc,
			     log_buf, log_len, &db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);

	// HAS_APP_META exists but false, No HAS_LOG
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, false_val);
	ret = jaldb_save_log(txn, uc, *sys_cont, *app_cont,
			     log_db, doc_name, &sys_doc, &app_doc,
			     log_buf, log_len, &db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);

	// Set HAS_APP_META and HAS_LOG to FALSE
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_APP_META, false_val);
	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_LOG, false_val);
	ret = jaldb_save_log(txn, uc, *sys_cont, *app_cont,
			     log_db, doc_name, &sys_doc, &app_doc,
			     log_buf, log_len, &db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);
	free(log_buf);
}

extern "C" void test_jaldb_save_log_fails_internal()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc = context->manager->createDocument();
	XmlDocument app_doc = context->manager->createDocument();
	std::string doc_name1 = "test_duplicate_sys_doc";
	std::string doc_name2 = "test_duplicate_app_doc";
	std::string doc_name3 = "test_duplicate_log";
	DB *log_db = context->log_dbp;
	DBT key;
	DBT data;
	int db_err_out;
	jaldb_status ret;
	XmlValue false_val(false);
	XmlValue true_val(true);
	uint8_t *log_buf = (uint8_t *) strdup(LOG_DATA_X);
	size_t log_len = strlen((char *)log_buf);

	sys_doc.setMetaData(JALDB_NS, JALDB_HAS_LOG, true_val);
	sys_doc.setMetaData(JALDB_NS,JALDB_HAS_APP_META, false_val);
	memset(&key, 0, sizeof(DBT));
	memset(&data, 0, sizeof(DBT));
	key.data = jal_strdup(doc_name3.c_str());
	key.size = doc_name3.length();
	key.flags = 0;
	data.data = log_buf;
	data.size = strlen((char *)log_buf);

	// Force internal failure by inserting records initially
	try {
		sys_doc.setName(doc_name1);
		app_doc.setName(doc_name2);
		sys_cont->putDocument(txn, sys_doc, uc);
		app_cont->putDocument(txn, app_doc, uc);
		int db_ret = log_db->put(log_db,
			txn.getDB_TXN(), &key, &data,
			0);
		if (0 != db_ret ) {
			ret = JALDB_E_DB;
			txn.abort();
		} else {
			ret = JALDB_OK;
			txn.commit();
		}
	} catch (XmlException &e) {
		txn.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	free(key.data);
	assert_equals(JALDB_OK, ret);

	// Fails on sys_doc already exists
	XmlTransaction txn2 = context->manager->createTransaction();
	XmlDocument sys_doc2 = context->manager->createDocument();
	sys_doc2.setMetaData(JALDB_NS, JALDB_HAS_LOG, true_val);
	sys_doc2.setMetaData(JALDB_NS, JALDB_HAS_APP_META, false_val);
	ret = jaldb_save_log(txn2, uc, *sys_cont, *app_cont,
			     log_db, doc_name1, &sys_doc2, &app_doc,
			     log_buf, log_len, &db_err_out);
	assert_equals(JALDB_E_SID, ret);

	// Fails on app_doc already exists
	XmlDocument app_doc2 = context->manager->createDocument();
	sys_doc2.setMetaData(JALDB_NS, JALDB_HAS_APP_META, true_val);
	ret = jaldb_save_log(txn2, uc, *sys_cont, *app_cont,
			     log_db, doc_name2, &sys_doc2, &app_doc2,
			     log_buf, log_len, &db_err_out);
	assert_equals(JALDB_E_SID, ret);

	// Fails on log already exists
	ret = jaldb_save_log(txn2, uc, *sys_cont, *app_cont,
			     log_db, doc_name3, &sys_doc2, &app_doc2,
			     log_buf, log_len, &db_err_out);
	assert_equals(JALDB_E_DB, ret);
	free(log_buf);
}

extern "C" void test_jaldb_retrieve_log_works()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc1 = context->manager->createDocument();
	XmlDocument app_doc1 = context->manager->createDocument();
	std::string doc_name = "test_duplicate_sys_doc";
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *log_buf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	DB *log_db = context->log_dbp;
	DBT key1;
	DBT data1;
	int db_err_out;
	jaldb_status ret;
	XmlValue false_val(false);
	XmlValue true_val(true);

	sys_doc1.setMetaData(JALDB_NS, JALDB_HAS_LOG, true_val);
	sys_doc1.setMetaData(JALDB_NS,JALDB_HAS_APP_META, true_val);
	memset(&key1, 0, sizeof(DBT));
	memset(&data1, 0, sizeof(DBT));
	key1.data = jal_strdup(doc_name.c_str());
	key1.size = doc_name.length();
	data1.data = log_buf;
	data1.size = loglen;

	// Insert sys_doc, app_doc and log
	try {
		sys_doc1.setName(doc_name);
		app_doc1.setName(doc_name);
		sys_cont->putDocument(txn, sys_doc1, uc);
		app_cont->putDocument(txn, app_doc1, uc);
		int db_ret = log_db->put(log_db,
			txn.getDB_TXN(), &key1, &data1,
			DB_NOOVERWRITE);
		if (0 != db_ret ) {
			ret = JALDB_E_DB;
			txn.abort();
		} else {
			ret = JALDB_OK;
			txn.commit();
		}
	} catch (XmlException &e) {
		txn.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	free(key1.data);
	assert_equals(JALDB_OK, ret);

	XmlTransaction txn2 = context->manager->createTransaction();
	XmlDocument sys_doc2;
	XmlDocument app_doc2;
	uint8_t *log_buf2 = NULL;
	size_t log_len2;
	ret = jaldb_retrieve_log(txn2, uc, *sys_cont, *app_cont,
				 log_db, doc_name, &sys_doc2,
				 &app_doc2, &log_buf2, &log_len2,
				 &db_err_out);
	assert_equals(JALDB_OK, ret);
	assert_equals(sys_doc1, sys_doc2);
	assert_equals(app_doc1, app_doc2);
	assert_equals(data1.size,
		      log_len2);
	assert_equals(0, memcmp((char *)data1.data,
				(char *)log_buf2,
				data1.size));
	free(log_buf2);
}

extern "C" void test_jaldb_retrieve_log_fails_bad_input()
{
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc1 = context->manager->createDocument();
	XmlDocument app_doc1 = context->manager->createDocument();
	std::string doc_name = "some_sid";
	std::string empty_sid = "";
	DB *log_db = context->log_dbp;
	int db_err_out;
	jaldb_status ret;
	uint8_t *log_buf = NULL;
	size_t log_len;

	ret = jaldb_retrieve_log(txn, uc, *sys_cont, *app_cont,
				 NULL, doc_name, &sys_doc1,
				 &app_doc1, &log_buf, &log_len,
				 &db_err_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_retrieve_log(txn, uc, *sys_cont, *app_cont,
				 log_db, doc_name, NULL,
				 &app_doc1, &log_buf, &log_len,
				 &db_err_out);
	assert_equals(JALDB_E_INVAL, ret);

	// Don't need to check app_doc as its existence
	//	is checked w/in the function using sys_doc's
	//	metadata

	ret = jaldb_retrieve_log(txn, uc, *sys_cont, *app_cont,
				 log_db, doc_name, &sys_doc1,
				 &app_doc1, NULL, &log_len,
				 &db_err_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_retrieve_log(txn, uc, *sys_cont, *app_cont,
				 log_db, doc_name, &sys_doc1,
				 &app_doc1, &log_buf, NULL,
				 &db_err_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_retrieve_log(txn, uc, *sys_cont, *app_cont,
				 log_db, doc_name, &sys_doc1,
				 &app_doc1, &log_buf, &log_len,
				 NULL);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_retrieve_log(txn, uc, *sys_cont, *app_cont,
				 log_db, empty_sid, &sys_doc1,
				 &app_doc1, &log_buf, &log_len,
				 &db_err_out);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_retrieve_log_fails_internal()
{
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument app_doc1;
	std::string doc_name = "test_retrieve_log_fails_internal";
	DB *log_db = context->log_dbp;
	int db_err_out;
	jaldb_status ret;
	XmlValue false_val(false);
	XmlValue true_val(true);
	uint8_t *log_buf = NULL;
	size_t log_len;

	// sys_doc does not exist in DB
	XmlDocument sys_doc_out1;
	ret = jaldb_retrieve_log(txn, uc, *sys_cont, *app_cont,
				 log_db, doc_name, &sys_doc_out1,
				 &app_doc1, &log_buf, &log_len,
				 &db_err_out);
	assert_equals(JALDB_E_NOT_FOUND, ret);

	// sys_doc exists, missing HAS_APP_META
	XmlDocument sys_doc_in1 = context->manager->createDocument();
	sys_doc_in1.setName(doc_name);
	sys_cont->putDocument(txn, sys_doc_in1, uc);
	txn.commit();

	XmlTransaction txn2 = context->manager->createTransaction();
	ret = jaldb_retrieve_log(txn2, uc, *sys_cont, *app_cont,
				 log_db, doc_name, &sys_doc_out1,
				 &app_doc1, &log_buf, &log_len,
				 &db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);

	// sys_doc exists, has HAS_APP_META, missing HAS_LOG
	std::string doc_name2 = "test_retrieve_log_fails_internal2";
	XmlDocument sys_doc_out2;
	XmlDocument sys_doc_in2 = context->manager->createDocument();
	sys_doc_in2.setName(doc_name2);
	sys_doc_in2.setMetaData(JALDB_NS,
			     JALDB_HAS_APP_META, true_val);
	sys_cont->putDocument(txn2, sys_doc_in2, uc);
	txn2.commit();

	XmlTransaction txn3 = context->manager->createTransaction();
	ret = jaldb_retrieve_log(txn3, uc, *sys_cont, *app_cont,
				 log_db, doc_name2, &sys_doc_out2,
				 &app_doc1, &log_buf, &log_len,
				 &db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);

	// sys_doc exists, has HAS_APP_META =false, has HAS_LOG = false
	std::string doc_name3 = "test_retrieve_log_fails_internal3";
	XmlDocument sys_doc_out3;
	XmlDocument sys_doc_in3 = context->manager->createDocument();
	sys_doc_in3.setName(doc_name3);
	sys_doc_in3.setMetaData(JALDB_NS,
			     JALDB_HAS_APP_META, false_val);
	sys_doc_in3.setMetaData(JALDB_NS,
			     JALDB_HAS_LOG, false_val);
	sys_cont->putDocument(txn3, sys_doc_in3, uc);
	txn3.commit();

	XmlTransaction txn4 = context->manager->createTransaction();
	ret = jaldb_retrieve_log(txn4, uc, *sys_cont, *app_cont,
				 log_db, doc_name3, &sys_doc_out3,
				 &app_doc1, &log_buf, &log_len,
				 &db_err_out);
	assert_equals(JALDB_E_CORRUPTED, ret);

	// HAS_APP_META=TRUE, but app_doc does not exist
	std::string doc_name4 = "test_retrieve_log_fails_internal4";
	XmlDocument sys_doc_out4;
	XmlDocument sys_doc_in4 = context->manager->createDocument();
	sys_doc_in4.setName(doc_name4);
	sys_doc_in4.setMetaData(JALDB_NS,
			     JALDB_HAS_APP_META, true_val);
	sys_doc_in4.setMetaData(JALDB_NS,
			     JALDB_HAS_LOG, false_val);
	sys_cont->putDocument(txn4, sys_doc_in4, uc);
	txn4.commit();

	XmlTransaction txn5 = context->manager->createTransaction();
	ret = jaldb_retrieve_log(txn5, uc, *sys_cont, *app_cont,
				 log_db, doc_name4, &sys_doc_out4,
				 &app_doc1, &log_buf, &log_len,
				 &db_err_out);
	assert_equals(JALDB_E_NOT_FOUND, ret);

	// HAS_APP_META=FALSE, HAS_LOG=TRUE but log does not exist
	std::string doc_name5 = "test_retrieve_log_fails_internal5";
	XmlDocument sys_doc_out5;
	XmlDocument sys_doc_in5 = context->manager->createDocument();
	sys_doc_in5.setName(doc_name5);
	sys_doc_in5.setMetaData(JALDB_NS,
			     JALDB_HAS_APP_META, false_val);
	sys_doc_in5.setMetaData(JALDB_NS,
			     JALDB_HAS_LOG, true_val);
	sys_cont->putDocument(txn5, sys_doc_in5, uc);
	txn5.commit();

	XmlTransaction txn6 = context->manager->createTransaction();
	ret = jaldb_retrieve_log(txn6, uc, *sys_cont, *app_cont,
				 log_db, doc_name5, &sys_doc_out5,
				 &app_doc1, &log_buf, &log_len,
				 &db_err_out);
	assert_equals(JALDB_E_DB, ret);
}

extern "C" void test_jaldb_xfer_log_works()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlContainer *sys_cont = context->log_sys_cont;
	XmlContainer *app_cont = context->log_app_cont;
	XmlDocument sys_doc1 = context->manager->createDocument();
	XmlDocument app_doc1 = context->manager->createDocument();
	std::string doc_name = "test_xfer_log_works";
	const char *log_buffer_x = LOG_DATA_X;
	uint8_t *log_buf = (uint8_t *)log_buffer_x;
	size_t loglen = strlen(log_buffer_x);
	DB *log_db = context->log_dbp;
	DBT key1;
	DBT data1;
	jaldb_status ret;
	XmlValue false_val(false);
	XmlValue true_val(true);
	string sys_db_name = jaldb_make_temp_db_name(src,
		JALDB_LOG_SYS_META_CONT_NAME);
	string app_db_name = jaldb_make_temp_db_name(src,
		JALDB_LOG_APP_META_CONT_NAME);
	string log_db_name = jaldb_make_temp_db_name(src,
		JALDB_LOG_DB_NAME);

	XmlContainer tmp_sys_cont;
	XmlContainer tmp_app_cont;
	DB *tmp_log_db = NULL;
	int db_err = 0;

	ret = jaldb_open_temp_container(context, sys_db_name, tmp_sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, app_db_name, tmp_app_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_db(context, log_db_name, &tmp_log_db, &db_err);
	assert_equals(JALDB_OK, ret);

	sys_doc1.setName(doc_name);
	app_doc1.setName(doc_name);
	sys_doc1.setMetaData(JALDB_NS, JALDB_HAS_LOG, true_val);
	sys_doc1.setMetaData(JALDB_NS,JALDB_HAS_APP_META, true_val);
	memset(&key1, 0, sizeof(DBT));
	memset(&data1, 0, sizeof(DBT));
	key1.data = jal_strdup(doc_name.c_str());
	key1.size = doc_name.length();
	data1.data = log_buf;
	data1.size = loglen;

	std::string sys_doc_cont;
	std::string app_doc_cont;

	// Insert sys_doc, app_doc and log into tmp
	try {
		sys_doc1.getContent(sys_doc_cont);
		app_doc1.getContent(app_doc_cont);
		tmp_sys_cont.putDocument(txn, sys_doc1, uc);
		tmp_app_cont.putDocument(txn, app_doc1, uc);
		int db_ret = tmp_log_db->put(tmp_log_db,
			txn.getDB_TXN(), &key1, &data1,
			DB_NOOVERWRITE);
		if (0 != db_ret ) {
			ret = JALDB_E_DB;
			txn.abort();
		} else {
			ret = JALDB_OK;
			txn.commit();
		}
	} catch (XmlException &e) {
		txn.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	free(key1.data);
	assert_equals(JALDB_OK, ret);

	std::string sid_out;
	ret = jaldb_xfer_log(context, src, doc_name, sid_out);
	assert_equals(JALDB_OK, ret);
	assert_true(0 < sid_out.length());

	std::string sys_doc_cont2;
	std::string app_doc_cont2;

	// Retrieve sys_doc, app_doc and log from perm
	XmlTransaction txn2 = context->manager->createTransaction();
	XmlDocument sys_doc2;
	XmlDocument app_doc2;
	DBT key2;
	DBT data2;
	memset(&key2, 0, sizeof(DBT));
	memset(&data2, 0, sizeof(DBT));
	key2.data = jal_strdup(sid_out.c_str());
	key2.size = sid_out.length();
	data2.flags = DB_DBT_MALLOC;
	try {
		sys_doc2 = sys_cont->getDocument(txn2, sid_out, 0);
		app_doc2 = app_cont->getDocument(txn2, sid_out, 0);
		sys_doc2.getContent(sys_doc_cont2);
		app_doc2.getContent(app_doc_cont2);

		int db_ret = log_db->get(log_db,
			txn2.getDB_TXN(), &key2, &data2,
			DB_READ_COMMITTED);
		if (0 != db_ret ) {
			ret = JALDB_E_DB;
			txn2.abort();
		} else {
			ret = JALDB_OK;
			txn2.commit();
		}
		ret = JALDB_OK;
	} catch (XmlException &e){
		txn2.abort();
		if (e.getExceptionCode()
			== XmlException::DOCUMENT_NOT_FOUND) {
			ret = JALDB_E_INVAL;
		}
		else {
			ret = JALDB_E_INVAL;
		}
	}
	free(key2.data);
	assert_equals(JALDB_OK, ret);
	assert_equals(sys_doc_cont, sys_doc_cont2);
	assert_equals(app_doc_cont, app_doc_cont2);
	assert_equals(data1.size, data2.size);
	assert_equals(0, memcmp((char *) data1.data,
				(char *) data2.data, data1.size));

	// Retrieve sys_doc, app_doc and log from temp
	//	Verification that the files were deleted.
	XmlTransaction txn3 = context->manager->createTransaction();
	XmlDocument sys_doc3;
	XmlDocument app_doc3;
	DBT key3;
	DBT data3;
	memset(&key3, 0, sizeof(DBT));
	memset(&data3, 0, sizeof(DBT));
	key3.data = jal_strdup(doc_name.c_str());
	key3.size = doc_name.length();
	data3.flags = DB_DBT_MALLOC;
	try {
		sys_doc3 = tmp_sys_cont.getDocument(txn3, doc_name, 0);
		app_doc3 = tmp_app_cont.getDocument(txn3, doc_name, 0);

		int db_ret = tmp_log_db->get(tmp_log_db,
			txn3.getDB_TXN(), &key3, &data3,
			DB_READ_COMMITTED);
		if (0 != db_ret ) {
			ret = JALDB_E_DB;
			txn3.abort();
		} else {
			ret = JALDB_OK;
			txn3.commit();
		}
		ret = JALDB_OK;
	} catch (XmlException &e){
		txn3.abort();
		if (e.getExceptionCode()
			== XmlException::DOCUMENT_NOT_FOUND) {
			ret = JALDB_E_INVAL;
		}
		else {
			ret = JALDB_E_INVAL;
		}
	}
	free(key3.data);
	assert_not_equals(JALDB_OK, ret);
}

extern "C" void test_jaldb_xfer_log_fails_bad_input()
{
	std::string src = REMOTE_HOST;
	std::string empty_src = "";
	std::string doc_name = "test_xfer_log_fails_bad_input";
	std::string sid_out;
	jaldb_status ret;

	XmlManager *mgr = context->manager;
	int db_read_only = context->db_read_only;

	ret = jaldb_xfer_log(NULL, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	context->manager = NULL;
	ret = jaldb_xfer_log(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	context->manager = mgr;
	mgr = NULL;
	ret = jaldb_xfer_log(context, empty_src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	context->db_read_only = 1;
	ret = jaldb_xfer_log(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_READ_ONLY, ret);
	context->db_read_only = db_read_only;
}

extern "C" void test_jaldb_xfer_audit_works()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn1 = context->manager->createTransaction();
	XmlContainer *sys_cont = context->audit_sys_cont;
	XmlContainer *app_cont = context->audit_app_cont;
	XmlContainer *audit_cont = context->audit_cont;
	std::string doc_name1 = "test_xfer_audit_works1";
	jaldb_status ret;
	XmlValue false_val(false);
	XmlValue true_val(true);
	string sys_db_name = jaldb_make_temp_db_name(src,
		JALDB_AUDIT_SYS_META_CONT_NAME);
	string app_db_name = jaldb_make_temp_db_name(src,
		JALDB_AUDIT_APP_META_CONT_NAME);
	string audit_db_name = jaldb_make_temp_db_name(src,
		JALDB_AUDIT_CONT_NAME);

	XmlContainer tmp_sys_cont;
	XmlContainer tmp_app_cont;
	XmlContainer tmp_audit_cont;

	ret = jaldb_open_temp_container(context, sys_db_name,
			tmp_sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, app_db_name,
			tmp_app_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, audit_db_name,
			tmp_audit_cont);
	assert_equals(JALDB_OK, ret);

	std::string sys_doc_cont1;
	std::string app_doc_cont1;
	std::string audit_doc_cont1;
	XmlDocument sys_doc1 = context->manager->createDocument();
	XmlDocument app_doc1 = context->manager->createDocument();
	XmlDocument audit_doc1 = context->manager->createDocument();
	sys_doc1.setName(doc_name1);
	app_doc1.setName(doc_name1);
	audit_doc1.setName(doc_name1);
	sys_doc1.setMetaData(JALDB_NS, JALDB_HAS_APP_META, true_val);

	// Insert sys_doc, app_doc and audit_doc into tmp
	try {
		sys_doc1.getContent(sys_doc_cont1);
		app_doc1.getContent(app_doc_cont1);
		audit_doc1.getContent(audit_doc_cont1);
		tmp_sys_cont.putDocument(txn1, sys_doc1, uc);
		tmp_app_cont.putDocument(txn1, app_doc1, uc);
		tmp_audit_cont.putDocument(txn1, audit_doc1, uc);
		txn1.commit();
		ret = JALDB_OK;
	} catch (XmlException &e) {
		txn1.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);

	std::string sid_out1;
	ret = jaldb_xfer_audit(context, src, doc_name1, sid_out1);
	assert_equals(JALDB_OK, ret);

	XmlTransaction txn2 = context->manager->createTransaction();
	std::string sys_doc_cont_out1;
	std::string app_doc_cont_out1;
	std::string audit_doc_cont_out1;
	XmlDocument sys_doc_out1;
	XmlDocument app_doc_out1;
	XmlDocument audit_doc_out1;

	// Verify sys_doc, app_doc and audit_doc exist in perm
	try {
		sys_doc_out1 = sys_cont->getDocument(txn2, sid_out1, 0);
		app_doc_out1 = app_cont->getDocument(txn2, sid_out1, 0);
		audit_doc_out1 = audit_cont->getDocument(txn2,
					sid_out1, 0);
		sys_doc_out1.getContent(sys_doc_cont_out1);
		app_doc_out1.getContent(app_doc_cont_out1);
		audit_doc_out1.getContent(audit_doc_cont_out1);
		txn2.commit();
		ret = JALDB_OK;
	} catch (XmlException &e) {
		txn2.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);
	assert_equals(sys_doc_cont1, sys_doc_cont_out1);
	assert_equals(app_doc_cont1, app_doc_cont_out1);
	assert_equals(audit_doc_cont1, audit_doc_cont_out1);

	XmlTransaction txn3 = context->manager->createTransaction();
	XmlDocument sys_doc_out2;
	XmlDocument app_doc_out2;
	XmlDocument audit_doc_out2;

	// Verify sys_doc, app_doc and audit_doc deleted from tmp
	jaldb_status ret1 = JALDB_OK;
	jaldb_status ret2 = JALDB_OK;
	jaldb_status ret3 = JALDB_OK;
	try {
		sys_doc_out2 = tmp_sys_cont.getDocument(txn3,
				doc_name1, 0);
	} catch (XmlException &e){
		ret1 = JALDB_E_INVAL;
	}
	try {
		app_doc_out2 = tmp_app_cont.getDocument(txn3,
				doc_name1, 0);
	} catch (XmlException &e){
		ret2 = JALDB_E_INVAL;
	}
	try {
		audit_doc_out2 = tmp_audit_cont.getDocument(txn3,
				doc_name1, 0);
	} catch (XmlException &e){
		ret3 = JALDB_E_INVAL;
	}
	if (JALDB_OK == (ret1 | ret2 | ret3)){
		txn3.commit();
		ret = JALDB_OK;
	} else {
		txn3.abort();
		ret = JALDB_E_INVAL;
	}

	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_xfer_audit_works_no_app()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn1 = context->manager->createTransaction();
	XmlContainer *sys_cont = context->audit_sys_cont;
	XmlContainer *audit_cont = context->audit_cont;
	std::string doc_name1 = "test_xfer_audit_works1";
	jaldb_status ret;
	XmlValue false_val(false);
	XmlValue true_val(true);
	string sys_db_name = jaldb_make_temp_db_name(src,
		JALDB_AUDIT_SYS_META_CONT_NAME);
	string audit_db_name = jaldb_make_temp_db_name(src,
		JALDB_AUDIT_CONT_NAME);

	XmlContainer tmp_sys_cont;
	XmlContainer tmp_audit_cont;

	ret = jaldb_open_temp_container(context, sys_db_name,
			tmp_sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, audit_db_name,
			tmp_audit_cont);
	assert_equals(JALDB_OK, ret);

	std::string sys_doc_cont1;
	std::string audit_doc_cont1;
	XmlDocument sys_doc1 = context->manager->createDocument();
	XmlDocument audit_doc1 = context->manager->createDocument();
	sys_doc1.setName(doc_name1);
	audit_doc1.setName(doc_name1);
	sys_doc1.setMetaData(JALDB_NS, JALDB_HAS_APP_META, false_val);

	// Insert sys_doc and audit_doc into tmp
	try {
		sys_doc1.getContent(sys_doc_cont1);
		audit_doc1.getContent(audit_doc_cont1);
		tmp_sys_cont.putDocument(txn1, sys_doc1, uc);
		tmp_audit_cont.putDocument(txn1, audit_doc1, uc);
		txn1.commit();
		ret = JALDB_OK;
	} catch (XmlException &e) {
		txn1.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);

	std::string sid_out1;
	ret = jaldb_xfer_audit(context, src, doc_name1, sid_out1);
	assert_equals(JALDB_OK, ret);

	XmlTransaction txn2 = context->manager->createTransaction();
	std::string sys_doc_cont_out1;
	std::string audit_doc_cont_out1;
	XmlDocument sys_doc_out1;
	XmlDocument audit_doc_out1;

	// Verify sys_doc and audit_doc exist in perm
	try {
		sys_doc_out1 = sys_cont->getDocument(txn2, sid_out1, 0);
		audit_doc_out1 = audit_cont->getDocument(txn2,
					sid_out1, 0);
		sys_doc_out1.getContent(sys_doc_cont_out1);
		audit_doc_out1.getContent(audit_doc_cont_out1);
		txn2.commit();
		ret = JALDB_OK;
	} catch (XmlException &e) {
		txn2.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);
	assert_equals(sys_doc_cont1, sys_doc_cont_out1);
	assert_equals(audit_doc_cont1, audit_doc_cont_out1);

	XmlTransaction txn3 = context->manager->createTransaction();
	XmlDocument sys_doc_out2;
	XmlDocument audit_doc_out2;

	// Verify sys_doc and audit_doc deleted from tmp
	try {
		jaldb_status ret1 = JALDB_OK;
		jaldb_status ret2 = JALDB_OK;
		try {
			sys_doc_out2 = tmp_sys_cont.getDocument(txn3,
					doc_name1, 0);
		} catch (XmlException &e){
			ret1 = JALDB_E_INVAL;
		}
		try {
			audit_doc_out2 = tmp_audit_cont.getDocument(txn3,
					doc_name1, 0);
		} catch (XmlException &e){
			ret2 = JALDB_E_INVAL;
		}
		if (JALDB_OK == (ret1 | ret2)){
			txn3.commit();
			ret = JALDB_OK;
		} else {
			txn3.abort();
			ret = JALDB_E_INVAL;
		}
	} catch (XmlException &e) {
		txn3.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_xfer_audit_fails_bad_input()
{
	std::string src = REMOTE_HOST;
	std::string empty_src = "";
	std::string doc_name = "test_xfer_audit_fails_bad_input";
	std::string empty_sid = "";
	std::string sid_out;
	jaldb_status ret;

	XmlManager *mgr = context->manager;
	XmlContainer *cont;
	int db_read_only = context->db_read_only;

	ret = jaldb_xfer_audit(context, src, empty_sid, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_xfer_audit(NULL, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	context->manager = NULL;
	ret = jaldb_xfer_audit(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	context->manager = mgr;
	mgr = NULL;
	ret = jaldb_xfer_audit(context, empty_src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	cont = context->audit_sys_cont;
	context->audit_sys_cont = NULL;
	ret = jaldb_xfer_audit(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);
	context->audit_sys_cont = cont;
	cont = NULL;

	cont = context->audit_app_cont;
	context->audit_app_cont = NULL;
	ret = jaldb_xfer_audit(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);
	context->audit_app_cont = cont;
	cont = NULL;

	cont = context->audit_cont;
	context->audit_cont = NULL;
	ret = jaldb_xfer_audit(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);
	context->audit_cont = cont;
	cont = NULL;

	context->db_read_only = 1;
	ret = jaldb_xfer_audit(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_READ_ONLY, ret);
	context->db_read_only = db_read_only;
}

extern "C" void test_jaldb_xfer_audit_fails_docs_dont_exist_in_tmp()
{
	std::string src = REMOTE_HOST;
	std::string empty_src = "";
	std::string doc_name = "test_xfer_audit_fails_docs_dont_exist";
	std::string empty_sid = "";
	std::string sid_out;
	jaldb_status ret;

	ret = jaldb_xfer_audit(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_NOT_FOUND, ret);
}

extern "C" void test_jaldb_xfer_journal_works()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn1 = context->manager->createTransaction();
	XmlContainer *sys_cont = context->journal_sys_cont;
	XmlContainer *app_cont = context->journal_app_cont;
	std::string doc_name1 = "test_xfer_journal_works1";
	jaldb_status ret;
	XmlValue false_val(false);
	XmlValue true_val(true);
	string sys_db_name = jaldb_make_temp_db_name(src,
		JALDB_JOURNAL_SYS_META_CONT_NAME);
	string app_db_name = jaldb_make_temp_db_name(src,
		JALDB_JOURNAL_APP_META_CONT_NAME);

	XmlContainer tmp_sys_cont;
	XmlContainer tmp_app_cont;

	ret = jaldb_open_temp_container(context, sys_db_name,
			tmp_sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, app_db_name,
			tmp_app_cont);
	assert_equals(JALDB_OK, ret);

	std::string sys_doc_cont1;
	std::string app_doc_cont1;
	std::string path1 = "RandomPath";

	XmlDocument sys_doc1 = context->manager->createDocument();
	XmlDocument app_doc1 = context->manager->createDocument();
	sys_doc1.setName(doc_name1);
	app_doc1.setName(doc_name1);
	sys_doc1.setMetaData(JALDB_NS, JALDB_HAS_APP_META, true_val);
	sys_doc1.setMetaData(JALDB_NS, JALDB_SOURCE, src);
	sys_doc1.setMetaData(JALDB_NS, JALDB_JOURNAL_PATH, path1);

	// Insert sys_doc, app_doc into tmp
	//	Unimportant to test transfer of journal file
	//	as it remains in the same location and isn't
	//	operated upon by the transfer function.
	try {
		sys_doc1.getContent(sys_doc_cont1);
		app_doc1.getContent(app_doc_cont1);
		tmp_sys_cont.putDocument(txn1, sys_doc1, uc);
		tmp_app_cont.putDocument(txn1, app_doc1, uc);
		txn1.commit();
		ret = JALDB_OK;
	} catch (XmlException &e) {
		txn1.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);

	std::string sid_out1;
	ret = jaldb_xfer_journal(context, src, doc_name1, sid_out1);
	assert_equals(JALDB_OK, ret);

	XmlTransaction txn2 = context->manager->createTransaction();
	std::string sys_doc_cont_out1;
	std::string app_doc_cont_out1;
	std::string path_out1;
	XmlValue val_out1;
	XmlDocument sys_doc_out1;
	XmlDocument app_doc_out1;

	// Verify sys_doc, app_doc exist in perm
	try {
		sys_doc_out1 = sys_cont->getDocument(txn2, sid_out1, 0);
		app_doc_out1 = app_cont->getDocument(txn2, sid_out1, 0);
		sys_doc_out1.getContent(sys_doc_cont_out1);
		app_doc_out1.getContent(app_doc_cont_out1);
		txn2.commit();
		ret = JALDB_OK;
	} catch (XmlException &e) {
		txn2.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);
	assert_equals(sys_doc_cont1, sys_doc_cont_out1);
	assert_equals(app_doc_cont1, app_doc_cont_out1);
	assert_true(sys_doc_out1.getMetaData(JALDB_NS,
			JALDB_JOURNAL_PATH, val_out1));
	assert_equals(path1, val_out1.asString());

	XmlTransaction txn3 = context->manager->createTransaction();
	XmlDocument sys_doc_out2;
	XmlDocument app_doc_out2;

	// Verify sys_doc, app_doc deleted from tmp
	jaldb_status ret1 = JALDB_OK;
	jaldb_status ret2 = JALDB_OK;
	try {
		sys_doc_out2 = tmp_sys_cont.getDocument(txn3,
				doc_name1, 0);
	} catch (XmlException &e){
		ret1 = JALDB_E_INVAL;
	}
	try {
		app_doc_out2 = tmp_app_cont.getDocument(txn3,
				doc_name1, 0);
	} catch (XmlException &e){
		ret2 = JALDB_E_INVAL;
	}
	if (JALDB_OK == (ret1 | ret2)){
		txn3.commit();
		ret = JALDB_OK;
	} else {
		txn3.abort();
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_xfer_journal_works_no_app()
{
	std::string src = REMOTE_HOST;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn1 = context->manager->createTransaction();
	XmlContainer *sys_cont = context->journal_sys_cont;
	std::string doc_name1 = "test_xfer_journal_works_no_app1";
	jaldb_status ret;
	XmlValue false_val(false);
	XmlValue true_val(true);
	string sys_db_name = jaldb_make_temp_db_name(src,
		JALDB_JOURNAL_SYS_META_CONT_NAME);
	XmlContainer tmp_sys_cont;

	ret = jaldb_open_temp_container(context, sys_db_name,
			tmp_sys_cont);
	assert_equals(JALDB_OK, ret);

	std::string sys_doc_cont1;
	std::string path1 = "RandomPath";

	XmlDocument sys_doc1 = context->manager->createDocument();
	sys_doc1.setName(doc_name1);
	sys_doc1.setMetaData(JALDB_NS, JALDB_HAS_APP_META, false_val);
	sys_doc1.setMetaData(JALDB_NS, JALDB_SOURCE, src);
	sys_doc1.setMetaData(JALDB_NS, JALDB_JOURNAL_PATH, path1);

	// Insert sys_doc, app_doc into tmp
	//	Unimportant to test transfer of journal file
	//	as it remains in the same location and isn't
	//	operated upon by the transfer function.
	try {
		sys_doc1.getContent(sys_doc_cont1);
		tmp_sys_cont.putDocument(txn1, sys_doc1, uc);
		txn1.commit();
		ret = JALDB_OK;
	} catch (XmlException &e) {
		txn1.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);

	std::string sid_out1;
	ret = jaldb_xfer_journal(context, src, doc_name1, sid_out1);
	assert_equals(JALDB_OK, ret);

	XmlTransaction txn2 = context->manager->createTransaction();
	std::string sys_doc_cont_out1;
	std::string path_out1;
	XmlValue val_out1;
	XmlDocument sys_doc_out1;

	// Verify sys_doc exist in perm
	try {
		sys_doc_out1 = sys_cont->getDocument(txn2, sid_out1, 0);
		sys_doc_out1.getContent(sys_doc_cont_out1);
		txn2.commit();
		ret = JALDB_OK;
	} catch (XmlException &e) {
		txn2.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);
	assert_equals(sys_doc_cont1, sys_doc_cont_out1);
	assert_true(sys_doc_out1.getMetaData(JALDB_NS,
			JALDB_JOURNAL_PATH, val_out1));
	assert_equals(path1, val_out1.asString());

	XmlTransaction txn3 = context->manager->createTransaction();
	XmlDocument sys_doc_out2;

	// Verify sys_doc deleted from tmp
	jaldb_status ret1 = JALDB_OK;
	try {
		sys_doc_out2 = tmp_sys_cont.getDocument(txn3,
				doc_name1, 0);
	} catch (XmlException &e){
		ret1 = JALDB_E_INVAL;
	}
	if (JALDB_OK == ret1 ){
		txn3.commit();
		ret = JALDB_OK;
	} else {
		txn3.abort();
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_xfer_journal_fails_bad_input()
{
	std::string src = REMOTE_HOST;
	std::string empty_src = "";
	std::string doc_name = "test_xfer_journal_fails_bad_input";
	std::string empty_sid = "";
	std::string sid_out;
	jaldb_status ret;

	XmlManager *mgr = context->manager;
	XmlContainer *cont;
	int db_read_only = context->db_read_only;

	ret = jaldb_xfer_journal(context, src, empty_sid, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_xfer_journal(NULL, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	context->manager = NULL;
	ret = jaldb_xfer_journal(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	context->manager = mgr;
	mgr = NULL;
	ret = jaldb_xfer_journal(context, empty_src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);

	cont = context->journal_sys_cont;
	context->journal_sys_cont = NULL;
	ret = jaldb_xfer_journal(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);
	context->journal_sys_cont = cont;
	cont = NULL;

	cont = context->journal_app_cont;
	context->journal_app_cont = NULL;
	ret = jaldb_xfer_journal(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_INVAL, ret);
	context->journal_app_cont = cont;
	cont = NULL;

	context->db_read_only = 1;
	ret = jaldb_xfer_journal(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_READ_ONLY, ret);
	context->db_read_only = db_read_only;
}

extern "C" void test_jaldb_xfer_journal_fails_docs_dont_exist_in_tmp()
{
	std::string src = REMOTE_HOST;
	std::string doc_name = "test_xfer_journal_fails_docs_dont_exist";
	std::string sid_out;
	jaldb_status ret;

	ret = jaldb_xfer_journal(context, src, doc_name, sid_out);
	assert_equals(JALDB_E_NOT_FOUND, ret);
}

extern "C" void test_jaldb_store_confed_sid_tmp_helper_works()
{
	int db_err_out;
	jaldb_status ret = JALDB_OK;
	string sys_db = jaldb_make_temp_db_name(REMOTE_HOST,
			JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);

	XmlDocument doc;
	XmlTransaction txn = context->manager->createTransaction();
	try {
		doc = sys_cont.getDocument(txn,
					JALDB_SERIAL_ID_DOC_NAME,
					DB_READ_COMMITTED);
		ret = JALDB_OK;
	} catch (XmlException &e){
		ret = JALDB_E_INVAL;
	}
	txn.abort();
	assert_equals(JALDB_E_INVAL, ret);

	// 1 SID Doc does not exist
	std::string sid = "ABC";
	ret = jaldb_store_confed_sid_tmp_helper(context, &sys_cont,
				REMOTE_HOST, sid.c_str(), &db_err_out);
	assert_equals(JALDB_OK, ret);
	XmlDocument doc2;
	XmlTransaction txn2 = context->manager->createTransaction();
	try {
		doc2 = sys_cont.getDocument(txn2,
					JALDB_SERIAL_ID_DOC_NAME,
					DB_READ_COMMITTED);
		XmlValue val;
		if (!doc2.getMetaData(JALDB_NS,
			JALDB_LAST_CONFED_SID_NAME, val)) {
			ret = JALDB_E_CORRUPTED;
		}
		if (!val.isString()) {
			ret = JALDB_E_CORRUPTED;
		}
		std::string sid_out = val.asString();
		int len = sid_out.length();
		if (0 != memcmp((const char *) sid_out.c_str(),
			sid.c_str(), len)){
			ret = JALDB_E_INVAL;
		}
		ret = JALDB_OK;
	} catch (XmlException &e){
		ret = JALDB_E_INVAL;
	}
	txn2.abort();
	assert_equals(JALDB_OK, ret);

	// 2 SID Doc exists, modify it
	std::string sid2 = "EZas123";
	ret = jaldb_store_confed_sid_tmp_helper(context, &sys_cont,
				REMOTE_HOST, sid2.c_str(), &db_err_out);
	assert_equals(JALDB_OK, ret);
	XmlDocument doc3;
	XmlTransaction txn3 = context->manager->createTransaction();
	try {
		doc3 = sys_cont.getDocument(txn3,
					JALDB_SERIAL_ID_DOC_NAME,
					DB_READ_COMMITTED);
		XmlValue val;
		if (!doc3.getMetaData(JALDB_NS,
			JALDB_LAST_CONFED_SID_NAME, val)) {
			ret = JALDB_E_CORRUPTED;
		}
		if (!val.isString()) {
			ret = JALDB_E_CORRUPTED;
		}
		std::string sid_out2 = val.asString();
		int len = sid2.length();
		if (0 != memcmp((const char *) sid_out2.c_str(),
			sid2.c_str(), len)){
			ret = JALDB_E_INVAL;
		}
		ret = JALDB_OK;
	} catch (XmlException &e){
		ret = JALDB_E_INVAL;
	}
	txn3.abort();
	assert_equals(JALDB_OK, ret);
}

extern "C" void test_jaldb_get_last_confed_sid_tmp_helper_works()
{
	int db_err_out;
	jaldb_status ret = JALDB_OK;
	string sys_db = jaldb_make_temp_db_name(REMOTE_HOST,
			JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);

	std::string sid_in = "ABCezAs123";
	XmlDocument doc;
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlTransaction txn = context->manager->createTransaction();
	XmlValue sid_val(sid_in);
	doc = context->manager->createDocument();
	doc.setName(JALDB_SERIAL_ID_DOC_NAME);
	doc.setMetaData(JALDB_NS,
			JALDB_LAST_CONFED_SID_NAME,
			sid_val);
	try {
		sys_cont.putDocument(txn, doc, uc);
		ret = JALDB_OK;
		txn.commit();
	} catch (XmlException &e){
		txn.abort();
		if (e.getExceptionCode()
			== XmlException::UNIQUE_ERROR) {
			ret = JALDB_E_SID;
		}
		else {
			throw e;
		}
	}
	assert_equals(JALDB_OK, ret);

	// 1 SID Doc does not exist
	std::string sid_out = "";
	ret = jaldb_get_last_confed_sid_tmp_helper(context, &sys_cont,
				REMOTE_HOST, sid_out, &db_err_out);
	assert_equals(JALDB_OK, ret);
	assert_equals(sid_in.length(), sid_out.length());
	assert(0 == memcmp(sid_in.c_str(), sid_out.c_str(),
			    sid_in.length()));
}

extern "C" void test_jaldb_get_last_confed_sid_tmp_helper_works_doc_dne()
{
	int db_err_out;
	jaldb_status ret = JALDB_OK;
	string sys_db = jaldb_make_temp_db_name(REMOTE_HOST,
			JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);

	// 1 SID Doc does not exist
	std::string sid_out = "";
	ret = jaldb_get_last_confed_sid_tmp_helper(context, &sys_cont,
				REMOTE_HOST, sid_out, &db_err_out);
	assert_not_equals(JALDB_OK, ret);
}

extern "C" void test_jaldb_store_journal_resume_works()
{
	std::string path = "my_path";
	std::string host = REMOTE_HOST;
	uint64_t offset = 123;
	jaldb_status ret = JALDB_OK;

	ret = jaldb_store_journal_resume(context, host.c_str(),
					 path.c_str(), offset);
	assert_equals(JALDB_OK, ret);

	string sys_db = jaldb_make_temp_db_name(REMOTE_HOST,
			JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);

	// Retrieve the stored document
	XmlDocument doc;
	XmlTransaction txn = context->manager->createTransaction();
	try {
		doc = sys_cont.getDocument(txn,
					JALDB_SERIAL_ID_DOC_NAME,
					DB_READ_COMMITTED);
		ret = JALDB_OK;
	} catch (XmlException &e){
		ret = JALDB_E_INVAL;
		txn.abort();
	}
	assert_equals(JALDB_OK, ret);

	// Compare values
	XmlValue offset_val;
	XmlValue path_val;
	if (!doc.getMetaData(JALDB_NS,
		JALDB_OFFSET_NAME, offset_val)) {
		assert_false(true);
	}
	if (!doc.getMetaData(JALDB_NS,
		JALDB_JOURNAL_PATH, path_val)) {
		assert_false(true);
	}
	assert_equals(0, path.compare(path_val.asString()));
	char *offset_str =  (char *) offset_val.asString().c_str();
	uint64_t *offset_out = (uint64_t *) jal_malloc(21);
	sscanf(offset_str, "%" PRIu64, offset_out);
	assert_equals(offset, *offset_out);
	txn.abort();

	// Modify the offset and path, doc should get updated.
	// last_confed_sid should remain the same
	offset = 300;
	path = "another_path";
	ret = jaldb_store_journal_resume(context, host.c_str(),
					 path.c_str(), offset);
	assert_equals(JALDB_OK, ret);

	// Retrieve the stored document
	XmlDocument doc2;
	XmlTransaction txn2 = context->manager->createTransaction();
	try {
		doc2 = sys_cont.getDocument(txn2,
					JALDB_SERIAL_ID_DOC_NAME,
					DB_READ_COMMITTED);
		ret = JALDB_OK;
	} catch (XmlException &e){
		ret = JALDB_E_INVAL;
		txn2.abort();
	}
	assert_equals(JALDB_OK, ret);

	// Verify it was updated
	XmlValue offset_val2;
	XmlValue path_val2;
	XmlValue sid_val2;
	if (!doc2.getMetaData(JALDB_NS,
		JALDB_OFFSET_NAME, offset_val2)) {
		assert_false(true);
	}
	if (!doc2.getMetaData(JALDB_NS,
		JALDB_JOURNAL_PATH, path_val2)) {
		assert_false(true);
	}
	assert_equals(0, path.compare(path_val2.asString()));
	char *offset_str2 =  (char *) offset_val2.asString().c_str();
	uint64_t *offset_out2 = (uint64_t *) jal_malloc(21);
	sscanf(offset_str2, "%" PRIu64, offset_out2);
	assert_equals(offset, *offset_out2);
	txn2.abort();
}

extern "C" void test_jaldb_get_journal_resume_works()
{
	char *path = NULL;
	std::string host = REMOTE_HOST;
	uint64_t offset;
	jaldb_status ret = JALDB_OK;
	std::string path_in = "my_path";
	std::string offset_in = "123";

	ret = jaldb_get_journal_resume(context, host.c_str(),
					 &path, offset);
	assert_not_equals(JALDB_OK, ret);
	string sys_db = jaldb_make_temp_db_name(REMOTE_HOST,
			JALDB_LOG_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);

	// Insert a dummy journal resume document
	XmlDocument doc;
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlValue offset_val(offset_in);
	XmlValue path_val(path_in);
	doc = context->manager->createDocument();
	doc.setName(JALDB_SERIAL_ID_DOC_NAME);
	doc.setMetaData(JALDB_NS,
		JALDB_OFFSET_NAME, offset_val);
	doc.setMetaData(JALDB_NS,
		JALDB_JOURNAL_PATH, path_val);
	try {
		sys_cont.putDocument(txn, doc, uc);
		ret = JALDB_OK;
		txn.commit();
	} catch (XmlException &e){
		ret = JALDB_E_INVAL;
		txn.abort();
	}
	assert_equals(JALDB_OK, ret);

	
	// Retrieve and compare values
	ret = jaldb_get_journal_resume(context, host.c_str(),
					 &path, offset);
	assert_equals(JALDB_OK, ret);
	size_t len = strlen(path);
	assert_equals(len, path_in.length());
	assert_equals(0, memcmp(path, path_in.c_str(), len));
	assert_equals(123, offset);
	free(path);
}
