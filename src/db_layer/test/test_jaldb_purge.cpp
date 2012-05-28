/**
 * @file test_jaldb_purge.cpp This file contains functions to test
 * jaldb_purge.cpp.
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
#include <errno.h>
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
#include "jaldb_purge.hpp"
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
#define LOG_SYS_TEST_XML_DOC "./test-input/system-metadata.xml"
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

void clear_docs( list<jaldb_doc_info> &docs)
{
	list<jaldb_doc_info>::iterator cur = docs.begin();
        while(cur != docs.end())
        {
		if(cur->sid) {
			free(cur->sid);
			cur->sid = NULL;
		}
		if(cur->uuid) {
			free(cur->uuid);
			cur->uuid = NULL;
		}
                cur++;
        }
	docs.clear();
}

void print_out_docs(list<jaldb_doc_info> docs)
{
	cout << "in print_out_docs" << endl;
	list<jaldb_doc_info>::iterator cur = docs.begin();
	int i=0;
	while(cur != docs.end())
	{	
		cout << "i " << i << endl;
		i++;
		if (cur->sid)
			cout << "sid: " << cur->sid;
		else
			cout << "sid: NULL";
		if (cur->uuid)
			cout << " uuid: " << cur->uuid << endl;
		else
			cout << " uuid: NULL" << endl;
		cur++;
	}
}
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
	audit_sys_meta_doc = parser->parseURI(LOG_SYS_TEST_XML_DOC);
	audit_app_meta_doc = parser->parseURI(AUDIT_APP_TEST_XML_DOC);
	audit_doc = parser->parseURI(AUDIT_TEST_XML_DOC);
	log_sys_meta_doc = parser->parseURI(LOG_SYS_TEST_XML_DOC);
	log_app_meta_doc = parser->parseURI(LOG_APP_TEST_XML_DOC);
	context = jaldb_context_create();
	jaldb_context_init(context, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, false);
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

extern "C" void test_purge_unconfirmed_audit_works_when_empty()
{
	enum jaldb_status ret;

	string src = "1.2.3.4";

	ret = jaldb_purge_unconfirmed_audit(context, src.c_str());
	assert_equals(JALDB_OK, ret);

	string sys_db = jaldb_make_temp_db_name(src, JALDB_AUDIT_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(src, JALDB_AUDIT_APP_META_CONT_NAME);
	string audit_db = jaldb_make_temp_db_name(src, JALDB_AUDIT_SYS_META_CONT_NAME);
	XmlContainer sys_cont;
	XmlContainer app_cont;
	XmlContainer audit_cont;

	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, app_db, app_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, audit_db, audit_cont);
	assert_equals(JALDB_OK, ret);


	XmlUpdateContext uc = context->manager->createUpdateContext();

	XmlDocument doc;
	try {
		doc = sys_cont.getDocument(JALDB_CONNECTION_METADATA_DOC_NAME);
		// the doc should exist, so an exception should be thrown.
		assert_true(false);
	} catch (XmlException &e) {
		assert_equals(e.getExceptionCode(), XmlException::DOCUMENT_NOT_FOUND);
	}

	XmlResults res = sys_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	res = app_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	res = audit_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
}

extern "C" void test_purge_unconfirmed_audit_returns_error_on_bad_input()
{
	string src = "1.2.3.4";
	enum jaldb_status ret;
	ret = jaldb_purge_unconfirmed_audit(NULL, src.c_str());
	assert_equals(JALDB_E_INVAL, ret);
	ret = jaldb_purge_unconfirmed_audit(context, NULL);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_purge_unconfirmed_log_with_no_confed_records()
{
	enum jaldb_status ret;
	int db_err;

	string sid = "abc";
	string src = "1.2.3.4";
	ret = jaldb_insert_log_record_into_temp(context, src,
		log_sys_meta_doc, log_app_meta_doc, (uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(JALDB_OK, ret);

	sid = "def";
	ret = jaldb_insert_log_record_into_temp(context, src,
		log_sys_meta_doc, log_app_meta_doc, (uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(JALDB_OK, ret);

	sid = "ghi";
	ret = jaldb_insert_log_record_into_temp(context, src,
		log_sys_meta_doc, log_app_meta_doc, (uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_purge_unconfirmed_log(context, src.c_str(), &db_err);
	assert_equals(JALDB_OK, ret);

	string sys_db = jaldb_make_temp_db_name(src, JALDB_LOG_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(src, JALDB_LOG_APP_META_CONT_NAME);
	string log_db_name = jaldb_make_temp_db_name(src, JALDB_LOG_DB_NAME);
	XmlContainer sys_cont;
	XmlContainer app_cont;
	DB *log_db = NULL;

	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, app_db, app_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_db(context, log_db_name, &log_db, &db_err);
	assert_equals(JALDB_OK, ret);

	XmlUpdateContext uc = context->manager->createUpdateContext();

	XmlDocument doc;
	try {
		doc = sys_cont.getDocument(JALDB_CONNECTION_METADATA_DOC_NAME);
		assert_true(false);
	} catch (XmlException &e) {
		assert_equals(e.getExceptionCode(), XmlException::DOCUMENT_NOT_FOUND);
	}

	XmlResults res = sys_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	res = app_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	DBT key;
	DBT data;
	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	DBC *cursor = NULL;
	XmlTransaction txn = context->manager->createTransaction();
	db_err = log_db->cursor(log_db, txn.getDB_TXN(), &cursor, DB_READ_COMMITTED);
	assert_equals(0, db_err);
	while(0 == (db_err = cursor->get(cursor, &key, &data, DB_NEXT))) {
		// the database should be empty at this point.
		assert_false(true);
	}
	assert_equals(DB_NOTFOUND, db_err);
	cursor->close(cursor);
}

extern "C" void test_purge_unconfirmed_log_works_with_no_records()
{
	enum jaldb_status ret;
	int db_err;

	string sid = "abc";
	string src = "1.2.3.4";

	ret = jaldb_purge_unconfirmed_log(context, src.c_str(), &db_err);
	assert_equals(JALDB_OK, ret);

	string sys_db = jaldb_make_temp_db_name(src, JALDB_LOG_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(src, JALDB_LOG_APP_META_CONT_NAME);
	string log_db_name = jaldb_make_temp_db_name(src, JALDB_LOG_DB_NAME);
	XmlContainer sys_cont;
	XmlContainer app_cont;
	DB *log_db = NULL;

	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, app_db, app_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_db(context, log_db_name, &log_db, &db_err);
	assert_equals(JALDB_OK, ret);

	XmlUpdateContext uc = context->manager->createUpdateContext();

	XmlDocument doc;
	try {
		doc = sys_cont.getDocument(JALDB_CONNECTION_METADATA_DOC_NAME);
		assert_true(false);
	} catch (XmlException &e) {
		assert_equals(e.getExceptionCode(), XmlException::DOCUMENT_NOT_FOUND);
	}

	XmlResults res = sys_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	res = app_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	DBT key;
	DBT data;
	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	DBC *cursor = NULL;
	XmlTransaction txn = context->manager->createTransaction();
	db_err = log_db->cursor(log_db, txn.getDB_TXN(), &cursor, DB_READ_COMMITTED);
	assert_equals(0, db_err);
	while(0 == (db_err = cursor->get(cursor, &key, &data, DB_NEXT))) {
		// the database should be empty at this point.
		assert_false(true);
	}
	assert_equals(DB_NOTFOUND, db_err);
	cursor->close(cursor);
}

extern "C" void test_purge_unconfirmed_log_works()
{
	enum jaldb_status ret;
	int db_err;

	string sid = "abc";
	string src = "1.2.3.4";
	ret = jaldb_insert_log_record_into_temp(context, src,
		log_sys_meta_doc, log_app_meta_doc, (uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(JALDB_OK, ret);

	sid = "def";
	ret = jaldb_insert_log_record_into_temp(context, src,
		log_sys_meta_doc, log_app_meta_doc, (uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(JALDB_OK, ret);

	sid = "ghi";
	ret = jaldb_insert_log_record_into_temp(context, src,
		log_sys_meta_doc, log_app_meta_doc, (uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_store_confed_log_sid_tmp(context, src.c_str(), sid.c_str(), &db_err);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_purge_unconfirmed_log(context, src.c_str(), &db_err);
	assert_equals(JALDB_OK, ret);

	string sys_db = jaldb_make_temp_db_name(src, JALDB_LOG_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(src, JALDB_LOG_APP_META_CONT_NAME);
	string log_db_name = jaldb_make_temp_db_name(src, JALDB_LOG_DB_NAME);
	XmlContainer sys_cont;
	XmlContainer app_cont;
	DB *log_db = NULL;

	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, app_db, app_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_db(context, log_db_name, &log_db, &db_err);
	assert_equals(JALDB_OK, ret);

	XmlUpdateContext uc = context->manager->createUpdateContext();

	XmlDocument doc;
	doc = sys_cont.getDocument(JALDB_CONNECTION_METADATA_DOC_NAME);
	sys_cont.deleteDocument(doc, uc);

	XmlResults res = sys_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	res = app_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	DBT key;
	DBT data;
	memset(&key, 0, sizeof(key));
	memset(&data, 0, sizeof(data));

	DBC *cursor = NULL;
	XmlTransaction txn = context->manager->createTransaction();
	db_err = log_db->cursor(log_db, txn.getDB_TXN(), &cursor, DB_READ_COMMITTED);
	assert_equals(0, db_err);
	while(0 == (db_err = cursor->get(cursor, &key, &data, DB_NEXT))) {
		// the database should be empty at this point.
		assert_false(true);
	}
	assert_equals(DB_NOTFOUND, db_err);
	cursor->close(cursor);
}

extern "C" void test_purge_unconfirmed_log_returns_error_on_bad_input()
{
	string src = "1.2.3.4";
	enum jaldb_status ret;
	int db_ret;
	ret = jaldb_purge_unconfirmed_log(NULL, src.c_str(), &db_ret);
	assert_equals(JALDB_E_INVAL, ret);
	ret = jaldb_purge_unconfirmed_log(context, NULL, &db_ret);
	assert_equals(JALDB_E_INVAL, ret);
	ret = jaldb_purge_unconfirmed_log(context, src.c_str(), NULL);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_purge_unconfirmed_journal_works()
{
	enum jaldb_status ret;
	int db_err;

	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	char *path_1 = NULL;
	char *path_2 = NULL;
	int fd = -1;
	int rc = 0;

	ret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	ret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	ret = jaldb_insert_journal_metadata_into_temp(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, ret);

	sid = "def";
	ret = jaldb_insert_journal_metadata_into_temp(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_store_confed_journal_sid_tmp(context, src.c_str(), sid.c_str(), &db_err);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_purge_unconfirmed_journal(context, src.c_str());
	assert_equals(JALDB_OK, ret);

	string sys_db = jaldb_make_temp_db_name(src, JALDB_JOURNAL_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(src, JALDB_JOURNAL_APP_META_CONT_NAME);
	XmlContainer sys_cont;
	XmlContainer app_cont;

	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, app_db, app_cont);
	assert_equals(JALDB_OK, ret);

	XmlUpdateContext uc = context->manager->createUpdateContext();

	XmlDocument doc;
	doc = sys_cont.getDocument(JALDB_CONNECTION_METADATA_DOC_NAME);
	sys_cont.deleteDocument(doc, uc);

	XmlResults res = sys_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	res = app_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}

	string was_deleted = context->journal_root;
	was_deleted.append("/").append(path_1);
	fd = open(was_deleted.c_str(), O_TRUNC);
	int my_errno = errno;
	assert_equals(-1, fd);
	assert_equals(ENOENT, my_errno);

	was_deleted = context->journal_root;
	was_deleted.append("/").append(path_2);
	fd = open(was_deleted.c_str(), O_TRUNC);
	my_errno = errno;
	assert_equals(-1, fd);
	assert_equals(ENOENT, my_errno);

	free(path_1);
	free(path_2);
}

extern "C" void test_purge_unconfirmed_journal_works_with_no_confed_records()
{
	enum jaldb_status ret;

	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	char *path_1 = NULL;
	char *path_2 = NULL;
	int fd = -1;
	int rc = 0;

	ret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	ret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, ret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	ret = jaldb_insert_journal_metadata_into_temp(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, ret);

	sid = "def";
	ret = jaldb_insert_journal_metadata_into_temp(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, ret);

	ret = jaldb_purge_unconfirmed_journal(context, src.c_str());
	assert_equals(JALDB_OK, ret);

	string sys_db = jaldb_make_temp_db_name(src, JALDB_JOURNAL_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(src, JALDB_JOURNAL_APP_META_CONT_NAME);
	XmlContainer sys_cont;
	XmlContainer app_cont;

	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, app_db, app_cont);
	assert_equals(JALDB_OK, ret);

	XmlUpdateContext uc = context->manager->createUpdateContext();

	XmlDocument doc;
	try {
		doc = sys_cont.getDocument(JALDB_CONNECTION_METADATA_DOC_NAME);
		// the doc should not exist, so an exception should be thrown.
		assert_true(false);
	} catch (XmlException &e) {
		assert_equals(e.getExceptionCode(), XmlException::DOCUMENT_NOT_FOUND);
	}

	XmlResults res = sys_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	res = app_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}

	string was_deleted = context->journal_root;
	was_deleted.append("/").append(path_1);
	fd = open(was_deleted.c_str(), O_TRUNC);
	int my_errno = errno;
	assert_equals(-1, fd);
	assert_equals(ENOENT, my_errno);

	was_deleted = context->journal_root;
	was_deleted.append("/").append(path_2);
	fd = open(was_deleted.c_str(), O_TRUNC);
	my_errno = errno;
	assert_equals(-1, fd);
	assert_equals(ENOENT, my_errno);

	free(path_1);
	free(path_2);
}

extern "C" void test_purge_unconfirmed_journal_works_when_empty()
{
	enum jaldb_status ret;

	string src = "1.2.3.4";

	ret = jaldb_purge_unconfirmed_journal(context, src.c_str());
	assert_equals(JALDB_OK, ret);

	string sys_db = jaldb_make_temp_db_name(src, JALDB_JOURNAL_SYS_META_CONT_NAME);
	string app_db = jaldb_make_temp_db_name(src, JALDB_JOURNAL_APP_META_CONT_NAME);
	XmlContainer sys_cont;
	XmlContainer app_cont;

	ret = jaldb_open_temp_container(context, sys_db, sys_cont);
	assert_equals(JALDB_OK, ret);
	ret = jaldb_open_temp_container(context, app_db, app_cont);
	assert_equals(JALDB_OK, ret);


	XmlUpdateContext uc = context->manager->createUpdateContext();

	XmlDocument doc;
	try {
		doc = sys_cont.getDocument(JALDB_CONNECTION_METADATA_DOC_NAME);
		// the doc should not exist, so an exception should be thrown.
		assert_true(false);
	} catch (XmlException &e) {
		assert_equals(e.getExceptionCode(), XmlException::DOCUMENT_NOT_FOUND);
	}

	XmlResults res = sys_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
	res = app_cont.getAllDocuments(DB_READ_COMMITTED);
	while(res.next(doc)) {
		// the result set should be empty
		assert_false(true);
	}
}

extern "C" void test_purge_unconfirmed_journal_returns_error_on_bad_input()
{
	string src = "1.2.3.4";
	enum jaldb_status ret;
	ret = jaldb_purge_unconfirmed_journal(NULL, src.c_str());
	assert_equals(JALDB_E_INVAL, ret);
	ret = jaldb_purge_unconfirmed_journal(context, NULL);
	assert_equals(JALDB_E_INVAL, ret);
}

//get_docs_to_purge tests
extern "C" void test_get_docs_to_purge_success()
{
	enum jaldb_status dbret;
	int db_err;
	string sid = "abc";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	string src = "1.2.3.4";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);


	XmlQueryContext qcontext = context->manager->createQueryContext();
	qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);
        qcontext.setVariableValue(JALDB_UUID_VAR, uuid);

	dbret = jaldb_mark_log_synced(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_log_sent_ok(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_log_synced(context, "3", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

	list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

}

extern "C" void test_get_docs_to_purge_fails_with_bad_input()
{
	enum jaldb_status dbret;
	int db_err;
	string sid = "abc";
	string src = "1.2.3.4";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);


	XmlQueryContext qcontext = context->manager->createQueryContext();
	qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

	list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;

	//null context	
	dbret = jaldb_get_docs_to_purge(NULL, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad transaction
	XmlTransaction bad_txn;
	dbret = jaldb_get_docs_to_purge(context, bad_txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad update context
	XmlUpdateContext bad_uc;
	dbret = jaldb_get_docs_to_purge(context, txn, bad_uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad query context
	XmlQueryContext bad_qcontext;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, bad_qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//empty query
	dbret = jaldb_get_docs_to_purge(context, txn, uc, bad_qcontext, "", docs);
	assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//empty query
	dbret = jaldb_get_docs_to_purge(context, txn, uc, bad_qcontext, "this is a bad query", docs);
	assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());
}

extern "C" void test_jaldb_purge_log_success()
{
	enum jaldb_status dbret;
        int db_err;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
        dbret = jaldb_purge_log(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs, 1);
        assert_equals(JALDB_OK, dbret);
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(true, docs.empty());
}

extern "C" void test_jaldb_purge_log_success_no_delete()
{
	enum jaldb_status dbret;
        int db_err;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
        dbret = jaldb_purge_log(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_OK, dbret);
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//with delete off, all docs should still exist
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
}

extern "C" void test_jaldb_purge_log_fails_with_bad_input()
{
	enum jaldb_status dbret;
        int db_err;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;

	//null jaldb context
        dbret = jaldb_purge_log(NULL, txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad jaldb context
	jaldb_context *null_ctx = NULL;
        dbret = jaldb_purge_log(null_ctx, txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad txn
	XmlTransaction bad_txn;
        dbret = jaldb_purge_log(context, bad_txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad uc
	XmlUpdateContext bad_uc;
        dbret = jaldb_purge_log(context, txn, bad_uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad qcontext
	XmlQueryContext bad_qcontext;
        dbret = jaldb_purge_log(context, txn, uc, bad_qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//empty query
        dbret = jaldb_purge_log(context, txn, uc, qcontext, "", docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad query
        dbret = jaldb_purge_log(context, txn, uc, qcontext, "this is a bad query", docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

}

extern "C" void test_jaldb_purge_log_by_sid_success()
{
	enum jaldb_status dbret;
        int db_err;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//docs should have 3 entries
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	
	dbret = jaldb_purge_log_by_sid(context, "2", docs, 1, 1);
	assert_equals(JALDB_OK, dbret);

	//docs should hold the two entries that were deleted
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	//docs should have only the 3rd entry left
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
	
}

extern "C" void test_jaldb_purge_log_by_sid_success_force_off()
{
	enum jaldb_status dbret;
        int db_err;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

	dbret = jaldb_mark_log_synced(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_log_sent_ok(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_log_synced(context, "3", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//docs should have 3 entries
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	
	dbret = jaldb_purge_log_by_sid(context, "3", docs, 0, 1);
	assert_equals(JALDB_OK, dbret);

	//docs should hold the two entries that were deleted
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	//docs should have only the 3rd entry left
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	
}

extern "C" void test_jaldb_purge_log_by_uuid_success()
{
	enum jaldb_status dbret;
        int db_err;
        string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);
        qcontext.setVariableValue(JALDB_UUID_VAR, uuid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.begin() != docs.end());
	clear_docs(docs);
	
	dbret = jaldb_purge_log_by_uuid(context, uuid.c_str(), docs, 1, 1);
	assert_equals(JALDB_OK, dbret);

	//docs should hold the two entries that were deleted
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	//docs should have only the 3rd entry left
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(docs.begin(), docs.end());

	clear_docs(docs);
	
}

extern "C" void test_jaldb_purge_log_by_uuid_success_force_off()
{
	enum jaldb_status dbret;
        int db_err;
        string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

	dbret = jaldb_mark_log_synced(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_log_sent_ok(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_log_synced(context, "3", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);
        qcontext.setVariableValue(JALDB_UUID_VAR, uuid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

	list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//docs should have 3 entries
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	
	dbret = jaldb_purge_log_by_uuid(context, uuid.c_str(), docs, 0, 1);
	assert_equals(JALDB_OK, dbret);

	//docs should hold the two entries that were deleted
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	//docs should have only the 3rd entry left
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	
}


extern "C" void test_jaldb_purge_log_by_sid_fails_with_bad_input()
{
	enum jaldb_status dbret;
        int db_err;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);

	//docs should have 3 entries
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	
	//null context
	dbret = jaldb_purge_log_by_sid(NULL, "2", docs, 1, 1);
	assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//null sid
	dbret = jaldb_purge_log_by_sid(context, NULL, docs, 1, 1);
	assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//These should return successfully but not entries should be removed
	//empty sid
	dbret = jaldb_purge_log_by_sid(context, "", docs, 1, 1);
	assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());
	
	//negative sid
	dbret = jaldb_purge_log_by_sid(context, "-1", docs, 1, 1);
	assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());

	//docs should still have 3 entries
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	
	
}

extern "C" void test_jaldb_purge_log_by_uuid_fails_with_bad_input()
{
	enum jaldb_status dbret;
        int db_err;
        string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( context, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->log_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);
        qcontext.setVariableValue(JALDB_UUID_VAR, uuid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);

	//docs should have 3 entries
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	
	//null context
	dbret = jaldb_purge_log_by_uuid(NULL, "2", docs, 1, 1);
	assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//null sid
	dbret = jaldb_purge_log_by_uuid(context, NULL, docs, 1, 1);
	assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//These should return successfully but not entries should be removed
	//empty sid
	dbret = jaldb_purge_log_by_uuid(context, "", docs, 1, 1);
	assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());
	
	//negative sid
	dbret = jaldb_purge_log_by_uuid(context, "-1", docs, 1, 1);
	assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());

	//docs should still have 3 entries
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	
	
}


extern "C" void test_jaldb_purge_audit_success()
{
	enum jaldb_status dbret;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->audit_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
        dbret = jaldb_purge_audit(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs, 1);
        assert_equals(JALDB_OK, dbret);
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(true, docs.empty());
}

extern "C" void test_jaldb_purge_audit_sucess_no_delete()
{
	enum jaldb_status dbret;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->audit_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
        dbret = jaldb_purge_audit(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_OK, dbret);
	clear_docs(docs);

	//with delete off, all files should still exist
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
}

extern "C" void test_jaldb_purge_audit_fails_with_bad_input()
{
	enum jaldb_status dbret;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->audit_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;

	//null jaldb context
        dbret = jaldb_purge_audit(NULL, txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad jaldb context
	jaldb_context *null_ctx = NULL;
        dbret = jaldb_purge_audit(null_ctx, txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad txn
	XmlTransaction bad_txn;
        dbret = jaldb_purge_audit(context, bad_txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad uc
	XmlUpdateContext bad_uc;
        dbret = jaldb_purge_audit(context, txn, bad_uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad qcontext
	XmlQueryContext bad_qcontext;
        dbret = jaldb_purge_audit(context, txn, uc, bad_qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//empty query
        dbret = jaldb_purge_audit(context, txn, uc, qcontext, "", docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad query
        dbret = jaldb_purge_audit(context, txn, uc, qcontext, "this is a bad query", docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

}

extern "C" void test_jaldb_purge_audit_by_sid_success()
{
	enum jaldb_status dbret;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->audit_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
        dbret = jaldb_purge_audit_by_sid(context, "2", docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
}

extern "C" void test_jaldb_purge_audit_by_sid_success_force_off()
{
	enum jaldb_status dbret;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

	dbret = jaldb_mark_audit_synced(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_audit_sent_ok(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_audit_synced(context, "3", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->audit_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
	//with force off, only the second entry should be removed
        dbret = jaldb_purge_audit_by_sid(context, "3", docs, 0, 1);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
}

extern "C" void test_jaldb_purge_audit_by_sid_fails_with_bad_input()
{
	enum jaldb_status dbret;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->audit_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	//null context
        dbret = jaldb_purge_audit_by_sid(NULL, "2", docs, 1, 1);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//null ssid
        dbret = jaldb_purge_audit_by_sid(context, NULL, docs, 1, 1);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//these should return successfully but should not remove any entries
	//empty ssid
        dbret = jaldb_purge_audit_by_sid(context, "", docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());

	//negative ssid
        dbret = jaldb_purge_audit_by_sid(context, "-1", docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
}

extern "C" void test_jaldb_purge_audit_by_uuid_success()
{
	enum jaldb_status dbret;
        string sid = "abc";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
        string src = "1.2.3.4";

	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

	dbret = jaldb_mark_audit_synced(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_audit_sent_ok(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_audit_synced(context, "3", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->audit_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);
        qcontext.setVariableValue(JALDB_UUID_VAR, uuid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	//list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	assert_equals(1, docs.begin() != docs.end());
	clear_docs(docs);

        dbret = jaldb_purge_audit_by_uuid(context, uuid.c_str(), docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.begin() != docs.end());
	/*cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());*/
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
        assert_equals(JALDB_OK, dbret);
	assert_equals(docs.begin(), docs.end());
	clear_docs(docs);
}

extern "C" void test_jaldb_purge_audit_by_uuid_success_force_off()
{
	enum jaldb_status dbret;
        string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

	dbret = jaldb_mark_audit_synced(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_audit_sent_ok(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_audit_synced(context, "3", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->audit_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);
        qcontext.setVariableValue(JALDB_UUID_VAR, uuid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
	//with force off, only the second entry should be removed
        dbret = jaldb_purge_audit_by_uuid(context, uuid.c_str(), docs, 0, 1);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
}

extern "C" void test_jaldb_purge_audit_by_uuid_fails_with_bad_input()
{
	enum jaldb_status dbret;
        string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( context, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->audit_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);
        qcontext.setVariableValue(JALDB_UUID_VAR, uuid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	//null context
        dbret = jaldb_purge_audit_by_uuid(NULL, "2", docs, 1, 1);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//null uuid
        dbret = jaldb_purge_audit_by_uuid(context, NULL, docs, 1, 1);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//these should return successfully but should not remove any entries
	//empty uuid
        dbret = jaldb_purge_audit_by_uuid(context, "", docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());

	//bad uuid
        dbret = jaldb_purge_audit_by_uuid(context, "-1", docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
}

extern "C" void test_jaldb_purge_journal_success()
{
	enum jaldb_status dbret;

	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	char *path_1 = NULL;
	char *path_2 = NULL;
	int fd = -1;
	int rc = 0;

	dbret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	sid = "def";
	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);


        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->journal_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);

	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
        dbret = jaldb_purge_journal(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs, 1);
        assert_equals(JALDB_OK, dbret);
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(true, docs.empty());

	free(path_1);
	free(path_2);
}

extern "C" void test_jaldb_purge_journal_success_no_delete()
{
	enum jaldb_status dbret;

	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	char *path_1 = NULL;
	char *path_2 = NULL;
	int fd = -1;
	int rc = 0;

	dbret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	sid = "def";
	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);


        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->journal_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);

	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
        dbret = jaldb_purge_journal(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs, 1);
        assert_equals(JALDB_OK, dbret);
	clear_docs(docs);

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(true, docs.empty());

	free(path_1);
	free(path_2);
}

extern "C" void test_jaldb_purge_journal_fails_with_bad_input()
{
	enum jaldb_status dbret;

	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	char *path_1 = NULL;
	char *path_2 = NULL;
	int fd = -1;
	int rc = 0;

	dbret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	sid = "def";
	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);


        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->journal_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;

	//null jaldb context
        dbret = jaldb_purge_audit(NULL, txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad jaldb context
	jaldb_context *null_ctx = NULL;
        dbret = jaldb_purge_audit(null_ctx, txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad txn
	XmlTransaction bad_txn;
        dbret = jaldb_purge_audit(context, bad_txn, uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad uc
	XmlUpdateContext bad_uc;
        dbret = jaldb_purge_audit(context, txn, bad_uc, qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad qcontext
	XmlQueryContext bad_qcontext;
        dbret = jaldb_purge_audit(context, txn, uc, bad_qcontext, JALDB_FIND_SYNCED_AND_SENT_BY_SID_QUERY, docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//empty query
        dbret = jaldb_purge_audit(context, txn, uc, qcontext, "", docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//bad query
        dbret = jaldb_purge_audit(context, txn, uc, qcontext, "this is a bad query", docs, 0);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	free(path_1);
	free(path_2);
}

extern "C" void test_jaldb_purge_journal_by_sid_success()
{
	enum jaldb_status dbret;

	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	char *path_1 = NULL;
	char *path_2 = NULL;
	int fd = -1;
	int rc = 0;

	dbret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	sid = "def";
	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);


        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->journal_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);

	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
        dbret = jaldb_purge_journal_by_sid(context, "2", docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	
	clear_docs(docs);

	free(path_1);
	free(path_2);
}

extern "C" void test_jaldb_purge_journal_by_sid_success_force_off()
{
	enum jaldb_status dbret;

	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	char *path_1 = NULL;
	char *path_2 = NULL;
	char *path_3 = NULL;
	int fd = -1;
	int rc = 0;

	dbret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_3, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_3);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_3, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_mark_journal_synced(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_journal_sent_ok(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_journal_synced(context, "3", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->journal_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);

	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	//only the second entry was marked synced and sent
	clear_docs(docs);
        dbret = jaldb_purge_journal_by_sid(context, "3", docs, 0, 1);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);

	free(path_1);
	free(path_2);
	free(path_3);
}

extern "C" void test_jaldb_purge_journal_by_sid_fails_with_bad_input()
{
	enum jaldb_status dbret;

	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	char *path_1 = NULL;
	char *path_2 = NULL;
	int fd = -1;
	int rc = 0;

	dbret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	sid = "def";
	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);


        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->journal_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);

	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	//null context
        dbret = jaldb_purge_journal_by_sid(NULL, "2", docs, 1, 1);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//null sid
        dbret = jaldb_purge_journal_by_sid(context, NULL, docs, 1, 1);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//empty sid
        dbret = jaldb_purge_journal_by_sid(context, "", docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());

	//negative sid
        dbret = jaldb_purge_journal_by_sid(context, "-1", docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());
	

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_SID_QUERY, docs);
	cur = docs.begin();
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
	free(path_1);
	free(path_2);
}

extern "C" void test_jaldb_purge_journal_by_uuid_success()
{
	enum jaldb_status dbret;

	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	char *path_1 = NULL;
	char *path_2 = NULL;
	int fd = -1;
	int rc = 0;

	dbret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	sid = "def";
	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_mark_journal_synced(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_journal_sent_ok(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_journal_synced(context, "3", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);


        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->journal_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);
        qcontext.setVariableValue(JALDB_UUID_VAR, uuid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);
	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
        dbret = jaldb_purge_journal_by_uuid(context, uuid.c_str(), docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(1, docs.begin() == docs.end());
	
	clear_docs(docs);

	free(path_1);
	free(path_2);
}

extern "C" void test_jaldb_purge_journal_by_uuid_success_force_off()
{
	enum jaldb_status dbret;

	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	char *path_1 = NULL;
	char *path_2 = NULL;
	char *path_3 = NULL;
	int fd = -1;
	int rc = 0;

	dbret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_3, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_3);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_3, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_mark_journal_synced(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_journal_sent_ok(context, "2", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);
	dbret = jaldb_mark_journal_synced(context, "3", "127.0.0.1");
	assert_equals(JALDB_OK, dbret);

        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->journal_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);
        qcontext.setVariableValue(JALDB_UUID_VAR, uuid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);

	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
	//only 1 file was synced and sent and forced is off
        dbret = jaldb_purge_journal_by_uuid(context, uuid.c_str(), docs, 0, 1);
        assert_equals(JALDB_OK, dbret);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);
	
	//non synced files should remain
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);

	free(path_1);
	free(path_2);
	free(path_3);
}

extern "C" void test_jaldb_purge_journal_by_uuid_fails_with_bad_input()
{
	enum jaldb_status dbret;

	string sid = "abc";
	string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	string msg = "foobar";
	char *path_1 = NULL;
	char *path_2 = NULL;
	int fd = -1;
	int rc = 0;

	dbret = jaldb_create_journal_file(context, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_create_journal_file(context, &path_2, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_2);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), strlen(msg.c_str()) + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	sid = "def";
	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);

	dbret = jaldb_insert_journal_metadata(context, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_2, sid);
	assert_equals(JALDB_OK, dbret);


        XmlQueryContext qcontext = context->manager->createQueryContext();
        qcontext.setDefaultCollection(context->journal_sys_cont->getName());
        qcontext.setVariableValue(JALDB_SID_VAR, sid);
        qcontext.setVariableValue(JALDB_UUID_VAR, uuid);

        XmlTransaction txn = context->manager->createTransaction();
        XmlUpdateContext uc = context->manager->createUpdateContext();

        list<jaldb_doc_info> docs;
	list<jaldb_doc_info>::iterator cur;
	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	assert_equals(JALDB_OK, dbret);

	//check the list
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());
	clear_docs(docs);

	//null context
        dbret = jaldb_purge_journal_by_uuid(NULL, "2", docs, 1, 1);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//null sid
        dbret = jaldb_purge_journal_by_uuid(context, NULL, docs, 1, 1);
        assert_equals(JALDB_E_INVAL, dbret);
	assert_equals(1, docs.empty());

	//empty sid
        dbret = jaldb_purge_journal_by_uuid(context, "", docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());

	//negative sid
        dbret = jaldb_purge_journal_by_uuid(context, "-1", docs, 1, 1);
        assert_equals(JALDB_OK, dbret);
	assert_equals(1, docs.empty());
	

	dbret = jaldb_get_docs_to_purge(context, txn, uc, qcontext, JALDB_FIND_ALL_BY_UUID_QUERY, docs);
	cur = docs.begin();
	cur = docs.begin();
	assert_equals(0, strcmp(cur->sid, "1"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "2"));
	cur++;
	assert_equals(0, strcmp(cur->sid, "3"));
	cur++;
	assert_equals(1, cur == docs.end());

	clear_docs(docs);
	free(path_1);
	free(path_2);
}



/*
 
jaldb_purge_log
jaldb_purge_audit
jaldb_purge_journal
jaldb_purge_log_by_sid
jaldb_purge_audit_by_sid
jaldb_purge_journal_by_sid
jaldb_purge_log_by_uuid
jaldb_purge_audit_by_uuid
jaldb_purge_journal_by_uuid
*/


