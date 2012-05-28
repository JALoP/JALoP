/**
 * @file test_jaldb_query.c This file contains functions to test jaldb_query.c.
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
#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif

#include <db.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <test-dept.h>
#include <time.h>
#include <unistd.h>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "test_utils.h"
#include "jaldb_query.hpp"
#include "jaldb_status.h"
#include "jaldb_context.hpp"
#include "xml_test_utils.hpp"
#include "jaldb_serial_id.hpp"
#include "jaldb_xml_doc_storage.hpp"

#include <xercesc/dom/DOM.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/util/PlatformUtils.hpp>
#include <dbxml/DbXml.hpp>
#include <dbxml/XmlContainer.hpp>

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
#include "xml_test_utils.hpp"

#define OTHER_DB_ROOT "./testdb/"
#define OTHER_SCHEMAS_ROOT "./schemas/"
#define JOURNAL_ROOT "/journal/"
#define AUDIT_SYS_TEST_XML_DOC "./test-input/system-metadata.xml"
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

using namespace DbXml;
//static DB_ENV *env = NULL;
static DB *dbase = NULL;
static jaldb_context *ctx = NULL;

static DOMLSParser *parser = NULL;
static DOMDocument *audit_sys_meta_doc = NULL;
static DOMDocument *audit_app_meta_doc = NULL;
static DOMDocument *audit_doc = NULL;
static DOMDocument *log_sys_meta_doc = NULL;
static DOMDocument *log_app_meta_doc = NULL;

extern "C" time_t time_always_fails(__attribute__((unused)) time_t *timer)
{
	return -1;
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
	audit_sys_meta_doc = parser->parseURI(AUDIT_SYS_TEST_XML_DOC);
	audit_app_meta_doc = parser->parseURI(AUDIT_APP_TEST_XML_DOC);
	audit_doc = parser->parseURI(AUDIT_TEST_XML_DOC);
	log_sys_meta_doc = parser->parseURI(LOG_SYS_TEST_XML_DOC);
	log_app_meta_doc = parser->parseURI(LOG_APP_TEST_XML_DOC);
	ctx = jaldb_context_create();
        jaldb_context_init(ctx, OTHER_DB_ROOT, OTHER_SCHEMAS_ROOT, false);
}

extern "C" void teardown()
{
	if (dbase) {
		dbase->close(dbase, 0);
	}
	dbase = NULL;

	delete parser;
	parser = NULL;
	audit_sys_meta_doc = NULL;
	audit_app_meta_doc = NULL;
	audit_doc = NULL;
	log_sys_meta_doc = NULL;
	log_app_meta_doc = NULL;
	jaldb_context_destroy(&ctx);
	ctx = NULL;
	XMLPlatformUtils::Terminate();
}

/////////////////jaldb_log_xquery_helper////////////////////////////////////
extern "C" void test_jaldb_log_xquery_helper_fails_null_input()
{
	char * initialized_result = strdup("foo");
	char * bak = strdup(initialized_result);
	char * result = NULL;
	jaldb_context *bad_ctx = NULL;
	enum jaldb_status ret;

	//NULL result
	ret = jaldb_xquery_helper(ctx, "query", "collection", NULL);
	assert_equals(JALDB_E_INVAL, ret);
	assert_equals(result, NULL);

	//initialized result
	ret = jaldb_xquery_helper(ctx, "query", "collection", &initialized_result);
	assert_equals(ret, JALDB_E_INVAL);
	assert_equals(0, strcmp(initialized_result, bak));

	//NULL context
	ret = jaldb_xquery_helper(bad_ctx, "query", "collection", &result);
	assert_equals(ret, JALDB_E_INVAL);
	assert_equals(result, NULL);

	//NULL query
	ret = jaldb_xquery_helper(ctx, NULL, "collection", &result);
	assert_equals(ret, JALDB_E_INVAL);
	assert_equals(result, NULL);

	//NULL collection
	ret = jaldb_xquery_helper(bad_ctx, "query", NULL, &result);
	assert_equals(ret, JALDB_E_INVAL);
	assert_equals(result, NULL);

	free(initialized_result);
	free(bak);
	free(result);
}

extern "C" void test_jaldb_log_xquery_helper_success_not_found()
{
	enum jaldb_status ret;
	int ret_val;
        char *xquery;
	char *result = NULL;

	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

        ret_val = jal_asprintf(&xquery, JALDB_QUERY_FORMAT, JALDB_LOG_SYS_META_CONT_NAME, JALDB_UUID_WHERE_CLAUSE, uuid.c_str());
	assert_equals(ret_val > 0, 1);
        ret = jaldb_xquery_helper(ctx, xquery, NULL, &result);

	assert_equals(ret, JALDB_E_NOT_FOUND);
        free(xquery);
	free(result);
}

extern "C" void test_jaldb_log_xquery_helper_success_entry_found_uuid()
{
	enum jaldb_status ret;
	int ret_val;
	int db_err;
        char *xquery;
	char *result = NULL;

	string sid = "1";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	ret = jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(ret, JALDB_OK);
	ret = jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(ret, JALDB_OK);
	ret = jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(ret, JALDB_OK);

        ret_val = jal_asprintf(&xquery, JALDB_QUERY_FORMAT, JALDB_LOG_SYS_META_CONT_NAME, JALDB_UUID_WHERE_CLAUSE, uuid.c_str());
	assert_equals(ret_val > 0, 1);
        ret = jaldb_xquery_helper(ctx, xquery, NULL, &result);
	assert_equals(ret, JALDB_OK);

        free(xquery);
	free(result);
}

extern "C" void test_jaldb_log_xquery_helper_success_entry_found_uuid_with_collection()
{
	enum jaldb_status ret;
	int ret_val;
	int db_err;
        char *xquery;
	char *result = NULL;

	string sid = "1";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	ret = jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(ret, JALDB_OK);
	ret = jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(ret, JALDB_OK);
	ret = jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	assert_equals(ret, JALDB_OK);

        ret_val = jal_asprintf(&xquery, JALDB_QUERY_FORMAT, JALDB_LOG_SYS_META_CONT_NAME, JALDB_UUID_WHERE_CLAUSE, uuid.c_str());
	assert_equals(ret_val > 0, 1);
        ret = jaldb_xquery_helper(ctx, xquery, ctx->audit_sys_cont->getName().c_str(), &result);
	assert_equals(ret, JALDB_OK);

        free(xquery);
	free(result);
}

extern "C" void test_jaldb_log_xquery_helper_success_entry_found_SID()
{
	enum jaldb_status ret;
	int ret_val;
	int db_err;
        char *xquery;
	char *result = NULL;

	string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

        ret_val = jal_asprintf(&xquery, JALDB_QUERY_FORMAT, JALDB_LOG_SYS_META_CONT_NAME, JALDB_SID_WHERE_CLAUSE, sid.c_str());
	assert_equals(ret_val > 0, 1);
        ret = jaldb_xquery_helper(ctx, xquery, NULL, &result);
	assert_equals(ret, JALDB_OK);

        free(xquery);
	free(result);
}

////////////////////////////jaldb_query_journal_sid///////////////////////////
extern "C" void test_jaldb_query_journal_sid_fails_null_input()
{
	char * initialized_result = strdup("foo");
        char * bak = strdup(initialized_result);
        char * result = NULL;
        jaldb_context *bad_ctx = NULL;
        enum jaldb_status ret;

	//null context
	ret = jaldb_query_journal_sid(bad_ctx, "abc", &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	//null sid
	ret = jaldb_query_journal_sid(ctx, NULL, &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);
	
	//initialized result
	ret = jaldb_query_journal_sid(ctx, "abc", &initialized_result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(0, strcmp(initialized_result, bak));

	//NULL result
	ret = jaldb_query_journal_sid(ctx, "abc", NULL);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	free(initialized_result);
	free(bak);
	free(result);

}

extern "C" void test_jaldb_query_journal_sid_success()
{
	string sid = "";
	string src = "1.2.3.4";
	string msg = "foobar";
        char * result = NULL;
	char *path_1 = NULL;
	int fd = -1;
	int rc = 0;
	int dbret = 0;
	enum jaldb_status ret;

	dbret = jaldb_create_journal_file(ctx, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(ctx, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	ret = jaldb_query_journal_sid(ctx, sid.c_str(), &result);
	assert_equals(ret, JALDB_OK);

	free(result);
	free(path_1);
}

extern "C" void test_jaldb_query_journal_sid_not_found()
{
	string sid = "abc";
        char * result = NULL;
	enum jaldb_status ret;

	ret = jaldb_query_journal_sid(ctx, sid.c_str(), &result);
	assert_equals(ret, JALDB_E_NOT_FOUND);
	assert_equals(result, NULL);
}

extern "C" void test_jaldb_query_journal_sid_not_found_with_other_records()
{
	string sid = "abc";
        char * result = NULL;
	enum jaldb_status ret;
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	int db_err;

	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

	ret = jaldb_query_journal_sid(ctx, sid.c_str(), &result);
	assert_equals(ret, JALDB_E_NOT_FOUND);
	assert_equals(result, NULL);

	free(result);
}

///////////////////////jaldb_query_audit_sid////////////////////////////////////
extern "C" void test_jaldb_query_audit_sid_fails_null_input()
{
	char * initialized_result = strdup("foo");
        char * bak = strdup(initialized_result);
        char * result = NULL;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
        jaldb_context *bad_ctx = NULL;
        enum jaldb_status ret;

	//null context
	ret = jaldb_query_audit_sid(bad_ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	//null sid
	ret = jaldb_query_audit_sid(ctx, NULL, &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);
	
	//initialized result
	ret = jaldb_query_audit_sid(ctx, uuid.c_str(), &initialized_result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(0, strcmp(initialized_result, bak));

	//NULL result
	ret = jaldb_query_audit_sid(ctx, uuid.c_str(), NULL);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	free(initialized_result);
	free(bak);
	free(result);
}

extern "C" void test_jaldb_query_audit_sid_success()
{
        char * result = NULL;
        enum jaldb_status ret;

        string sid = "";
        string src = "1.2.3.4";

	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

	ret = jaldb_query_audit_sid(ctx, sid.c_str(), &result);
	assert_equals(JALDB_OK, ret);
        assert_equals(1, result != NULL);

	free(result);
}

extern "C" void test_jaldb_query_audit_sid_not_found()
{
        char * result = NULL;
        enum jaldb_status ret;

        string sid = "abc";

	ret = jaldb_query_audit_sid(ctx, sid.c_str(), &result);
	assert_equals(JALDB_E_NOT_FOUND, ret);
        assert_equals(result, NULL);

	free(result);
}

extern "C" void test_jaldb_query_audit_sid_not_found_with_other_records()
{
        char * result = NULL;
        enum jaldb_status ret;
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	int db_err;
	string msg = "foobar";
	char *path_1 = NULL;
	int fd = -1;
	int rc = 0;
	int dbret = 0;

        string sid = "abc";
	dbret = jaldb_create_journal_file(ctx, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(ctx, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

	ret = jaldb_query_audit_sid(ctx, sid.c_str(), &result);
	assert_equals(JALDB_E_NOT_FOUND, ret);
        assert_equals(result, NULL);

	free(result);
	free(path_1);
}

///////////////////////jaldb_query_log_sid////////////////////////////////////
extern "C" void test_jaldb_query_log_sid_fails_null_input()
{
	char * initialized_result = strdup("foo");
        char * bak = strdup(initialized_result);
        char * result = NULL;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
        jaldb_context *bad_ctx = NULL;
        enum jaldb_status ret;

	//null context
	ret = jaldb_query_log_sid(bad_ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	//null sid
	ret = jaldb_query_log_sid(ctx, NULL, &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);
	
	//initialized result
	ret = jaldb_query_log_sid(ctx, uuid.c_str(), &initialized_result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(0, strcmp(initialized_result, bak));

	//NULL result
	ret = jaldb_query_log_sid(ctx, uuid.c_str(), NULL);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	free(initialized_result);
	free(bak);
	free(result);
}

extern "C" void test_jaldb_query_log_sid_success()
{
        char * result = NULL;
        enum jaldb_status ret;
	int db_err;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

	ret = jaldb_query_log_sid(ctx, sid.c_str(), &result);
	assert_equals(JALDB_OK, ret);
        assert_equals(1, result != NULL);

	free(result);
}

extern "C" void test_jaldb_query_log_sid_not_found()
{
        char * result = NULL;
        enum jaldb_status ret;
        string sid = "abc";

	ret = jaldb_query_log_sid(ctx, sid.c_str(), &result);
	assert_equals(JALDB_E_NOT_FOUND, ret);
        assert_equals(result, NULL);

	free(result);
}

extern "C" void test_jaldb_query_log_sid_not_found_with_other_records()
{
        char * result = NULL;
        enum jaldb_status ret;
        string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	char *path_1 = NULL;
	int fd = -1;
	int rc = 0;
	int dbret = 0;

	dbret = jaldb_create_journal_file(ctx, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(ctx, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

	ret = jaldb_query_log_sid(ctx, sid.c_str(), &result);
	assert_equals(JALDB_E_NOT_FOUND, ret);
        assert_equals(result, NULL);

	free(result);
	free(path_1);
}

////////////////////////jaldb_query_journal_uuid/////////////////////////////
extern "C" void test_jaldb_query_journal_uuid_fails_null_input()
{
	char * initialized_result = strdup("foo");
        char * bak = strdup(initialized_result);
        char * result = NULL;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
        jaldb_context *bad_ctx = NULL;
        enum jaldb_status ret;

	//null context
	ret = jaldb_query_journal_uuid(bad_ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	//null sid
	ret = jaldb_query_journal_uuid(ctx, NULL, &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);
	
	//initialized result
	ret = jaldb_query_journal_uuid(ctx, uuid.c_str(), &initialized_result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(0, strcmp(initialized_result, bak));

	//NULL result
	ret = jaldb_query_journal_uuid(ctx, uuid.c_str(), NULL);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	free(initialized_result);
	free(result);
	free(bak);

}

extern "C" void test_jaldb_query_journal_uuid_success()
{
        char * result = NULL;
        enum jaldb_status ret;
	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	char *path_1 = NULL;
	int fd = -1;
	int rc = 0;
	int dbret = 0;

	dbret = jaldb_create_journal_file(ctx, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(ctx, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);


	ret = jaldb_query_journal_uuid(ctx, uuid.c_str(), &result);
	assert_equals(JALDB_OK, ret);
        assert_equals(1, result != NULL);

	free(result);
	free(path_1);

}

extern "C" void test_jaldb_query_journal_uuid_not_found()
{
        char * result = NULL;
        enum jaldb_status ret;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	ret = jaldb_query_journal_uuid(ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_NOT_FOUND, ret);
        assert_equals(result,  NULL);

}

extern "C" void test_jaldb_query_journal_uuid_not_found_with_other_records()
{
        char * result = NULL;
        enum jaldb_status ret;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	string sid = "abc";
        string src = "1.2.3.4";
	int db_err;

	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

	ret = jaldb_query_journal_uuid(ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_NOT_FOUND, ret);
        assert_equals(result,  NULL);

}

////////////////////////jaldb_query_audit_uuid/////////////////////////////
extern "C" void test_jaldb_query_audit_uuid_fails_null_input()
{
	char * initialized_result = strdup("foo");
        char * bak = strdup(initialized_result);
        char * result = NULL;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
        jaldb_context *bad_ctx = NULL;
        enum jaldb_status ret;

	//null context
	ret = jaldb_query_audit_uuid(bad_ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	//null sid
	ret = jaldb_query_audit_uuid(ctx, NULL, &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);
	
	//initialized result
	ret = jaldb_query_audit_uuid(ctx, uuid.c_str(), &initialized_result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(0, strcmp(initialized_result, bak));

	//NULL result
	ret = jaldb_query_audit_uuid(ctx, uuid.c_str(), NULL);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	free(initialized_result);
	free(bak);
	free(result);
}

extern "C" void test_jaldb_query_audit_uuid_success()
{
        char * result = NULL;
        enum jaldb_status ret;

        string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);


	ret = jaldb_query_audit_uuid(ctx, uuid.c_str(), &result);
	assert_equals(JALDB_OK, ret);
        assert_equals(1, result != NULL);

	free(result);
}

extern "C" void test_jaldb_query_audit_uuid_not_found()
{
        char * result = NULL;
        enum jaldb_status ret;

        string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	ret = jaldb_query_audit_uuid(ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_NOT_FOUND, ret);
        assert_equals(result, NULL);
}

extern "C" void test_jaldb_query_audit_uuid_not_found_with_other_records()
{
        char * result = NULL;
        enum jaldb_status ret;

        string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	int db_err;
	string msg = "foobar";
	char *path_1 = NULL;
	int fd = -1;
	int rc = 0;
	int dbret = 0;

	dbret = jaldb_create_journal_file(ctx, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(ctx, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

	ret = jaldb_query_audit_uuid(ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_NOT_FOUND, ret);
        assert_equals(result, NULL);

	free(path_1);
}


////////////////////////jaldb_query_log_uuid/////////////////////////////
extern "C" void test_jaldb_query_log_uuid_fails_null_input()
{
	char * initialized_result = strdup("foo");
        char * bak = strdup(initialized_result);
        char * result = NULL;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
        jaldb_context *bad_ctx = NULL;
        enum jaldb_status ret;

	//null context
	ret = jaldb_query_log_uuid(bad_ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	//null sid
	ret = jaldb_query_log_uuid(ctx, NULL, &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);
	
	//initialized result
	ret = jaldb_query_log_uuid(ctx, uuid.c_str(), &initialized_result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(0, strcmp(initialized_result, bak));

	//NULL result
	ret = jaldb_query_log_uuid(ctx, uuid.c_str(), NULL);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	free(initialized_result);
	free(bak);
	free(result);
}

extern "C" void test_jaldb_query_log_uuid_success()
{
        char * result = NULL;
        enum jaldb_status ret;
	int db_err;
	string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);

	ret = jaldb_query_log_uuid(ctx, uuid.c_str(), &result);
	assert_equals(JALDB_OK, ret);
        assert_equals(1, result != NULL);

	free(result);
}

extern "C" void test_jaldb_query_log_uuid_not_found()
{
        char * result = NULL;
        enum jaldb_status ret;
	string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	ret = jaldb_query_log_uuid(ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_NOT_FOUND, ret);
        assert_equals(result,  NULL);

	free(result);
}

extern "C" void test_jaldb_query_log_uuid_not_found_with_other_records()
{
        char * result = NULL;
        enum jaldb_status ret;
	string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	string msg = "foobar";
	char *path_1 = NULL;
	int fd = -1;
	int rc = 0;
	int dbret = 0;

	dbret = jaldb_create_journal_file(ctx, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(ctx, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

	ret = jaldb_query_log_uuid(ctx, uuid.c_str(), &result);
	assert_equals(JALDB_E_NOT_FOUND, ret);
        assert_equals(result,  NULL);

	free(path_1);
}

/////////////////////////jaldb_journal_xquery////////////////////////////////////
extern "C" void test_jaldb_journal_xquery_fails_bad_input()
{
	string query = "This is a query";
	char * initialized_result = strdup("foo");
        char * bak = strdup(initialized_result);
        char * result = NULL;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
        jaldb_context *bad_ctx = NULL;
        enum jaldb_status ret;

	//null context
	ret = jaldb_journal_xquery(bad_ctx, query.c_str(), &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	//null sid
	ret = jaldb_journal_xquery(ctx, NULL, &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);
	
	//initialized result
	ret = jaldb_journal_xquery(ctx, query.c_str(), &initialized_result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(0, strcmp(initialized_result, bak));

	//NULL result
	ret = jaldb_journal_xquery(ctx, query.c_str(), NULL);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	free(initialized_result);
	free(bak);
	free(result);
}

extern "C" void test_jaldb_journal_xquery_success()
{
        char * result = NULL;
        enum jaldb_status ret;
	string sid = "abc";
	string src = "1.2.3.4";
	string msg = "foobar";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
	char *path_1 = NULL;
	int fd = -1;
	int rc = 0;
	int dbret = 0;

	dbret = jaldb_create_journal_file(ctx, &path_1, &fd);
	assert_equals(JALDB_OK, dbret);
	assert_not_equals(NULL, path_1);
	assert_not_equals(-1, fd);
	rc = write(fd, msg.c_str(), msg.length() + 1);
	assert_not_equals(-1, rc);
	close(fd);
	fd = -1;

	dbret = jaldb_insert_journal_metadata(ctx, src,
		audit_sys_meta_doc, audit_app_meta_doc, path_1, sid);
	assert_equals(JALDB_OK, dbret);

        char *xquery;
        rc = jal_asprintf(&xquery, JALDB_QUERY_FORMAT, JALDB_JOURNAL_SYS_META_CONT_NAME, JALDB_UUID_WHERE_CLAUSE, uuid.c_str());
	assert_equals(1, rc > 0);


	ret = jaldb_journal_xquery(ctx, xquery, &result);
	assert_equals(JALDB_OK, ret);
        assert_equals(1, result != NULL);

	free(result);
	free(xquery);
}


//////////////////////////jaldb_audit_xquery/////////////////////////////
extern "C" void test_jaldb_audit_xquery_fails_bad_input()
{
	string query = "This is a query";
	char * initialized_result = strdup("foo");
        char * bak = strdup(initialized_result);
        char * result = NULL;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
        jaldb_context *bad_ctx = NULL;
        enum jaldb_status ret;

	//null context
	ret = jaldb_audit_xquery(bad_ctx, query.c_str(), &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	//null sid
	ret = jaldb_audit_xquery(ctx, NULL, &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);
	
	//initialized result
	ret = jaldb_audit_xquery(ctx, query.c_str(), &initialized_result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(0, strcmp(initialized_result, bak));

	//NULL result
	ret = jaldb_audit_xquery(ctx, query.c_str(), NULL);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	free(initialized_result);
	free(bak);
	free(result);
}


extern "C" void test_jaldb_audit_xquery_success()
{
        char * result = NULL;
        enum jaldb_status ret;
	int rc;

        string sid = "abc";
        string src = "1.2.3.4";
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";

	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);
	jaldb_insert_audit_record( ctx, src, audit_sys_meta_doc, audit_app_meta_doc, 
		audit_doc, sid);

        char *xquery;
        rc = jal_asprintf(&xquery, JALDB_QUERY_FORMAT, JALDB_AUDIT_SYS_META_CONT_NAME, JALDB_UUID_WHERE_CLAUSE, uuid.c_str());
	assert_equals(1, rc > 0);

	ret = jaldb_audit_xquery(ctx, xquery, &result);
	assert_equals(JALDB_OK, ret);
        assert_equals(1, result != NULL);

	free(result);
	free(xquery);
}

///////////////////////////jaldb_log_xquery//////////////////////////
extern "C" void test_jaldb_log_xquery_fails_bad_input()
{
	string query = "This is a query";
	char * initialized_result = strdup("foo");
        char * bak = strdup(initialized_result);
        char * result = NULL;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
        jaldb_context *bad_ctx = NULL;
        enum jaldb_status ret;

	//null context
	ret = jaldb_log_xquery(bad_ctx, query.c_str(), &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	//null sid
	ret = jaldb_log_xquery(ctx, NULL, &result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);
	
	//initialized result
	ret = jaldb_log_xquery(ctx, query.c_str(), &initialized_result);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(0, strcmp(initialized_result, bak));

	//NULL result
	ret = jaldb_log_xquery(ctx, query.c_str(), NULL);
	assert_equals(JALDB_E_INVAL, ret);
        assert_equals(result, NULL);

	free(initialized_result);
	free(bak);
	free(result);
}

extern "C" void test_jaldb_log_xquery_success()
{
        char * result = NULL;
	string uuid = "f9032e9c-7e9a-4f2c-b40e-621b0e66c47f";
        enum jaldb_status ret;
	int rc;
	int db_err;
        string sid = "abc";
        string src = "1.2.3.4";

	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);
	jaldb_insert_log_record( ctx, src.c_str(), log_sys_meta_doc, log_app_meta_doc, 
		(uint8_t*) "foobar", strlen("foobar"), sid, &db_err);


	char * xquery;
	rc = jal_asprintf(&xquery, JALDB_QUERY_FORMAT, JALDB_LOG_SYS_META_CONT_NAME, JALDB_UUID_WHERE_CLAUSE, uuid.c_str());

	ret = jaldb_log_xquery(ctx, xquery, &result);
	assert_equals(JALDB_OK, ret);
        assert_equals(1, result != NULL);

	free(result);
	free(xquery);
}

