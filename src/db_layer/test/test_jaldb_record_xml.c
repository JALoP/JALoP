/**
 * @file test_jaldb_record_xml.c This file contains functions to test
 * jaldb_record_xml.
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

#include <jalop/jal_namespaces.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xmlschemastypes.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <test-dept.h>

#include "jaldb_record.h"
#include "jaldb_record_xml.h"
#include "jaldb_segment.h"

#include "xml_test_utils2.h"

struct jaldb_record rec;
struct jaldb_segment app_meta;
struct jaldb_segment payload;

#define HOSTNAME "some.host.name.com"
#define SOURCE "localhost"
#define TIMESTAMP "2012-11-10T10:09:08Z"
#define USERNAME "some user"
#define SEC_LABEL "sec:context"
#define HOST_UUID "fedbcba9-1234-5678-abcd-fedcba987654"
#define REC_UUID  "01234567-1234-5678-abcd-fedcba987654"
#define JID "UUID-" REC_UUID
#define PID_STR "1234"
#define UID_STR "5678"

void setup()
{
	memset(&rec, 0, sizeof(rec));
	memset(&app_meta, 0, sizeof(app_meta));
	memset(&payload, 0, sizeof(payload));
	rec.pid = 1234;
	rec.uid = 5678;
	rec.source = SOURCE;
	rec.hostname = HOSTNAME;
	rec.timestamp = TIMESTAMP;
	rec.username = USERNAME;
	rec.sec_lbl = SEC_LABEL;
	rec.have_uid = 1;
	rec.version = 1;
	rec.payload = jaldb_create_segment();
	assert_equals(0, uuid_parse(REC_UUID, rec.uuid));
	assert_equals(0, uuid_parse(HOST_UUID, rec.host_uuid));
}

void teardown()
{
	jaldb_destroy_segment(&rec.payload);
	xmlCleanupParser();
}

#define VERIFY_DOC(rtype, have_sec_lbl, have_uid) \
do { \
	enum jaldb_status ret; \
	char* dbuf = NULL; \
	size_t dbufsz = 0; \
	xmlDocPtr doc; \
	ret = jaldb_record_to_system_metadata_doc(&rec, &dbuf, &dbufsz); \
	assert_equals(JALDB_OK, ret); \
	assert_not_equals((void*) NULL, dbuf); \
	assert_not_equals(0, dbufsz); \
 \
	doc = xmlReadMemory(dbuf, dbufsz, "sys_meta.xml", NULL, 0); \
	assert_not_equals((void*) NULL, doc); \
	assert_equals(0, validate(doc, "sys_meta.xml", TEST_XML_SYS_META_SCHEMA, 0)); \
	xmlXPathContextPtr ctx; \
	xmlXPathObjectPtr obj; \
	ctx = xmlXPathNewContext(doc); \
	assert_not_equals((void*) NULL, ctx); \
	assert_equals(0, xmlXPathRegisterNs(ctx, BAD_CAST "j", BAD_CAST JAL_SYS_META_NAMESPACE_URI)); \
	assert_equals(0, xmlXPathRegisterNs(ctx, BAD_CAST "d", BAD_CAST JAL_XMLDSIG_URI)); \
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/@JID='"JID"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_true(obj->boolval); \
	xmlXPathFreeObject(obj); \
\
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/j:JALDataType='"#rtype"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_true(obj->boolval); \
	xmlXPathFreeObject(obj); \
\
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/j:RecordID='"REC_UUID"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_true(obj->boolval); \
	xmlXPathFreeObject(obj); \
\
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/j:Hostname='"HOSTNAME"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_true(obj->boolval); \
	xmlXPathFreeObject(obj); \
\
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/j:HostUUID='"HOST_UUID"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_true(obj->boolval); \
	xmlXPathFreeObject(obj); \
\
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/j:Timestamp='"TIMESTAMP"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_true(obj->boolval); \
	xmlXPathFreeObject(obj); \
\
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/j:ProcessID='"PID_STR"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_true(obj->boolval); \
	xmlXPathFreeObject(obj); \
\
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/j:User/@name='"USERNAME"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_true(obj->boolval); \
	xmlXPathFreeObject(obj); \
\
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/j:User='"UID_STR"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_equals(have_uid, obj->boolval); \
	xmlXPathFreeObject(obj); \
\
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/j:SecurityLabel='"SEC_LABEL"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_equals(have_sec_lbl, obj->boolval); \
	xmlXPathFreeObject(obj); \
	xmlXPathFreeContext(ctx); \
	xmlFreeDoc(doc); \
	free(dbuf); \
} while(0)

void test_to_system_works_for_journal()
{

	rec.type = JALDB_RTYPE_JOURNAL;

	VERIFY_DOC(journal, 1, 1);
}

void test_to_system_works_for_audit()
{

	rec.type = JALDB_RTYPE_AUDIT;

	VERIFY_DOC(audit, 1, 1);
}

void test_to_system_works_for_log()
{

	rec.type = JALDB_RTYPE_LOG;

	VERIFY_DOC(log, 1, 1);
}

void test_to_system_works_without_sec_label()
{
	rec.type = JALDB_RTYPE_LOG;
	rec.sec_lbl = NULL;

	VERIFY_DOC(log, 0, 1);
}

void test_to_system_works_without_uid()
{

	rec.type = JALDB_RTYPE_LOG;
	rec.have_uid = 0;

	VERIFY_DOC(log, 1, 0);
}

void test_to_system_fails_with_bad_input()
{
	enum jaldb_status ret;
	char* dbuf = NULL;
	size_t dbufsz = 0;

	ret = jaldb_record_to_system_metadata_doc(NULL, &dbuf, &dbufsz);
	assert_not_equals(JALDB_OK, ret);
	ret = jaldb_record_to_system_metadata_doc(&rec, NULL, &dbufsz);
	assert_not_equals(JALDB_OK, ret);
	ret = jaldb_record_to_system_metadata_doc(&rec, &dbuf, NULL);
	assert_not_equals(JALDB_OK, ret);

	dbuf = (void*) 0xdeadbeef;
	ret = jaldb_record_to_system_metadata_doc(&rec, &dbuf, &dbufsz);
	dbuf = NULL;
	assert_not_equals(JALDB_OK, ret);

	rec.type = JALDB_RTYPE_UNKNOWN;
	ret = jaldb_record_to_system_metadata_doc(&rec, &dbuf, &dbufsz);
	assert_not_equals(JALDB_OK, ret);
}
