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
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#include "jal_alloc.h"

#include "jaldb_record.h"
#include "jaldb_record_xml.h"
#include "jaldb_segment.h"

#include "xml_test_utils2.h"

struct jaldb_record rec;
struct jaldb_segment app_meta;
struct jaldb_segment payload;
RSA *key;

#define TEST_RSA_KEY  TEST_INPUT_ROOT "rsa_key"

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
#define GOOD_SYS_META "./test-input/system-metadata.xml"
#define GOOD_SYS_META_CDATA "./test-input/system-metadata-with-cdata.xml"
#define MALFORMED_SYS_META "./test-input/system-metadata-malformed.xml"
#define SIGNATURE "tOpBqUbWFLwxN/IEQVv3VOkzGnuNywqZE1F1ahnbO6SE3hNkeEGofQd9xxcj+uy8\nLOh4FIh0WHpZx8Wz5y29TA=="

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

	SSL_library_init();
	xmlSecInit();

	xmlSecCryptoDLLoadLibrary(BAD_CAST "openssl");

	xmlSecCryptoAppInit(NULL);
	xmlSecCryptoInit();

	key = NULL;
}

void teardown()
{
	jaldb_destroy_segment(&rec.payload);
	xmlCleanupParser();
}

#define VERIFY_DOC(rtype, have_sec_lbl, have_uid, have_sig) \
do { \
	enum jaldb_status ret; \
	char* dbuf = NULL; \
	size_t dbufsz = 0; \
	xmlDocPtr doc; \
	ret = jaldb_record_to_system_metadata_doc(&rec, key, NULL, 0, NULL, NULL, 0, NULL, &dbuf, &dbufsz); \
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
\
	obj = xmlXPathEvalExpression(BAD_CAST "//j:JALRecord/d:Signature/d:SignatureValue='"SIGNATURE"'", ctx); \
	assert_not_equals((void*)NULL, obj); \
	assert_equals(XPATH_BOOLEAN, obj->type); \
	assert_equals(have_sig, obj->boolval); \
	xmlXPathFreeObject(obj); \
	xmlXPathFreeContext(ctx); \
	xmlFreeDoc(doc); \
	free(dbuf); \
} while(0)

void test_to_system_works_for_journal()
{

	rec.type = JALDB_RTYPE_JOURNAL;

	VERIFY_DOC(journal, 1, 1, 0);
}

void test_to_system_works_for_audit()
{

	rec.type = JALDB_RTYPE_AUDIT;

	VERIFY_DOC(audit, 1, 1, 0);
}

void test_to_system_works_for_log()
{

	rec.type = JALDB_RTYPE_LOG;

	VERIFY_DOC(log, 1, 1, 0);
}

void test_to_system_works_without_sec_label()
{
	rec.type = JALDB_RTYPE_LOG;
	rec.sec_lbl = NULL;

	VERIFY_DOC(log, 0, 1, 0);
}

void test_to_system_works_without_uid()
{

	rec.type = JALDB_RTYPE_LOG;
	rec.have_uid = 0;

	VERIFY_DOC(log, 1, 0, 0);
}

void test_to_system_works_with_signing_key()
{
	rec.type = JALDB_RTYPE_LOG;

	FILE *fp = fopen(TEST_RSA_KEY, "r");
	assert_not_equals(NULL, fp);
	key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	VERIFY_DOC(log, 1, 1, 1);
}

void test_to_system_fails_with_bad_input()
{
	enum jaldb_status ret;
	char* dbuf = NULL;
	size_t dbufsz = 0;

	ret = jaldb_record_to_system_metadata_doc(NULL, NULL, NULL, 0, NULL, NULL, 0, NULL, &dbuf, &dbufsz);
	assert_not_equals(JALDB_OK, ret);
	ret = jaldb_record_to_system_metadata_doc(&rec, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL, &dbufsz);
	assert_not_equals(JALDB_OK, ret);
	ret = jaldb_record_to_system_metadata_doc(&rec, NULL, NULL, 0, NULL, NULL, 0, NULL, &dbuf, NULL);
	assert_not_equals(JALDB_OK, ret);

	dbuf = (void*) 0xdeadbeef;
	ret = jaldb_record_to_system_metadata_doc(&rec, NULL, NULL, 0, NULL, NULL, 0, NULL, &dbuf, &dbufsz);
	dbuf = NULL;
	assert_not_equals(JALDB_OK, ret);

	rec.type = JALDB_RTYPE_UNKNOWN;
	ret = jaldb_record_to_system_metadata_doc(&rec, NULL, NULL, 0, NULL, NULL, 0, NULL, &dbuf, &dbufsz);
	assert_not_equals(JALDB_OK, ret);
}

void test_jaldb_xml_to_sys_metadata_works()
{
	struct jaldb_record *sys_meta;
	FILE *fd = fopen(GOOD_SYS_META,"r");
	assert_not_equals(fd,NULL);
	assert_equals(fseek(fd, 0L, SEEK_END),0);
	long bufsize = ftell(fd);
	assert_not_equals(bufsize,-1);
	
	char *buf = jal_calloc(bufsize,sizeof(char));
	assert_not_equals(NULL,buf);
	assert_equals(fseek(fd,0L,SEEK_SET),0);
	assert_not_equals(fread(buf,sizeof(char),bufsize,fd),0);

	assert_equals(JAL_OK,jaldb_xml_to_sys_metadata((uint8_t *)buf,(size_t)bufsize,&sys_meta));
	assert_not_equals(sys_meta,NULL);
	assert_equals(sys_meta->pid,0);
	assert_equals(sys_meta->uid,0);
	assert_string_equals(sys_meta->hostname,"test.jalop.com");
	assert_string_equals(sys_meta->timestamp,"2011-11-10T04:09:55-05:00");
	assert_string_equals(sys_meta->username,"root");
	assert_string_equals(sys_meta->sec_lbl,"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023");
	assert_equals(sys_meta->type,JALDB_RTYPE_JOURNAL);
	
	fclose(fd);
	free(buf);
}

void test_jaldb_xml_to_sys_metadata_works_with_cdata()
{
	struct jaldb_record *sys_meta;
	FILE *fd = fopen(GOOD_SYS_META_CDATA,"r");
	assert_not_equals(fd,NULL);
	assert_equals(fseek(fd, 0L, SEEK_END),0);
	long bufsize = ftell(fd);
	assert_not_equals(bufsize,-1);
	
	char *buf = jal_calloc(bufsize,sizeof(char));
	assert_not_equals(NULL,buf);
	assert_equals(fseek(fd,0L,SEEK_SET),0);
	assert_not_equals(fread(buf,sizeof(char),bufsize,fd),0);

	assert_equals(JAL_OK,jaldb_xml_to_sys_metadata((uint8_t *)buf,(size_t)bufsize,&sys_meta));
	assert_not_equals(sys_meta,NULL);
	assert_equals(sys_meta->pid,0);
	assert_equals(sys_meta->uid,0);
	assert_string_equals(sys_meta->hostname,"test.jalop.com");
	assert_string_equals(sys_meta->timestamp,"2011-11-10T04:09:55-05:00");
	assert_string_equals(sys_meta->username,"root");
	assert_string_equals(sys_meta->sec_lbl,"unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023");
	assert_equals(sys_meta->type,JALDB_RTYPE_JOURNAL);
	
	fclose(fd);
	free(buf);
}

void test_jaldb_xml_to_sys_metadata_returns_error_on_malformed_data()
{
	struct jaldb_record *sys_meta;
	FILE *fd = fopen(MALFORMED_SYS_META,"r");
	assert_not_equals(fd,NULL);
	assert_equals(fseek(fd, 0L, SEEK_END),0);
	long bufsize = ftell(fd);
	assert_not_equals(bufsize,-1);
	
	char *buf = jal_calloc(bufsize,sizeof(char));
	assert_not_equals(NULL,buf);
	assert_equals(fseek(fd,0L,SEEK_SET),0);
	assert_not_equals(fread(buf,sizeof(char),bufsize,fd),0);

	assert_equals(JALDB_E_INVAL,jaldb_xml_to_sys_metadata((uint8_t *)buf,(size_t)bufsize,&sys_meta));
	
	fclose(fd);
	free(buf);
}
