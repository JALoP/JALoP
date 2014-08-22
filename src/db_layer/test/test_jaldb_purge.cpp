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
#include <errno.h>
#include <fcntl.h>
#include <db.h>
#include <dirent.h>
#include <inttypes.h>
#include <iostream>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "jal_alloc.h"
#include "jaldb_context.hpp"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "jaldb_purge.hpp"
#include "jaldb_segment.h"

using namespace std;

#define OTHER_DB_ROOT "./testdb/"
#define OTHER_SCHEMA_ROOT "./schemas/"
#define JOURNAL_ROOT "/journal/"
#define AUDIT_SYS_TEST_XML_DOC "./test-input/domwriter_audit_sys.xml"
#define AUDIT_APP_TEST_XML_DOC "./test-input/domwriter_audit_app.xml"
#define AUDIT_TEST_XML_DOC "./test-input/domwriter_audit.xml"
#define LOG_SYS_TEST_XML_DOC "./test-input/system-metadata.xml"
#define LOG_APP_TEST_XML_DOC "./test-input/domwriter_log_app.xml"
#define REMOTE_HOST "remote_host"
#define TEST_XML_DOC "./test-input/domwriter.xml"
#define LOG_DATA_X "Log Buffer\nLog Entry 1\n"
#define LOG_DATA_Y "Log Buffer\nLog Entry 1\nLog Entry 2\n"
#define PAYLOAD "SoMe_data   is here\nMoreData is Here!\n"

#define DT1 "2012-12-12T09:00:00.00000"
#define HN1 "somehost"
#define UN1 "someuser"
#define S1 "source1"
#define UUID_1 "11234567-89AB-CDEF-0123-456789ABCDEF"

#define DT2 "2012-12-12T09:00:00.00000"
#define HN2 "somehost"
#define UN2 "someuser"
#define S2 "source1"
#define UUID_2 "21234567-89AB-CDEF-0123-456789ABCDEF"

#define EXPECTED_RECORD_VERSION 1

static void *audit_sys_meta_doc = NULL;
static void *audit_app_meta_doc = NULL;
static void *audit_doc = NULL;
static void *log_sys_meta_doc = NULL;
static void *log_app_meta_doc = NULL;
static jaldb_context *context = NULL;

void clear_docs( list<jaldb_doc_info> &docs)
{
	list<jaldb_doc_info>::iterator cur = docs.begin();
	while(cur != docs.end())
	{
		if(cur->nonce) {
			free(cur->nonce);
			cur->nonce = NULL;
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
		if (cur->nonce)
			cout << "nonce: " << cur->nonce;
		else
			cout << "nonce: NULL";
		if (cur->uuid)
			cout << " uuid: " << cur->uuid << endl;
		else
			cout << " uuid: NULL" << endl;
		cur++;
	}
}
extern "C" void setup()
{
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
	context = jaldb_context_create();
	jaldb_context_init(context, OTHER_DB_ROOT, OTHER_SCHEMA_ROOT, false);
}

extern "C" void teardown()
{
	audit_sys_meta_doc = NULL;
	audit_app_meta_doc = NULL;
	audit_doc = NULL;
	log_sys_meta_doc = NULL;
	log_app_meta_doc = NULL;
	jaldb_context_destroy(&context);
}

extern "C" void test_jaldb_purge_unconfirmed_records()
{
	jaldb_record *rec_final = NULL;

	jaldb_record *rec1 = jaldb_create_record();
	rec1->version = EXPECTED_RECORD_VERSION;
	rec1->type = JALDB_RTYPE_LOG;	
	rec1->timestamp = jal_strdup(DT1);
	rec1->hostname = jal_strdup(HN1);
	rec1->source = jal_strdup(S1);
	rec1->username = jal_strdup(UN1);
	rec1->payload = jaldb_create_segment();
	assert_equals(0, uuid_parse(UUID_1, rec1->uuid));
	rec1->network_nonce = jal_strdup("NN");

	jaldb_record *rec2 = jaldb_create_record();
	rec2->version = EXPECTED_RECORD_VERSION;
	rec2->type = JALDB_RTYPE_LOG;	
	rec2->timestamp = jal_strdup(DT2);
	rec2->hostname = jal_strdup(HN2);
	rec2->source = jal_strdup(S2);
	rec2->username = jal_strdup(UN2);
	rec2->payload = jaldb_create_segment();
	assert_equals(0, uuid_parse(UUID_2, rec2->uuid));
	rec2->network_nonce = jal_strdup("NN2");
	
	char *nonce = NULL;
	char *nonce2 = NULL;
	char *nonce3 = NULL;

	assert_equals(JALDB_E_INVAL,jaldb_purge_unconfirmed_records(context,"localhost",JALDB_RTYPE_JOURNAL));
	assert_equals(JALDB_E_INVAL,jaldb_purge_unconfirmed_records(context,"1.2.3.4",JALDB_RTYPE_UNKNOWN));
	assert_equals(JALDB_E_INVAL,jaldb_purge_unconfirmed_records(NULL,"1.2.3.4",JALDB_RTYPE_JOURNAL));

	assert_equals(JALDB_OK, jaldb_insert_record(context, rec1, 0, &nonce));
	assert_equals(JALDB_OK, jaldb_insert_record(context, rec2, 0, &nonce2));
	assert_equals(JALDB_OK, jaldb_mark_confirmed(context, JALDB_RTYPE_LOG, (char*)"NN", &nonce3));
	assert_string_equals(nonce,nonce3);

	assert_equals(JALDB_OK, jaldb_purge_unconfirmed_records(context, "1.2.3.4", JALDB_RTYPE_LOG));

	assert_equals(JALDB_OK, jaldb_get_record(context, JALDB_RTYPE_LOG, nonce, &rec_final));

	jaldb_destroy_record(&rec_final);
	rec_final = NULL;

	assert_equals(JALDB_E_NOT_FOUND, jaldb_get_record(context, JALDB_RTYPE_LOG, nonce2, &rec_final));

	jaldb_destroy_record(&rec_final);
	jaldb_destroy_record(&rec1);
	jaldb_destroy_record(&rec2);
	free(nonce);
	free(nonce2);
	free(nonce3);

}
