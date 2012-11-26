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

