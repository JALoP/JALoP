/**
* @file test_jsub_db_layer.cpp This file contains functions to test
* jsub_db_layer.cpp.
*
* @section LICENSE
*
* Source code in 3rd-party is licensed and owned by their respective
* copyright holders.
*
* All other source code is copyright Tresys Technology and licensed as below.
*
 * Copyright (c) 2011-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <dirent.h>
#include <sys/stat.h>

#include "jsub_db_layer.hpp"
#include "jaldb_context.hpp"

#define OTHER_DB_ROOT "./jsbu_testdb/"
#define OTHER_SCHEMA_ROOT "./schemas/"
#define PAYLOAD "This Is Some Text!\n"

jaldb_context *db_ctx = NULL;

extern "C" void setup()
{
	struct stat st;
	if (stat(OTHER_DB_ROOT, &st) != 0) {
		mkdir(OTHER_DB_ROOT, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}
	else {
		struct dirent *d;
		DIR *dir;
		char buf[sizeof(OTHER_DB_ROOT) + NAME_MAX + 1];
		dir = opendir(OTHER_DB_ROOT);
		while ((d = readdir(dir)) != NULL) {
			sprintf(buf, "%s/%s", OTHER_DB_ROOT, d->d_name);
			remove(buf);
		}
		closedir(dir);
	}
	db_ctx = jsub_setup_db_layer(OTHER_DB_ROOT, OTHER_SCHEMA_ROOT);
}

extern "C" void teardown()
{
	jsub_teardown_db_layer(&db_ctx);
}
// Not implemented
/*
extern "C" void test_write_journal_works()
{
	char *db_payload_path = NULL;
	int db_payload_fd = -1;
	size_t payload_len = strlen(PAYLOAD);

	int rc = 0;
	rc = jsub_write_journal(db_ctx, &db_payload_path,
				&db_payload_fd, (uint8_t *)PAYLOAD,
				payload_len, 0);
	assert_equals(0, rc);
	rc = jsub_write_journal(db_ctx, &db_payload_path,
				&db_payload_fd, (uint8_t *)PAYLOAD,
				payload_len, 0);
	assert_equals(0, rc);
	rc = jsub_write_journal(db_ctx, &db_payload_path,
				&db_payload_fd, (uint8_t *)PAYLOAD,
				payload_len, 0);
	assert_equals(0, rc);
}
*/
