/**
 * @file test_jaldb_serial_id.cpp This file contains functions to test
 * functions related to acquiring a serial id.
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

#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <db.h>
#include "jaldb_serial_id.hpp"
#include "jaldb_context.hpp"
#include "jaldb_strings.h"

#define OTHER_DB_ROOT "./testdb/"
#define INVALID_JALDB_NS "jalop/metadata"
#define INVALID_JALDB_SERIAL_ID_NAME "serial_id"

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
	uint32_t env_flags =
		DB_CREATE |
		DB_INIT_LOCK |
		DB_INIT_LOG |
		DB_INIT_MPOOL |
		DB_THREAD |
		DB_INIT_TXN;
	DB_ENV *env = NULL;
	int dberr = db_env_create(&env, 0);
	if (dberr) {
		exit(1);
	}

	dberr = env->open(env, OTHER_DB_ROOT, env_flags, 0);
	if (dberr) {
		env->close(env, 0);
		exit(1);
	}
}

extern "C" void teardown()
{
}


extern "C" void test_increment_serial_id_returns_expected_results()
{
	std::string ser_id = "9";
	jaldb_increment_serial_id(ser_id);
	assert_string_equals("A", ser_id.c_str());

	ser_id = "0";
	jaldb_increment_serial_id(ser_id);
	assert_string_equals("1", ser_id.c_str());

	ser_id = "Z";
	jaldb_increment_serial_id(ser_id);
	assert_string_equals("a", ser_id.c_str());

	ser_id = "z";
	jaldb_increment_serial_id(ser_id);
	assert_string_equals("10", ser_id.c_str());

	ser_id = "zz";
	jaldb_increment_serial_id(ser_id);
	assert_string_equals("100", ser_id.c_str());

	ser_id = "zzz";
	jaldb_increment_serial_id(ser_id);
	assert_string_equals("1000", ser_id.c_str());
}
