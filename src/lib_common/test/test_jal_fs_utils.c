/**
 * @file test_jal_fs_utils.c This file contains functions to test jal_fs_utils.c.
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

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <test-dept.h>

#include "jal_fs_utils.h"
#include "test_utils.h"

int mkdir_fails_with_eperm(__attribute__((unused)) const char *path,
		__attribute__((unused))mode_t mode)
{
	errno = EPERM;
	return -1;
}

int mkdir_fails_with_eexist(__attribute__((unused)) const char *path,
		__attribute__((unused))mode_t mode)
{
	errno = EEXIST;
	return -1;
}

void test_jal_create_dirs_creates_specified_directory_structure()
{
	dir_cleanup("./foo");
	enum jal_status ret = jal_create_dirs("./foo/bar/test");
	assert_equals(JAL_OK, ret);

	struct stat st;
	assert_equals(0, stat("./foo/bar", &st));
	assert_equals(-1, stat("./foo/bar/test", &st));

	int rc = dir_cleanup("./foo");
	assert_equals(0, rc);
}

void test_jal_create_dirs_fails_cleanly_when_path_is_null()
{
	enum jal_status ret = jal_create_dirs(NULL);
	assert_equals(JAL_E_INVAL, ret);
}

void test_jal_create_dirs_fails_cleanly_when_mkdir_fails_errno_eperm()
{
	replace_function(mkdir, mkdir_fails_with_eperm);
	enum jal_status ret = jal_create_dirs("./foo/bar/");
	assert_equals(JAL_E_INVAL, ret);
	restore_function(mkdir);
}

void test_jal_create_dirs_continues_when_mkdir_fails_errno_eexist()
{
	replace_function(mkdir, mkdir_fails_with_eexist);
	enum jal_status ret = jal_create_dirs("./foo/bar/");
	assert_equals(JAL_OK, ret);
	restore_function(mkdir);
}

