/**
 * @file
 *
 * @brief This file contains functions to test jaldb_utils.c.
 *
 * ### LICENSE
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
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

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
extern "C" {
#include <test-dept.h>
}
#include <time.h>
#include <unistd.h>
#include <jalop/jal_status.h>
#include <fcntl.h>

#include "jal_alloc.h"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "test_utils.h"
#include "jaldb_context.h"

#define OTHER_DB_ROOT "./testdb/"

extern "C" void setup()
{
	struct stat st;
	if (stat(OTHER_DB_ROOT, &st) != 0) {
		(void)mkdir(OTHER_DB_ROOT, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}
	else {
		struct dirent *d;
		DIR *dir;
		char buf[sizeof(OTHER_DB_ROOT) + sizeof(d->d_name)];
		dir = opendir(OTHER_DB_ROOT);
		while ((d = readdir(dir)) != NULL) {
			sprintf(buf, "%s/%s", OTHER_DB_ROOT, d->d_name);
			remove(buf);
		}
		(void)closedir(dir);
	}
}

extern "C" void teardown()
{

}

extern "C" void test_jaldb_create_file_returns_cleanly_when_open_fails()
{
	char *path = NULL;
	int fd = -1;
	uuid_t uuid,uuid_orig;
	uuid_generate(uuid);
	uuid_copy(uuid_orig,uuid);
	enum jaldb_status ret = jaldb_create_file("/dev/null/", &path, &fd,uuid,JALDB_RTYPE_AUDIT,JALDB_DTYPE_SYS_META);
	assert_equals(JALDB_E_INTERNAL_ERROR, ret);
	assert_pointer_equals((void*) NULL, path);
	assert_equals(-1, fd);
	assert_equals(uuid_compare(uuid,uuid_orig),0);

	// When this particular failure occurs, the subdirectory /tmp/XX where XX is the first
	// two characters in uuid will still happen as a side effect, but path is left as NULL
	// So we have to rebuild the directory name ourselves
	const int UUID_LEN = 37;
	char *uuid_string = (char*)jal_calloc(UUID_LEN,sizeof(char));
	uuid_unparse(uuid,uuid_string);

	char* dir_path = NULL;
	int dir_path_len = strlen("/tmp/XX/") + 1;
	dir_path = (char*)jal_calloc(dir_path_len, sizeof(char));
	strcpy(dir_path, "/tmp/");
	strncat(dir_path, uuid_string, 2);  // nosemgrep - non issue for unit test use
	dir_path[dir_path_len-1] = '/';

	// Remove this directory
	remove(dir_path);
	free(dir_path);
	free(uuid_string);
}

extern "C" void test_jaldb_create_file_returns_cleanly_when_db_root_is_null()
{
	char *path = NULL;
	int fd = -1;
	uuid_t uuid,uuid_orig;
	uuid_generate(uuid);
	uuid_copy(uuid_orig,uuid);
	enum jaldb_status ret = jaldb_create_file(NULL, &path, &fd,uuid,JALDB_RTYPE_AUDIT,JALDB_DTYPE_SYS_META);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, path);
	assert_equals(-1, fd);
	assert_equals(uuid_compare(uuid,uuid_orig),0);
}

extern "C" void test_jaldb_create_file_returns_cleanly_when_rtype_is_unknown()
{
	char *path = NULL;
	int fd = -1;
	uuid_t uuid,uuid_orig;
	uuid_generate(uuid);
	uuid_copy(uuid_orig,uuid);
	enum jaldb_status ret = jaldb_create_file("/tmp/", &path, &fd,uuid,JALDB_RTYPE_UNKNOWN,JALDB_DTYPE_SYS_META);
	assert_equals(JALDB_E_INVAL, ret);
	assert_pointer_equals((void*) NULL, path);
	assert_equals(-1, fd);
	assert_equals(uuid_compare(uuid,uuid_orig),0);
}

extern "C" void test_jaldb_create_file_works()
{
	char *path = NULL;
	char *full_path = NULL;
	int fd = -1;
	uuid_t uuid, uuid_orig;
	uuid_generate(uuid);
	uuid_copy(uuid_orig,uuid);

	enum jaldb_status ret = jaldb_create_file("/tmp/",&path,&fd,uuid,JALDB_RTYPE_AUDIT,JALDB_DTYPE_SYS_META);
	assert_equals(JAL_OK,ret);
	assert_equals(uuid_compare(uuid,uuid_orig),0);
	assert_not_equals(fd,-1);
	assert_not_equals(path, NULL);

	full_path = (char*)jal_calloc(strlen(path)+6,sizeof(char));
	snprintf(full_path,strlen(path)+6,"/tmp/%s",path);

	// Ensure the file was created
	struct stat buffer;
	assert_equals(lstat(full_path, &buffer),0);
	// Remove the file
	remove(full_path);

	// truncate to just the /tmp/XX portion by finding the last / and replacing it with 0
	char* lastSlash = strrchr(full_path, '/');
	assert_not_equals(NULL, lastSlash);
	// Sanity checks to make sure we don't try to remove /tmp
	assert_not_equals(strlen("/tmp/"), strlen(full_path));
	assert_not_equals(strlen("/tmp"), strlen(full_path));
	*lastSlash = 0;

	// remove the temporary directory /tmp/XX
	remove(full_path);

	free(full_path);
	free(path);
}