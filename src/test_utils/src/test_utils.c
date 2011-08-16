/**
 * @file This file defines functions to assist with general testing.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

//#include "jal_alloc.h"
#include "test_utils.h"

int dir_cleanup(const char *path)
{
	int ret = -1;
	int path_len = 0;
	DIR *dir = NULL;
	struct dirent *ent = NULL;

	path_len = strlen(path);

	dir = opendir(path);
	if (!dir) {
		goto out;
	}

	while ((ent = readdir(dir))) {
		int ent_len = strlen(ent->d_name);
		char *ent_path = NULL;
		struct stat st;

		ent_path = malloc(path_len + ent_len + 2);

		strcpy(ent_path, path);
		strcat(ent_path, "/");
		strcat(ent_path, ent->d_name);

		lstat(ent_path, &st);

		if (0 != strcmp(ent->d_name, ".")
		&& 0 != strcmp(ent->d_name, "..")) {
			if (S_ISREG(st.st_mode)) {
				ret = remove(ent_path);
				if (ret) {
					goto out;
				}
			} else  if (S_ISDIR(st.st_mode)) {
				ret = dir_cleanup((const char *)ent_path);
				if (ret) {
					goto out;
				}
			} else {
				ret = -1;
				goto out;
			}
		}
		free(ent_path);
		ent_path = NULL;
	}
	ret = rmdir(path);

out:
	return ret;
}
