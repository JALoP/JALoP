/**
 * @file jal_fs_utils.c This file contains general utility functions.
 *
 * @section LICENSE
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

#include "jal_alloc.h"
#include "jal_fs_utils.h"

#include <errno.h>
#include <jalop/jal_status.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>

enum jal_status jal_create_dirs(const char *path)
{
	if (!path) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = JAL_E_INVAL;
	char *curr = NULL;
	char *lpath = NULL;
	lpath = jal_strdup(path);
	curr = lpath;
	while(*curr) {
		if (*curr == '/' && curr != lpath) {
			*curr = '\0';
			if (-1 == mkdir(lpath, 0700) && errno != EEXIST) {
				goto out;
			}
			*curr = '/';
		}
		curr += 1;
	}
	ret = JAL_OK;
out:
	free(lpath);
	return ret;
}
