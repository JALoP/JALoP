/**
 * @file jalu_daemonize.c This file contains utility functions to daemonize a process.
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
#include "jalu_daemonize.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "jal_asprintf_internal.h"

int jalu_daemonize() {
	pid_t pid, sid;
	pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid > 0) {
		//exit the parent process
		exit(0);
	}

	sid = setsid();
	if (sid < 0) {
		return -1;
	}

	if ((chdir("/")) < 0) {
		return -1;
	}

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	return 0;
}

int jalu_make_absolute_path(char **path) {
	if (*path[0] == '/') {
		//path is already absolute
		return 0;
	} else {
		char *cwd = NULL;
		int cwd_ret = jalu_getcwd(&cwd);
		if (cwd_ret < 0) {
			return cwd_ret;
		}
		char *abspath = NULL;
		int asprintf_ret = jal_asprintf(&abspath, "%s/%s", cwd, *path);
		if (asprintf_ret < 0) {
			return asprintf_ret;
		}
		free(*path);
		*path = abspath;
		return 0;
	}
}

int jalu_getcwd(char **dir) {
	int size = 128;
	char *cwd_buf = malloc(size);
	if (!cwd_buf) {
		return -1;
	}
	char *cwd = getcwd(cwd_buf, size);
	if (cwd != NULL) {
		*dir = cwd;
		return 0;
	} else {
		while ((!cwd) && (errno == ERANGE)) {
			size *= 2;
			char * resize_cwd_buf = realloc(cwd_buf, size);
			if (!resize_cwd_buf) {
				free(cwd_buf);
				return -1;
			}
			cwd_buf = resize_cwd_buf;
			cwd = getcwd(cwd_buf, size);
			if (cwd != NULL) {
				*dir = cwd;
				return 0;
			}
		}
		//some error other than ERANGE occurred
		free(cwd_buf);
		return -1;
	}
}
