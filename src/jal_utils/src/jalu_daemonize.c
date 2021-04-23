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
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <sys/types.h>
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

	int rc = daemon(0, 0);
	return rc;
}

int jalu_pid(const char* path) {
	pid_t pid;
	FILE *pidfile = NULL;
	pid = getpid();

	if (path) {
		pidfile = fopen(path, "w");
		if (NULL == pidfile) {
			return -1;
		}
		fprintf(pidfile, "%d\n", pid);
		fclose(pidfile);
		pidfile = NULL;
	}

	return pid;
}
