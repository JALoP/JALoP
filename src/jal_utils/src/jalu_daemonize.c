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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "jal_asprintf_internal.h"

int jalu_daemonize(const char *log_dir, const char *pid_file) {

	// Daemonize the process
	// This causes the parent to exit, sets the sid for the child process,
	// changes the directory to "/", and redirects stdin/out/err to /dev/null
	if(0 != daemon(0,0)) {
		return -1;
	}

	// There is a known issue with the way daemonization works
	// in order to prevent the daemonized process from acting as a session
	// host - and in paticular from potentially attaching to a new
	// terminal if one were created, an additional fork() call
	// is recommended.
	switch(fork()) {
		case -1: return -1; // fork error
		case 0: break; // child continues
		default: exit(0); // parent process exits
	}


	if (log_dir != NULL) {
		// Re-redirect stdout to a log file in the provided directory
		char filename[PATH_MAX];

		if (snprintf(filename, sizeof(filename), "%s/stdout.log", log_dir) < 0) {
			return -1;
		}

		mode_t mode = 0660; // Let umask decide the group permissions
		int flags = O_CREAT | O_WRONLY | O_TRUNC;

		// Attempt to create the stdout log file
		int fd = open(filename, flags, mode);
		if(-1 == fd) {
			return -1;
		}

		// Redirect stdout to the stdout log file
		if(-1 == dup2(fd, STDOUT_FILENO)) {
			return -1;
		}
		close(fd);

		// Re-redirect stderr to a log file in the provided directory
		if (snprintf(filename, sizeof(filename), "%s/stderr.log", log_dir) < 0) {
			return -1;
		}

		// Attempt to create the stderr log file
		fd = open(filename, flags, mode);
		if(-1 == fd) {
			return -1;
		}

		// Redirect stderr to the stderr log file
		if(-1 == dup2(fd, STDERR_FILENO)) {
			return -1;
		}
		close(fd);

		// The stdout stream is buffered. To print immediately, disable buffering on stdout
		setbuf(stdout, NULL);
	}

	if (pid_file != NULL) {
		FILE *fp = fopen(pid_file, "w");
		if (fp == NULL) {
			fprintf(stderr, "Failed to open pid file '%s'.\n", pid_file);
			return -1;
		}

		fprintf(fp, "%ld\n", (long) getpid());
		fclose(fp);
	}

	return 0;
}
