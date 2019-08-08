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

	if (log_dir != NULL) {
		int fd = open("/dev/null", O_RDONLY);
		if (fd != 0) {
			/* fd 0 stdin */
			if (fd != -1)
				close(fd);
			return -1;
		}

		char filename[PATH_MAX];

		if (snprintf(filename, sizeof(filename), "%s/stdout.log", log_dir) < 0) {
			return -1;
		}

		mode_t mode = 0660; // Let umask decide the group permissions
		int flags = O_CREAT | O_WRONLY | O_TRUNC;

		fd = open(filename, flags, mode);
		if ( fd != 1) {
			/* fd 1 stdout */
			if (fd != -1)
				close(fd);
			return -1;
		}

		if (snprintf(filename, sizeof(filename), "%s/stderr.log", log_dir) < 0) {
			return -1;
		}

		fd = open(filename, flags, mode);
		if (fd != 2) {
			/* fd 2 stderr */
			if (fd != -1)
				close(fd);
			return -1;
		}

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
