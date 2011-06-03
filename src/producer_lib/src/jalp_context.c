/**
 * @file jalp_context.c This file defines functions for jalp_context.
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <jalop/jal_status.h>
#include <jalop/jalp_context.h>
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jalp_config_internal.h"
#include "jalp_context_internal.h"

jalp_context *jalp_context_create(void)
{
	jalp_context *context = jal_calloc(1, sizeof(*context));
	context->socket = -1;
	return context;
}

void jalp_context_disconnect(jalp_context *ctx)
{
	if (ctx) {
		close(ctx->socket);
		ctx->socket = -1;
	}
}

void jalp_context_destroy(jalp_context **ctx)
{
	if (!ctx || !(*ctx)) {
		return;
	}

	jalp_context_disconnect(*ctx);

	free((*ctx)->path);
	free((*ctx)->hostname);
	free((*ctx)->app_name);
	free(*ctx);
	*ctx = NULL;
}

enum jal_status jalp_context_init(jalp_context *ctx, const char *path,
		const char *hostname, const char *app_name)
{
	if (!ctx) {
		return JAL_E_INVAL;
	}

	// make sure a context cannot be initialized more than once
	if (ctx->path || ctx->hostname || ctx->app_name) {
		return JAL_E_INITIALIZED;
	}

	if (path) {
		ctx->path = jal_strdup(path);
	} else {
		ctx->path = jal_strdup(JALP_SOCKET_NAME);
	}

	if (hostname) {
		ctx->hostname = jal_strdup(hostname);
	} else {
		char name[_POSIX_HOST_NAME_MAX+1];
		if (gethostname(name, sizeof(name)) == 0) {
			name[_POSIX_HOST_NAME_MAX] = '\0';
			ctx->hostname = jal_strdup(name);
		} else {
			return JAL_E_INVAL;
		}
	}

	if (app_name) {
		ctx->app_name = jal_strdup(app_name);
	} else {
		pid_t pid = getpid();
		char *abspath;
		abspath = jal_calloc(PATH_MAX+2, sizeof(*abspath));

		// if we can get the process name from /proc, then we try to
		// get it.  If not, then we just fall back on using the pid.
#if JALP_HAVE_PROCFS
		char *linkpath;
		ssize_t pathsize;

		jal_asprintf(&linkpath, JALP_PROCESS_NAME_PATH, (intmax_t)pid);
		pathsize = readlink(linkpath, abspath, PATH_MAX+1);

		// if this doesn't exist for some reason, just use the pid
		if (pathsize <= 0 || pathsize > PATH_MAX) {
			snprintf(abspath, PATH_MAX, "%" PRIdMAX, (intmax_t)pid);
		}

		free(linkpath);
#else /* no JALP_HAVE_PROCFS */
		snprintf(abspath, PATH_MAX, "%" PRIdMAX, (intmax_t)pid);
#endif /* JALP_HAVE_PROCFS */
		ctx->app_name = abspath;
	}

	return JAL_OK;
}
