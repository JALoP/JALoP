/**
 * @file jalp_context.c This file defines functions for dealing
 * with the jalp_context struct.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2013 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <jalop/jal_status.h>
#include <jalop/jalp_context.h>
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jalp_config_internal.h"
#include "jalp_context_internal.h"


jalp_context *jalp_context_create(void)
{
	jalp_context *context = NULL;

	context = jal_calloc(1, sizeof(*context));
	if (context == NULL) {
		return NULL;
	}

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

	jal_digest_ctx_destroy(&(*ctx)->digest_ctx);
	free((*ctx)->path);
	free((*ctx)->hostname);
	free((*ctx)->app_name);
	RSA_free((*ctx)->signing_key);
	X509_free((*ctx)->signing_cert);
	free((*ctx)->schema_root);
	free(*ctx);
	*ctx = NULL;
}

enum jal_status jalp_context_init(jalp_context *ctx, const char *path,
		const char *hostname, const char *app_name,
		const char *schema_root)
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

	if (schema_root) {
		ctx->schema_root = jal_strdup(schema_root);
	} else {
		ctx->schema_root = jal_strdup(JALP_SCHEMA_ROOT);
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

enum jal_status jalp_context_connect(jalp_context *ctx)
{
	int err;
	struct sockaddr_un sock_addr;

	if (!ctx) {
		return JAL_E_INVAL;
	}

	// make sure the context has been initialized
	if (!ctx->path || !ctx->hostname || !ctx->app_name) {
		return JAL_E_UNINITIALIZED;
	}

	// close the socket in case it is already open
	if (ctx->socket != -1) {
		jalp_context_disconnect(ctx);
	}

	ctx->socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ctx->socket == -1) {
		goto err_out;
	}

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sun_family = AF_UNIX;

	size_t pathlen = strlen(ctx->path);
	if (pathlen >= sizeof(sock_addr.sun_path)) {
		// path to socket file is too long to fit in sockaddr_un.sun_path
		goto err_out;
	}

	strncpy(sock_addr.sun_path, ctx->path, sizeof(sock_addr.sun_path) - 1);
	err = connect(ctx->socket, (struct sockaddr*) &sock_addr, sizeof(sock_addr));
	if (0 != err) {
		goto err_out;
	}

	return JAL_OK;

err_out:
	jalp_context_disconnect(ctx);
	return JAL_E_NOT_CONNECTED;
}
enum jal_status jalp_context_set_digest_callbacks(jalp_context *ctx,
		const struct jal_digest_ctx *digest_ctx)
{
	if (!ctx) {
		return JAL_E_INVAL;
	}

	if (!digest_ctx) {
		jal_digest_ctx_destroy(&ctx->digest_ctx);
		return JAL_OK;
	}

	if (!jal_digest_ctx_is_valid(digest_ctx)) {
		return JAL_E_INVAL;
	}


	if(!ctx->digest_ctx) {
		ctx->digest_ctx = jal_digest_ctx_create();
	}

	free(ctx->digest_ctx->algorithm_uri);
	memcpy(ctx->digest_ctx, digest_ctx, sizeof(*digest_ctx));
	ctx->digest_ctx->algorithm_uri = jal_strdup(digest_ctx->algorithm_uri);

	return JAL_OK;
}
