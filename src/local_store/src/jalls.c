/**
 * @file jalls.c This file contains functions the main function of the
 * jal local store
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
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/pem.h>
#include <strings.h>

#include <jalop/jal_status.h>

#include "jalls_config.h"
#include "jalu_daemonize.h"
#include "jalls_handler.h"
#include "jalls_msg.h"
#include "jalls_init.h"

#define JALLS_LISTEN_BACKLOG 20
#define JALLS_USAGE "usage: [--debug] FILE\n"

static const char *DEBUG_FLAG = "--debug";

static int parse_cmdline(int argc, char **argv, char ** config_path, int *debug);

int main(int argc, char **argv) {

	char *config_path;
	FILE *fp;
	RSA *key = NULL;
	X509 *cert = NULL;
	jaldb_context *db_ctx = NULL;
	struct jalls_context *jalls_ctx = NULL;

	if (0 != jalls_init()) {
		goto err_out;
	}
	int debug = 0;
	int err = parse_cmdline(argc, argv, &config_path, &debug);
	if (err < 0) {
		goto err_out;
	}

	err = jalls_parse_config(config_path, &jalls_ctx);
	if (err < 0) {
		goto err_out;
	}
	jalls_ctx->debug = debug;

	//load the private key

	fp = fopen(jalls_ctx->private_key_file, "r");
	if (!fp) {
		fprintf(stderr, "failed to open private key file\n");
		goto err_out;
	}
	key = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!key) {
		fprintf(stderr, "failed to read private key\n");
		goto err_out;
	}

	//load the public cert
	if (jalls_ctx->public_cert_file) {
		fp = fopen(jalls_ctx->public_cert_file, "r");
		if (!fp) {
			fprintf(stderr, "failed to open public cert file\n");
			goto err_out;
		}
		cert = PEM_read_X509(fp, NULL, NULL, NULL);
		if (!cert) {
			fprintf(stderr, "failed to read public cert\n");
			goto err_out;
		}
	}

	//create a jaldb_context to pass to work threads
	db_ctx = jaldb_context_create();
	enum jal_status jal_err = jaldb_context_init(db_ctx, jalls_ctx->db_root,
			jalls_ctx->schemas_root, 1, 0);
	if (jal_err != JAL_OK) {
		fprintf(stderr, "failed to create the jaldb_context\n");
		goto err_out;
	}

	//check if the socket file already exists
	struct stat sock_stat;
	int sock = -1;
	struct sockaddr_un sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	size_t socket_path_len = strlen(jalls_ctx->socket);
	err = stat(jalls_ctx->socket, &sock_stat);
	if (err != -1) {
		fprintf(stderr, "failed to create socket: already exists\n");
		goto err_out;
	}
	if (errno != ENOENT) {
		fprintf(stderr, "failed to stat the socket path: %s\n", strerror(errno));
		goto err_out;
	}

	//create the socket
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		fprintf(stderr, "failed to create the socket: %s\n", strerror(errno));
		goto err_out;
	}

	sock_addr.sun_family = AF_UNIX;
	if (socket_path_len >= sizeof(sock_addr.sun_path)) {
		fprintf(stderr, "could not create the socket: path %s is too long\n", jalls_ctx->socket);
		goto err_out;
	}

	strncpy(sock_addr.sun_path, jalls_ctx->socket, sizeof(sock_addr.sun_path));
	sock_addr.sun_path[sizeof(sock_addr.sun_path) - 1] = '\0';

	err = bind(sock, (struct sockaddr*) &sock_addr, sizeof(sock_addr));
	if (-1 == err) {
		fprintf(stderr, "failed to bind %s: %s\n", jalls_ctx->socket, strerror(errno));
		return -1;
	}

	err = listen(sock, JALLS_LISTEN_BACKLOG);
	if (-1 == err) {
		fprintf(stderr, "failed to listen, %s\n", strerror(errno));
		return -1;
	}

	if (!debug) {
		err = daemonize();
		if (err < 0) {
			fprintf(stderr, "failed to create daemon");
			goto err_out;
		}
	}

	struct sockaddr_un peer_addr;
	unsigned int peer_addr_size = sizeof(peer_addr);
	while (1) {
		struct jalls_thread_context *thread_ctx = calloc(1, sizeof(*thread_ctx));
		if (thread_ctx == NULL) {
			if (debug) {
				fprintf(stderr, "Failed to allocate memory");
			}
		}
		thread_ctx->fd = accept(sock, (struct sockaddr *) &peer_addr, &peer_addr_size);
		thread_ctx->signing_key = key;
		thread_ctx->signing_cert = cert;
		thread_ctx->db_ctx = db_ctx;
		thread_ctx->ctx = jalls_ctx;
		int my_errno = errno;
		if (-1 != thread_ctx->fd) {
			pthread_t new_thread;
			err = pthread_create(&new_thread, NULL, jalls_handler, thread_ctx);
			my_errno = errno;
			if (err < -1 && debug) {
				fprintf(stderr, "Failed to create pthread: %s", strerror(my_errno));
			}
		} else {
			if (debug) {
				fprintf(stderr, "Failed to accept: %s", strerror(my_errno));
			}
		}
	}

err_out:
	RSA_free(key);
	X509_free(cert);
	jalls_shutdown();

	jaldb_context_destroy(&db_ctx);

	exit(-1);
}

static int parse_cmdline(int argc, char **argv, char ** config_path, int *debug) {
	if (argc <= 1) {
		fprintf(stderr, JALLS_USAGE);
		return -1;
	}
	if (argc == 2) {
		if (0 == strcmp(argv[1], DEBUG_FLAG)) {
			fprintf(stderr, JALLS_USAGE);
			return -1;
		}
		*config_path = argv[1];
		return 0;
	}
	if (argc == 3) {
		if (0 != strcmp(argv[1], DEBUG_FLAG)) {
			fprintf(stderr, JALLS_USAGE);
			return -1;
		}
		*debug = 1;
		*config_path = argv[2];
	}
	else {
		fprintf(stderr, JALLS_USAGE);
		return -1;
	}

	return 0;

}
