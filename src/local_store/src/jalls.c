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

/** 	The following defines check if GNU_SOURCE has
	previously been defined.  If it has, we undefine it
	and define _POSIX_C_SOURCE as 20112L so that we could
	use the XSI-compliant version of strerror_r which is
	more portable.  The defines must come before "string.h".
	The defines also appear not to work with "strings.h".

	From http://linux.die.net/man/3/strerror_r
	"The XSI-compliant version of strerror_r() is provided if:
		(_POSIX_C_SOURCE >= 20112L || _XOPEN_SOURCE >= 600)
		&& !_GNU_SOURCE
	Otherwise, the GNU-specific version is provided."
**/
#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif
#define _POSIX_C_SOURCE 200112L
#include <string.h>

#include <stdio.h>	/** For remove **/
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <errno.h>
#include <pthread.h>
#include <openssl/pem.h>
#include <limits.h>
#include <signal.h>	/** For SIGABRT, SIGTERM, SIGINT **/

#include <jalop/jal_status.h>
#include <jalop/jal_version.h>

#include "jal_fs_utils.h"
#include "jalls_config.h"
#include "jalu_daemonize.h"
#include "jalls_handler.h"
#include "jalls_msg.h"
#include "jalls_init.h"
#include "jal_alloc.h"

#define JALLS_LISTEN_BACKLOG 20
#define JALLS_USAGE "usage: [--debug] [--version] FILE\n"
#define JALLS_ERRNO_MSG_SIZE 1024
#define VERSION_CALLED 1

static const char *DEBUG_FLAG = "--debug";
static const char *VERSION_FLAG = "--version";

// Members for deleting socket file
extern volatile int should_exit;

static int parse_cmdline(int argc, char **argv, char ** config_path, int *debug);
static int setup_signals();
static void sig_handler(int sig);
static void delete_socket(const char *socket_path, int debug);
static int get_thread_count();

int main(int argc, char **argv) {

	char *config_path;
	FILE *fp;
	RSA *key = NULL;
	X509 *cert = NULL;
	jaldb_context *db_ctx = NULL;
	struct jalls_context *jalls_ctx = NULL;
	enum jal_status jal_err = JAL_E_INVAL;
	int sock = -1;
	int old_socket_exist = 0;

	// Perform signal hookups
	if ( 0 != setup_signals()) {
		goto err_out;
	}

	if (0 != jalls_init()) {
		goto err_out;
	}
	int debug = 0;
	int err = parse_cmdline(argc, argv, &config_path, &debug);
	if (err == VERSION_CALLED) {
		goto version_out;
	} else if (err < 0) {
		goto err_out;
	}

	err = jalls_parse_config(config_path, &jalls_ctx);
	if (err < 0) {
		goto err_out;
	}
	jalls_ctx->debug = debug;

	jal_err = jal_create_dirs(jalls_ctx->db_root);
	if (JAL_OK != jal_err) {
		fprintf(stderr, "failed to create database directory\n");
		goto err_out;
	}

	//the db_root path must be made absolute before daemonizing
	char absolute_db_root[PATH_MAX];
	char *res = realpath(jalls_ctx->db_root, absolute_db_root);
	if (res == NULL) {
		fprintf(stderr, "failed to create an absolute path from db_root\n");
		goto err_out;
	} else {
		free(jalls_ctx->db_root);
		jalls_ctx->db_root = absolute_db_root;
	}

	//the schemas_root path must be made absolute before daemonizing
	char absolute_schemas_root[PATH_MAX];
	char *res2 = realpath(jalls_ctx->schemas_root, absolute_schemas_root);
	if (res2 == NULL) {
		fprintf(stderr, "failed to create an absolute path from schemas_root\n");
		goto err_out;
	} else {
		free(jalls_ctx->schemas_root);
		jalls_ctx->schemas_root = absolute_schemas_root;
	}

	//load the private key
	if (jalls_ctx->private_key_file) {
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
	jal_err = jaldb_context_init(db_ctx, jalls_ctx->db_root,
					jalls_ctx->schemas_root, 0);
	if (jal_err != JAL_OK) {
		fprintf(stderr, "failed to create the jaldb_context\n");
		goto err_out;
	}

	//check if the socket file already exists
	struct stat sock_stat;
	struct sockaddr_un sock_addr;
	memset(&sock_addr, 0, sizeof(sock_addr));
	size_t socket_path_len = strlen(jalls_ctx->socket);

	jal_err = jal_create_dirs(jalls_ctx->socket);
	if (JAL_OK != jal_err) {
		fprintf(stderr, "failed to create socket directory\n");
		goto err_out;
	}

	err = stat(jalls_ctx->socket, &sock_stat);
	if (err != -1) {
		fprintf(stderr, "failed to create socket: already exists\n");
		fprintf(stderr, "Exiting ...\n");
		old_socket_exist = 1;
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
		close(sock);
		return -1;
	}

	err = listen(sock, JALLS_LISTEN_BACKLOG);
	if (-1 == err) {
		fprintf(stderr, "failed to listen, %s\n", strerror(errno));
		close(sock);
		return -1;
	}

	if (!debug) {
		err = jalu_daemonize();
		if (err < 0) {
			fprintf(stderr, "failed to create daemon\n");
			goto err_out;
		}
	}

	if (jalls_ctx->debug) {
		fprintf(stderr, "Accept delay thread count: %d\n", jalls_ctx->accept_delay_thread_count);
		fprintf(stderr, "Accept delay increment: %d microSec\n", jalls_ctx->accept_delay_increment);
		fprintf(stderr, "Accept delay max: %d microSec\n", jalls_ctx->accept_delay_max);
		fprintf(stderr, "Ready to accept connections\n");
	}

	struct sockaddr_un peer_addr;
	unsigned int peer_addr_size = sizeof(peer_addr);

	const int min_thread_count_intervention = jalls_ctx->accept_delay_thread_count;
	const int max_thread_count_intervention = jalls_ctx->accept_delay_max;
	const int min_accept_delay = jalls_ctx->accept_delay_increment;

	while (!should_exit) {
		struct jalls_thread_context *thread_ctx = calloc(1, sizeof(*thread_ctx));
		if (thread_ctx == NULL) {
			if (debug) {
				fprintf(stderr, "Failed to allocate memory\n");
			}
			goto err_out;
		}
		int thread_count = 0;

		/* Flow control functionality turned off if min_thread_count_intervention
		* set to zero in the jal-local-store configuration file
		*/
		if (0 < min_thread_count_intervention) {
			thread_count = get_thread_count();
			if (jalls_ctx->debug) {
				fprintf(stderr, "Thread_count: %d\n", thread_count);
			}
		}

		if (0 < min_thread_count_intervention &&
			thread_count > min_thread_count_intervention) {

			int delay_count = thread_count - min_thread_count_intervention;
			int64_t accept_delay = min_accept_delay;

			for (; delay_count > 1; delay_count--) {
				accept_delay+=accept_delay;
				if (accept_delay > max_thread_count_intervention) {
					accept_delay = max_thread_count_intervention;
					break;
				}
			}

			if (jalls_ctx->debug) {
				fprintf(stderr, "Accept_delay: %ld microSec\n", accept_delay);
			}
			usleep((useconds_t)accept_delay);
		}

		if (should_exit) {
			break;
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
				fprintf(stderr, "Failed to create pthread: %s\n", strerror(my_errno));
			}
		} else {
			free(thread_ctx);
			if (debug) {
				fprintf(stderr, "Failed to accept: %s\n", strerror(my_errno));
			}
		}
	}

err_out:
	if (jalls_ctx && 0 == old_socket_exist) {
		delete_socket(jalls_ctx->socket, jalls_ctx->debug);
	}

	RSA_free(key);
	X509_free(cert);
	jalls_shutdown();

	jaldb_context_destroy(&db_ctx);
	close(sock);

	exit(-1);

version_out:
	jalls_shutdown();
	exit(0);
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
		} else if (0 == strcmp(argv[1], VERSION_FLAG)) {
			printf("%s\n", jal_version_as_string());
			return VERSION_CALLED;
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

static int setup_signals()
{
	// Signal action to delete the socket file
	struct sigaction action_on_sig;
	action_on_sig.sa_handler = &sig_handler;
	sigemptyset(&action_on_sig.sa_mask);
	action_on_sig.sa_flags = 0;

	if (0 != sigaction(SIGABRT, &action_on_sig, NULL)) {
		fprintf(stderr, "failed to register SIGABRT.\n");
		goto err_out;
	}
	if (0 != sigaction(SIGTERM, &action_on_sig, NULL)) {
		fprintf(stderr, "failed to register SIGTERM.\n");
		goto err_out;
	}
	if (0 != sigaction(SIGINT, &action_on_sig, NULL)) {
		fprintf(stderr, "failed to register SIGINT.\n");
		goto err_out;
	}
	return 0;

err_out:
	return -1;
}

static void sig_handler(__attribute__((unused)) int sig)
{
	should_exit = 1;	// Global Flag will cause main
				// to exit.
}

static void delete_socket(const char *p_socket_path, int p_debug)
{
	if (0 != remove(p_socket_path)) {
		int local_errno = errno;
		if (p_debug) {
			char *buf = jal_malloc(JALLS_ERRNO_MSG_SIZE);
			int result = strerror_r(local_errno, buf, JALLS_ERRNO_MSG_SIZE);
			if (0 != result) {
				printf("Failed to parse errno.\n");
			}
			fprintf(stderr,
				"Error deleting socket file: %s\n",
				buf);
			free(buf);
		}
	}
}

static int get_thread_count()
{
	FILE *self_status_file = NULL;

	const char *self_status_file_path = "/proc/self/status";
	const char *threads_token = "Threads:";
	size_t thread_token_length = strlen(threads_token);
	int thread_count = 0;
	const int line_length = 100;
	char one_line [line_length];
	char *fgets_status = NULL;
	int strncmp_result = 0;
	static bool file_error_reported = false;
	
	/* Determine if a regular file before opening. */

	struct stat stat_buffer;
	if (-1 == stat(self_status_file_path, &stat_buffer)) {
		if (!file_error_reported) {
			file_error_reported = true;
			fprintf(stderr, "%s(): Stat of file to read thread count failed:\n    ", __func__);
			perror(self_status_file_path);
		}
		return thread_count;
	}

	if (!S_ISREG(stat_buffer.st_mode)) {
		if (!file_error_reported) {
			file_error_reported = true;
			fprintf(stderr, "%s(): File to read thread count is not a regular file:\n", __func__);
			fprintf(stderr, "   %s\n" ,self_status_file_path);
		}
		return thread_count;
	}

	self_status_file = fopen(self_status_file_path, "r");

	if (NULL == self_status_file && !file_error_reported) {
		file_error_reported = true;
		fprintf(stderr, "%s(): Open of file to read thread count failed:\n    ", __func__);
		perror(self_status_file_path);
	}

	/* Find the line starting with 'Threads:' */

	for(int line_number=1;NULL != self_status_file;line_number++)
	{
		fgets_status = fgets(one_line, line_length, self_status_file);
		if (NULL == fgets_status) {
			if (!file_error_reported) {
				file_error_reported = true;
				fprintf(stderr, "%s(): No line found starting with \"%s\";\n",
					__func__, threads_token);
				fprintf(stderr, "  attempting to read line number: %d; from: \"%s\"\n",
					line_number, self_status_file_path);
				if (0 != ferror(self_status_file)) {
					perror("    Error reported by read of process self status file");
				}
			}
			break;
		}
		/* See if the line starts with 'Threads:' */
		strncmp_result = strncmp(threads_token, one_line, thread_token_length);
		if (0 != strncmp_result) {
			continue;
		}
		/* Found the line containing the 'Threads:' token. */

		/* Make sure the location after the token is not zero */
		fgets_status += thread_token_length;
		if ( '\0' == *fgets_status ) {
			break;
		}

		thread_count = atoi(fgets_status);
		if (0 > thread_count) {
			thread_count = 0; // don't allow negative numbers
		}
		if (0 == thread_count && !file_error_reported) {
			file_error_reported = true;
			fprintf(stderr, "%s(): no integer string was converted after \"%s\" was found;\n",
				__func__, threads_token);
			fprintf(stderr, "  looking for a positive integer on line #%d; from: \"%s\"\n",
				line_number, self_status_file_path);
		}
		break;
	}

	if (NULL != self_status_file) {
		(void) fclose(self_status_file);
	}
	return thread_count;
}
