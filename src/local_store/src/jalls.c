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
#include <systemd/sd-daemon.h>
#include <argp.h>

#include <jalop/jal_status.h>
#include <jalop/jal_version.h>

#include "jal_fs_utils.h"
#include "jal_linux_cap.h"
#include "jal_linux_seccomp.h"
#include "jalls_config.h"
#include "jalu_daemonize.h"
#include "jalls_handler.h"
#include "jalls_msg.h"
#include "jalls_init.h"
#include "jal_alloc.h"

#define JALLS_LISTEN_BACKLOG 20
#define JALLS_ERRNO_MSG_SIZE 1024

#define dfprintf(...){if(debug==1){fprintf(__VA_ARGS__);}}

// Members for deleting socket file
extern volatile int should_exit;

static int setup_signals();
static void sig_handler(int sig);
static void delete_socket(const char *socket_path, int debug);
static int get_thread_count();

static int systemd_sockfd;
static int get_sockfd_from_systemd();
// argp
const char *argp_program_version = "2";
const char *argp_program_bug_address = "";
static char args_doc[] = "";
static char doc[] = "jal-local-store -- A program to receive and store JALoP records.";
static error_t parse_opt(int key, char *arg, struct argp_state *state);
static struct argp_option options[] =
{
  {"debug", 'd', NULL, 0, "run jal-local-store in debug mode", 0},
	{"config", 'c', "path", 0, "jal-local-store configuration file path", 0},
	{"socket", 's', "path", 0, "jal-local-store socket path", 0},
	{"socket-owner", 'o', "owner", 0, "jal-local-store socket owner", 0},
	{"socket-group", 'g', "group", 0, "jal-local-store socket group", 0},
	{"socket-mode", 'm', "mode", 0, "jal-local-store socket file mode ex:0420", 0},
	{"run-db_recover", 'r', NULL, 0, "run db_recover before opening DB", 0},
	{"no-daemon", 'n', NULL, 0, "do not run jal-local-store as daemon process", 0},
	{0}
};
char *config_path;
int debug;
struct jalls_context cli_jalls_ctx;
// merge command-line configurations into file configurations. Have command-line take precedence
void merge_jal_contexts(struct jalls_context cli_ctx, struct jalls_context *out_ctx); 
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};
//validate file mode parameter for socket-mode
static int check_mode(char * mode);
char mode_error[256] = "socket-mode must be in the form example: 0420.\nExactly four digits with each digit being in range 0-7.\n";

int main(int argc, char **argv) {
	FILE *fp;
	RSA *key = NULL;
	X509 *cert = NULL;
	jaldb_context *db_ctx = NULL;
	struct jalls_context *jalls_ctx = NULL;
	enum jal_status jal_err = JAL_E_INVAL;
	int sock = -1;
	int old_socket_exist = 0;
	char * absolute_path = NULL;

	// Perform signal hookups
	if ( 0 != setup_signals()) {
		goto err_out;
	}

	if (0 != jalls_init()) {
		goto err_out;
	}
	
	debug = 0;
        cli_jalls_ctx.db_recover = -1;
	cli_jalls_ctx.daemon = -1;
	int err = argp_parse(&argp, argc, argv, 0, 0, &cli_jalls_ctx);
	if(err!=0){
		goto err_out;
	}

	err = jalls_parse_config(config_path, &jalls_ctx);
	if (err < 0) {
		goto err_out;
	}
	merge_jal_contexts(cli_jalls_ctx, jalls_ctx);	
	if(config_path){
		int rc = read_sc_config(config_path);
		if (rc != 0) {
                	goto err_out;
                }
	}

	jalls_ctx->debug = debug;

	if(seccomp_config.enable_seccomp){
		if (configureInitialSeccomp()!=0){
			goto err_out;
		}
	}

	jal_err = jal_create_dirs(jalls_ctx->db_root);
	if (JAL_OK != jal_err) {
		fprintf(stderr, "failed to create database directory\n");
		goto err_out;
	}

	//load the private key
	if (jalls_ctx->private_key_file) {
		absolute_path = NULL;
		absolute_path = realpath(jalls_ctx->private_key_file, NULL);
		if(absolute_path == NULL){
			fprintf(stderr, "failed getting private_key_file absolute path for: %s\n", jalls_ctx->private_key_file);
			goto err_out;
		}
		free(jalls_ctx->private_key_file);
		jalls_ctx->private_key_file = absolute_path;
		absolute_path = NULL;

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
		absolute_path = NULL;
		absolute_path = realpath(jalls_ctx->public_cert_file, NULL);
		if(absolute_path == NULL){
			fprintf(stderr, "failed getting public_cert_file absolute path for: %s\n", jalls_ctx->public_cert_file);
			goto err_out;
		}
		free(jalls_ctx->public_cert_file);
		jalls_ctx->public_cert_file = absolute_path;
		absolute_path = NULL;

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
	absolute_path = NULL;		
	absolute_path = realpath(jalls_ctx->db_root, NULL);
	if(absolute_path == NULL){
		fprintf(stderr, "failed getting db_root absolute path for: %s\n", jalls_ctx->db_root);
		goto err_out;
	}
	free(jalls_ctx->db_root);
	jalls_ctx->db_root = absolute_path;
	absolute_path = NULL;

	db_ctx = jaldb_context_create();
        enum jaldb_flags db_flags = JDB_NONE;
        if (jalls_ctx->db_recover==1){
	    dfprintf(stderr, "Setting DB_RECOVER flag.\n");
            db_flags |= JDB_DB_RECOVER;
        }
	else{
	    dfprintf(stderr, "Not setting DB_RECOVER flag.\n");
	}
	jal_err = jaldb_context_init(db_ctx, jalls_ctx->db_root, db_flags);

	if (jal_err != JAL_OK) {
		fprintf(stderr, "failed to create the jaldb_context\n");
		goto err_out;
	}

	systemd_sockfd = get_sockfd_from_systemd();
	if (systemd_sockfd>0){
		sock = systemd_sockfd;
	}
	else{
		dfprintf(stderr, "jal-local-store creating socket....\n");
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
		if(!jalls_ctx->socket_mode){
			jalls_ctx->socket_mode = "0666";
		}		
		if (check_mode(jalls_ctx->socket_mode)!=0){
			fprintf(stderr, "%s", mode_error);
			goto err_out;
		}
		mode_t mode = strtol(jalls_ctx->socket_mode, NULL, 8);
		dfprintf(stderr, "int value %i for mode %s\n", mode, jalls_ctx->socket_mode);
		if (performChmod(jalls_ctx->socket, mode)!=0){
			fprintf(stderr, "failed to set perms on the socket: %s\n", strerror(errno));
			goto err_out;
		}

		int owner_id = geteuid();
		int group_id = getgid();
		if(jalls_ctx->socket_owner){
			dfprintf(stderr, "Trying to get userid for socket_owner: %s ...\n", jalls_ctx->socket_owner);
			owner_id = get_userid_from_username(jalls_ctx->socket_owner);
			dfprintf(stderr, "Success: %i\n", owner_id);
			if (owner_id<0){
				fprintf(stderr, "failed to get socket owner id for %s\n", jalls_ctx->socket_owner);
				goto err_out;
			}
		}
		if(jalls_ctx->socket_group){
			dfprintf(stderr, "Trying to get groupid for socket_group: %s ...\n", jalls_ctx->socket_group);
			group_id = get_groupid_from_groupname(jalls_ctx->socket_group);
			dfprintf(stderr, "Success: %i\n", group_id);
			if (group_id<0){
				fprintf(stderr, "failed to get socket group id for %s\n", jalls_ctx->socket_group);
				goto err_out;
			}
		}
		if(jalls_ctx->socket_group || jalls_ctx->socket_owner){
			if (owner_id==0){
				if(chown(jalls_ctx->socket, owner_id, group_id)!=0){
					fprintf(stderr, "failed to set ownership on the socket as root: %s\n", strerror(errno));
					goto err_out;
				}
				dfprintf(stderr, "root has set ownership on the socket\n");
			}
			else{
				if (performChown(jalls_ctx->socket, owner_id, group_id)!=0){
					fprintf(stderr, "failed to set ownership on the socket: %s\n", strerror(errno));
					goto err_out;
				}
			}
		}
		dfprintf(stderr, "Socket Created!\n");

	}
	//the paths must be made absolute before daemonizing
	absolute_path = NULL;	
	absolute_path = realpath(jalls_ctx->schemas_root, NULL);
	if(absolute_path == NULL){
		fprintf(stderr, "failed getting schemas_root absolute path for: %s\n", jalls_ctx->schemas_root);
		goto err_out;
	}
	free(jalls_ctx->schemas_root);
	jalls_ctx->schemas_root = absolute_path;
	absolute_path = NULL;

	if (systemd_sockfd<0){
		absolute_path = NULL;
		absolute_path = realpath(jalls_ctx->socket, NULL);
		if(absolute_path == NULL){
			fprintf(stderr, "failed getting socket absolute path for: %s\n", jalls_ctx->socket);
			goto err_out;
		}
		free(jalls_ctx->socket);
		jalls_ctx->socket = absolute_path;
		absolute_path = NULL;
	}
	if (jalls_ctx->log_dir){
		absolute_path = NULL;
		absolute_path = realpath(jalls_ctx->log_dir, NULL);
		if(absolute_path == NULL){
			fprintf(stderr, "failed getting log_dir absolute path for: %s\n", jalls_ctx->log_dir);
			goto err_out;
		}
		free(jalls_ctx->log_dir);
		jalls_ctx->log_dir = absolute_path;
		absolute_path = NULL;
	}
	dfprintf(stderr, "private_key_file:%s \npublic_cert_file:%s \ndb_root:%s \nschemas_root:%s \nsocket:%s \nlog_dir:%s\n", 
		jalls_ctx->private_key_file, jalls_ctx->public_cert_file, jalls_ctx->db_root, jalls_ctx->schemas_root, jalls_ctx->socket, jalls_ctx->log_dir);
	
	if (jalls_ctx->daemon) {
		dfprintf(stderr, "daemonizing...\n");
		err = jalu_daemonize(jalls_ctx->log_dir, jalls_ctx->pid_file);
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

	if(seccomp_config.enable_seccomp){
		if (configureFinalSeccomp()!=0){
			goto err_out;
		}
	}

	if(sock==systemd_sockfd){
		sd_notify(0, "READY=1");
	}
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
			dfprintf(stderr, "Thread_count: %d\n", thread_count);
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
			dfprintf(stderr, "Accept_delay: %ld microSec\n", accept_delay);
			usleep((useconds_t)accept_delay);
		}

		if (should_exit) {
			break;
		}

		thread_ctx->fd = accept(sock, (struct sockaddr *) &peer_addr, &peer_addr_size);
		if (should_exit) {
			break;
		}
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
			dfprintf(stderr, "Failed to accept: %s\n", strerror(my_errno));
		}
		if (should_exit) {
			break;
		}
	}

err_out:
	if (jalls_ctx && 0 == old_socket_exist) {
		dfprintf(stderr, "Deleting Socket\n");
		close(sock);
		delete_socket(jalls_ctx->socket, jalls_ctx->debug);
	}
	RSA_free(key);
	X509_free(cert);
	jalls_shutdown();
	jaldb_context_destroy(&db_ctx);	
	config_destroy(&sc_config);
	
	exit(-1);

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
				fprintf(stderr,"Failed to parse errno.\n");
			}
			fprintf(stderr,
				"Error deleting socket file: %s path: %s\n",
				buf, p_socket_path);
			free(buf);
		}
	}
	else {
		fprintf(stderr,"Removed jal.sock socket: %s\n", p_socket_path);
	}
}

static int get_thread_count()
{
	FILE *self_status_file = NULL;

	const char *self_status_file_path = "/proc/self/status";
	const char *threads_token = "Threads:";
	size_t thread_token_length = strlen(threads_token);
	int thread_count = 0;
	char one_line [100];
	const int line_length = sizeof(one_line);
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

static int get_sockfd_from_systemd()
{
	int num_fds;
	int socketfd = -1;

	num_fds = sd_listen_fds(0);
	if (num_fds<0){
		fprintf(stderr, "No file descriptors from systemd\n");
		return -1;
	}
	for (int x=0; x<num_fds; x++){
		fprintf(stderr, "FD: %i \n", x+SD_LISTEN_FDS_START);
		if (sd_is_socket_unix(x+SD_LISTEN_FDS_START, -1, SOCK_STREAM, NULL, 0)){
			socketfd = x+SD_LISTEN_FDS_START;
			break;
		}
	}
	if (socketfd == -1){
		dfprintf(stderr, "No socket file desriptors found from systemd\n");
	}
	return socketfd;
}
static int check_mode(char * mode){
	if (strlen(mode)!=4){
		return -1;
	}
	for (int x=0; x<4; x++){
		//ascii 48=0 ascii 55=7
		if(mode[x]<48 || mode[x]>55){
			return -1;
		}
	}
	return 0;
}
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct jalls_context * cli_ctx = state->input;
	switch (key)
	{
		case 'd':
			debug = 1;
			break;
		case 's':
			cli_ctx->socket = arg;
			break;
		case 'o':
			cli_ctx->socket_owner = arg;
			break;
		case 'g':
			cli_ctx->socket_group = arg;
			break;
		case 'm':
			if (check_mode(arg)!=0){
				argp_failure(state, 1, 0, "%s", mode_error);
				argp_usage(state);
			}
			else
			{
				cli_ctx->socket_mode = arg;
			}
			break;
                case 'r':
			cli_ctx->db_recover = 1;
			break;
		case 'n':
			cli_ctx->daemon = 0;
			break;
		case 'c':
			config_path = arg;
			break;
		case ARGP_KEY_END:
			if(!config_path)
			{
				argp_failure(state, 1, 0, "required -c");
				argp_usage(state);
			}
			else
			{
				struct stat config_stat;
				int ret = stat(config_path, &config_stat);
				if(ret<0)
				{
					argp_failure(state, 1, 0, "Cannot stat config path: %s", config_path);
					argp_usage(state);
				}
			}
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
void merge_jal_contexts(struct jalls_context cli_ctx, struct jalls_context *out_ctx)
{
	if (cli_ctx.socket)
	{
		if (out_ctx->socket){
			free(out_ctx->socket);
		}
		out_ctx->socket = jal_strdup(cli_ctx.socket);
	}
	if (cli_ctx.socket_owner)
	{
		if (out_ctx->socket_owner){
			free(out_ctx->socket_owner);
		}
		out_ctx->socket_owner = jal_strdup(cli_ctx.socket_owner);
	}
	if (cli_ctx.socket_group)
	{
		if (out_ctx->socket_group){
			free(out_ctx->socket_group);
		}
		out_ctx->socket_group = jal_strdup(cli_ctx.socket_group);
	}
	if (cli_ctx.socket_mode)
	{
		if (out_ctx->socket_mode){
			free(out_ctx->socket_mode);
		}
		out_ctx->socket_mode = jal_strdup(cli_ctx.socket_mode);
	}
        if (cli_ctx.db_recover>-1)
	{
		out_ctx->db_recover = cli_ctx.db_recover;
	}
	if (cli_ctx.daemon>-1)
	{
		out_ctx->daemon = cli_ctx.daemon;
	}
}
