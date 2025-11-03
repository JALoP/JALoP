/**
 * @file
 *
 * @brief This file contains functions the main function of the
 * jal local store
 *
 * ### LICENSE
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
#include <jalop/jal_seccomp_enforcer.h>
#include "jalls_config.h"
#include "jalu_daemonize.h"
#include "jal_config.h"
#include "jaldb_config.h"
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
	EVP_PKEY *key = NULL;
	X509 *cert = NULL;
	jaldb_context *db_ctx = NULL;
	struct jalls_context *jalls_ctx = NULL;
	enum jal_status jal_err = JAL_E_INVAL;
	int sock = -1;
	int old_socket_exist = 0;
	char * absolute_path = NULL;
	struct jal_seccomp_enforcer_t* seccomp_enforcer = NULL;
	typedef struct JallsThreadStruct {
		struct jalls_thread_context* context;
		pthread_t thread;
	} JallsThread;
	JallsThread* thread_array = NULL;
	// Perform signal hookups
	if ( 0 != setup_signals()) {
		goto err_out;
	}

	if (0 != jalls_init()) {
		goto err_out;
	}

	debug = 0;
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
	// config_path must be set at this point
	// Create a seccomp policy enforcer using the config file
	seccomp_enforcer = jal_seccomp_enforcer_create(config_path);
	if(NULL == seccomp_enforcer){
		goto err_out;
	}

	jalls_ctx->debug = debug;

	// Enforce initial seccomp policy set
	if (0 != jal_seccomp_enforcer_apply_initial(seccomp_enforcer)){
		goto err_out;
	}

	jal_err = jal_create_dirs(jalls_ctx->db_root);
	if (JAL_OK != jal_err) {
		fprintf(stderr, "failed to create database directory\n");
		goto err_out;
	}

	//load the private key
	if (jalls_ctx->private_key_file) {
		absolute_path = NULL;
		absolute_path = jal_expand_path(jalls_ctx->private_key_file, JALLS_CFG_PRIVATE_KEY_FILE);
		if(absolute_path == NULL){
			//Error already displayed from method above
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
		key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
		fclose(fp);
		if (!key) {
			fprintf(stderr, "failed to read private key\n");
			goto err_out;
		}
	}

	//load the public cert
	if (jalls_ctx->public_cert_file) {
		absolute_path = NULL;
		absolute_path = jal_expand_path(jalls_ctx->public_cert_file, JALLS_CFG_PUBLIC_CERT_FILE);
		if(absolute_path == NULL){
			//Error already displayed from method above
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
		fclose(fp);
		if (!cert) {
			fprintf(stderr, "failed to read public cert\n");
			goto err_out;
		}
	}

	//create a jaldb_context to pass to work threads
	absolute_path = NULL;
	absolute_path = jal_expand_path(jalls_ctx->db_root, JALLS_CFG_DB_ROOT);

	if(absolute_path == NULL){
		//Error already displayed from method above
		goto err_out;
	}

	free(jalls_ctx->db_root);
	jalls_ctx->db_root = absolute_path;
	absolute_path = NULL;

	db_ctx = jaldb_context_create();

	//Attempts to load optional LMDB_CONFIG file in db_root
	//If present, this will override the lmdb performance level
	//and lmdb map size, otherwise default values will be used.
	jaldb_config *jdb_config = NULL;
	enum jaldb_config_status rc = get_jaldb_config(jalls_ctx->db_root, &jdb_config);
	if (rc != JALDB_CONFIG_OK && rc != JALDB_CONFIG_E_NOTFOUND) {
		old_socket_exist = 1; //Prevent trying to delete socket since it wasn't created yet.
		goto err_out;
	}

	//Only override map size if present in config
	enum jaldb_flags jdb_flags = JDB_LMDB_PERFORMANCE_LEVEL2;
	jalls_ctx->map_size = DEFAULT_LMDB_MAP_SIZE;
	jalls_ctx->database_option = jal_strdup(JDB_LMDB_PERFORMANCE_LEVEL2_STR);

	if (rc != JALDB_CONFIG_E_NOTFOUND)
	{
		if (jdb_config->map_size != 0)
		{
			jalls_ctx->map_size = jdb_config->map_size;
		}

		//Only override database option if present in config
		if (NULL != jdb_config->database_option)
		{
			jdb_flags = jdb_config->jdb_flags;
			free(jalls_ctx->database_option);
			jalls_ctx->database_option = jal_strdup(jdb_config->database_option);
		}
		free_jaldb_config(&jdb_config);
	}

	enum jaldb_status jaldb_err = jaldb_context_init(db_ctx, jalls_ctx->db_root, jdb_flags, jalls_ctx->map_size);
	if (jaldb_err != JALDB_OK) {
		fprintf(stderr, "failed to create the jaldb_context\n");
		goto err_out;
	}

	//Expands any "~/" in socket path first so the socket can be created
	absolute_path = jal_expand_home_dir(jalls_ctx->socket, JALLS_CFG_SOCKET);
	if(absolute_path == NULL){
		//Error already displayed from method above
		goto err_out;
	}

	free(jalls_ctx->socket);
	jalls_ctx->socket = absolute_path;
	absolute_path = NULL;

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
	absolute_path = jal_expand_path(jalls_ctx->schemas_root, JALLS_CFG_SCHEMAS_ROOT);
	if(absolute_path == NULL){
		//Error already displayed from method above
		goto err_out;
	}

	free(jalls_ctx->schemas_root);
	jalls_ctx->schemas_root = absolute_path;
	absolute_path = NULL;

	if (systemd_sockfd<0){
		absolute_path = NULL;
		absolute_path = jal_expand_path(jalls_ctx->socket, JALLS_CFG_SOCKET);
		if(absolute_path == NULL){
			//Error already displayed from method above
			goto err_out;
		}

		free(jalls_ctx->socket);
		jalls_ctx->socket = absolute_path;
		absolute_path = NULL;
	}
	if (jalls_ctx->log_dir){
		absolute_path = NULL;
		absolute_path = jal_expand_path(jalls_ctx->log_dir, JALLS_CFG_LOG_DIR);
		if(absolute_path == NULL){
			//Error already displayed from method above
			goto err_out;
		}

		free(jalls_ctx->log_dir);
		jalls_ctx->log_dir = absolute_path;
		absolute_path = NULL;
	}

	if (jalls_ctx->pid_file){
		absolute_path = NULL;
		absolute_path = jal_expand_home_dir(jalls_ctx->pid_file, JALLS_CFG_PID_FILE);
		if(absolute_path == NULL){
			//Error already displayed from method above
			goto err_out;
		}

		free(jalls_ctx->pid_file);
		jalls_ctx->pid_file = absolute_path;
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

	}

	dfprintf(stderr, "journal_record_size_limit: %lld\n", jalls_ctx->journal_record_size_limit);
	dfprintf(stderr, "audit_record_size_limit: %lld\n", jalls_ctx->audit_record_size_limit);
	dfprintf(stderr, "log_record_size_limit: %lld\n", jalls_ctx->log_record_size_limit);
	dfprintf(stderr, "database_option: %s\n", jalls_ctx->database_option);
	free(jalls_ctx->database_option);
	dfprintf(stderr, "lmdb_map_size (GB): %d\n", jalls_ctx->map_size);

	struct sockaddr_un peer_addr;
	unsigned int peer_addr_size = sizeof(peer_addr);

	const int min_thread_count_intervention = jalls_ctx->accept_delay_thread_count;
	const int max_thread_count_intervention = jalls_ctx->accept_delay_max;
	const int min_accept_delay = jalls_ctx->accept_delay_increment;

	if (0 != jal_seccomp_enforcer_apply_final(seccomp_enforcer)){
		goto err_out;
	}

	if(sock==systemd_sockfd){
		sd_notify(0, "READY=1");
	}

	// In order to track currently running threads, we'll make a poor man's map
	size_t tracked_thread_array_size = 10;
	size_t thread_count = 0;
	thread_array = calloc(tracked_thread_array_size, sizeof(JallsThread));

	dfprintf(stderr, "Ready to accept connections\n");
	while (!should_exit) {
		struct jalls_thread_context *thread_ctx = calloc(1, sizeof(*thread_ctx));
		if (thread_ctx == NULL) {
			if (debug) {
				fprintf(stderr, "Failed to allocate memory\n");
			}
			goto err_out;
		}

		/* Flow control functionality turned off if min_thread_count_intervention
		* set to zero in the jal-local-store configuration file
		*/
		if (0 < min_thread_count_intervention) {
			dfprintf(stderr, "Thread_count: %zu\n", thread_count);
		}

		if (0 < min_thread_count_intervention &&
			// We guard against negative values, so the cast to size_t is safe
			thread_count > (size_t)min_thread_count_intervention) {

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
			free(thread_ctx);
			break;
		}

		thread_ctx->fd = accept(sock, (struct sockaddr *) &peer_addr, &peer_addr_size);
		if(-1 == thread_ctx->fd) {
			free(thread_ctx);
			// This is normal in the case of a ctrl-C command.
			// Only print an error if errno is something other than EINTR
			if(EINTR != errno) {
				dfprintf(stderr, "Failed to accept: %s\n", strerror(errno));
			}
			// This is non-fatal but we don't have anything to connect to right now
			// Jump back to the top of the loop
			continue;
		}

		// The accept call is blocking, so make sure a kill signal didn't arrive while
		// we were waiting before we create the new thread
		if (should_exit) {
			free(thread_ctx);
			break;
		}

		// Pointer assignments are fast - there's no new memory being created here
		thread_ctx->signing_key = key;
		thread_ctx->signing_cert = cert;
		thread_ctx->db_ctx = db_ctx;
		thread_ctx->ctx = jalls_ctx;
		thread_ctx->journal_record_size_limit = jalls_ctx->journal_record_size_limit;
		thread_ctx->audit_record_size_limit = jalls_ctx->audit_record_size_limit;
		thread_ctx->log_record_size_limit = jalls_ctx->log_record_size_limit;

		// Walk the array from 0..thread_count-1
		// Check for any finished threads
		// If a thread has finished, call join to free any pthread resources
		// then pull the "last" thread in the array forward to take its slot, keeping
		// the array compact
		for(size_t i = 0; i < thread_count; i++) {
			// If this thread slot has not been initialized, we are in an error state. Abort
			if(NULL == thread_array[i].context || 0 == thread_array[i].thread) {
				fprintf(stderr, "Corruption of thread handles detected: uninitialized thread. Exiting.");
				free(thread_ctx);
				goto err_out;
			}

			// If a thread has finished...
			if(thread_array[i].context->finished) {
				// Call join to free its resources.
				// This should return immediately
				void* retval = NULL;
				int join_err = pthread_join(thread_array[i].thread, &retval);
				if(0 != join_err) {
					fprintf(stderr, "Failed to join thread with error: %d\n", join_err);
				}
				// Free our context associated with the finished thread
				free(thread_array[i].context);

				// If and only if the thread_array contains more than one thread
				// AND this isn't the last thread
				if(thread_count > 1 && i < thread_count-1) {
					// This slot is now open. Promote the "last" thread to this slot
					// and zero out the slot we're promoting from
					thread_array[i].thread = thread_array[thread_count-1].thread;
					thread_array[i].context = thread_array[thread_count-1].context;
					thread_array[thread_count-1].thread = 0;
					thread_array[thread_count-1].context = NULL;
				}
				thread_count -= 1;
				fprintf(stderr, "thread removed, count now: %zu\n", thread_count);
				// Go back to the top of the loop - decrementing i by one since we need
				// to re-examine the thread we've just placed into slot i
				i -= 1;
				continue;
			}
		}

		// Now that we've walked our entire array compacting it, we can place our new thread
		// at thread_array[thread_count]
		// But first, make sure we have room
		if(thread_count > tracked_thread_array_size) {
			// This shouldn't be possible unless there's a logical error nearby
				fprintf(stderr, "Corruption of thread handles detected: Array overrun. Exiting.");
				free(thread_ctx);
				goto err_out;
		}
		if(thread_count == tracked_thread_array_size) {
			// TODO - We never shrink this back down. This is unlikely to get so
			// large to need to be shrunk since we re-fill empty slots before
			// making new ones, but someone eventually might want this.
			//
			// Realloc our array, doubling its size
			JallsThread* new_array = realloc(thread_array, tracked_thread_array_size*2*sizeof(JallsThread));
			if(NULL == new_array) {
				fprintf(stderr, "Failed to increase thread array size with error: %s. "
					"Aborting new thread creation\n", strerror(errno));
				free(thread_ctx);
				continue;
			}
			thread_array = new_array;

			// Zero out all the new memory so our NULL checks will work correctly on new slots
			// Since we're doubling the size, both our offset and length happen to be
			// tracked_thread_array_size (prior to doubling it)
			memset(&thread_array[tracked_thread_array_size], 0, tracked_thread_array_size * sizeof(JallsThread));

			tracked_thread_array_size = tracked_thread_array_size*2;
			fprintf(stderr, "Reallocated thread pool to size: %zu\n", tracked_thread_array_size);
		}

		// Create our new thread in the array slot
		int pthread_err = pthread_create(&thread_array[thread_count].thread, NULL, jalls_handler, thread_ctx);
		if (0 != pthread_err) {
			fprintf(stderr, "Failed to create pthread: %s\n", strerror(errno));
			free(thread_ctx);
			thread_array[thread_count].thread = 0;
			continue;
		}

		// Attach our context to this thread slot
		thread_array[thread_count].context = thread_ctx;
		thread_count += 1;
		fprintf(stderr, "thread added, count now: %zu\n", thread_count);
	}

err_out:
	if (jalls_ctx && 0 == old_socket_exist) {
		dfprintf(stderr, "Deleting Socket\n");
		close(sock);
		delete_socket(jalls_ctx->socket, jalls_ctx->debug);
	}

	// Send a kill signal to each thread which has not finished, then wait for it to join
	// And destroy any associated contexts
	if(thread_array) {
		for(size_t i = 0; i < thread_count; i++) {
			if(0 != thread_array[i].thread && NULL != thread_array[i].context) {
				if(!thread_array[i].context->finished) {
					pthread_kill(thread_array[i].thread, SIGINT);
				}
				pthread_join(thread_array[i].thread, NULL);
				free(thread_array[i].context);
			}
		}
		free(thread_array);
	}

	free(jalls_ctx->db_root);
	free(jalls_ctx->private_key_file);
	free(jalls_ctx->public_cert_file);
	free(jalls_ctx->socket);
	free(jalls_ctx->schemas_root);
	free(jalls_ctx->log_dir);
	free(jalls_ctx->pid_file);
	free(jalls_ctx->hostname);
	free(jalls_ctx);

	EVP_PKEY_free(key);
	X509_free(cert);
	jalls_shutdown();
	jaldb_context_destroy(&db_ctx);
	jal_seccomp_enforcer_destroy(&seccomp_enforcer);

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
	if (cli_ctx.daemon>-1)
	{
		out_ctx->daemon = cli_ctx.daemon;
	}
}
