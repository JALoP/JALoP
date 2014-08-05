/**
 * @file jal_subscribe.cpp This file contains functions the main function of the
 * jal_subscribe program.
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

#include <getopt.h>
#include <libconfig.h>
#include <syslog.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <jalop/jaln_network.h>
#include <jalop/jal_version.h>
#include "jaldb_context.hpp"
#include "jalu_daemonize.h"
#include "jsub_db_layer.hpp"
#include "jsub_callbacks.hpp"

#define DEBUG_MODE_ON 1
#define DEBUG_MODE_OFF 0
#define PRIVATE_KEY "private_key"
#define PUBLIC_CERT "public_cert"
#define REMOTE_CERT "remote_cert"
#define SESSION_TIMEOUT "session_timeout"
#define DATA_CLASS "data_class"
#define PORT "port"
#define HOST "host"
#define MODE "mode"
#define PENDING_DIGEST_MAX "pending_digest_max"
#define PENDING_DIGEST_TIMEOUT "pending_digest_timeout"
#define DB_ROOT "db_root"
#define SCHEMAS_ROOT "schemas_root"
#define MAX_PORT_LENGTH 10
#define VERSION_CALLED 1

#define DEBUG_LOG(args...) \
	do { \
		time_t rawtime; \
		time(&rawtime); \
		char timestr[26]; \
		strftime(timestr, 26, "%Y-%m-%dT%H:%M:%S", gmtime(&rawtime)); \
		fprintf(stdout, "(jal_subscribe) %s[%d](%s) ", __FUNCTION__, __LINE__, timestr); \
		fprintf(stdout, ##args); \
		fprintf(stdout, "\n"); \
	} while(0)

volatile sig_atomic_t timer_keep_going = 1;
volatile bool global_quit = false;
jaldb_context *jsub_db_ctx = NULL;

struct global_config_t {
	const char *private_key;
	const char *public_cert;
	const char *remote_cert;
	const char *session_timeout;
	config_setting_t *data_class;	/* Array */
	long long int port;
	const char *host;
	const char *mode;
	long long int pending_digest_max;
	long long int pending_digest_timeout;
	int len_data_class;
	const char *db_root;
	const char *schemas_root;
	int data_classes;
} global_config;

struct global_args_t {
	int debug_flag;		/* --debug option */
	char *config_path;	/* --config option */
	bool enable_tls;	/* --disable_tls option */
} global_args;

enum jal_subscribe_status {
	JAL_E_CONFIG_LOAD = -1
};

static void usage();
static int process_options(int argc, char **argv);
static int config_load(config_t *config, char *config_path);
static void init_global_config(void);
static void free_global_args(void);
static void print_config(void);
static int set_global_config(config_t *config);
static void *timer_do_work(void *ptr);
static void *subscriber_do_work(void *ptr);
static unsigned int get_seconds_from_timeout(char *session_timeout);
static void catch_alarm(int sig);

static void sig_handler(__attribute__((unused)) int sig)
{
	global_quit = true;
}

static int setup_signals(void)
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

int main(int argc, char **argv)
{
	int rc = 0;
	pthread_t thread_timer, thread_subscriber;
	int rc_timer, rc_subscriber;
	config_t config;
	config_init(&config);
	jsub_is_conn_closed = false; // Externed in jsub_callbacks

	rc = setup_signals();
	if (0 != rc) {
		goto out;
	}

	if (VERSION_CALLED == process_options(argc, argv)) {
		goto version_out;
	}

	DEBUG_LOG("Config Path: %s\tDebug: %d",
		 global_args.config_path, global_args.debug_flag);
	if (!global_args.config_path){
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
	rc = config_load(&config, global_args.config_path);
	if (rc == JAL_E_CONFIG_LOAD){
		goto out;
	}
	jsub_debug = global_args.debug_flag;
	if (global_args.debug_flag) {
		DEBUG_LOG("Config load result: %d", rc);
	}
	init_global_config();
	rc = set_global_config(&config);
	if (rc == JAL_E_CONFIG_LOAD){
		goto out;
	}
	print_config();
	jsub_db_ctx = jsub_setup_db_layer(global_config.db_root, global_config.schemas_root);
	if (!jsub_db_ctx) {
		if (global_args.debug_flag) {
			DEBUG_LOG("DBLayer Setup Failed!");
		}
		goto out;
	}
	jsub_flush_stale_data(jsub_db_ctx, global_config.host, global_config.data_classes, global_args.debug_flag);
	if (global_args.debug_flag) {
		DEBUG_LOG("DBLayer Setup Success!");
	}
	/* Handler for SIGALRM signals */
	signal(SIGALRM, catch_alarm);
	rc_timer = pthread_create(
				&thread_timer,
				NULL,
				timer_do_work,
				(void *) global_config.session_timeout);
	rc_subscriber = pthread_create(
				&thread_subscriber,
				NULL,
				subscriber_do_work,
				(void *) &global_config);

	pthread_join(thread_timer, NULL);
	pthread_join(thread_subscriber, NULL);
	if (global_args.debug_flag) {
		DEBUG_LOG("Threads joined!");
	}
out:
	free_global_args();
	jsub_teardown_db_layer(&jsub_db_ctx);
	config_destroy(&config);
	if (global_args.debug_flag) {
		DEBUG_LOG("Cleanup completed!");
	}
	return rc;

version_out:
	config_destroy(&config);
	return 0;
}

int process_options(int argc, char **argv)
{
	int opt = 0;
	int long_index = 0;

	static const char *opt_string = "c:dvs";
	static const struct option long_options[] = {
		{"config", required_argument, NULL,'c'}, /* --config or -c */
		{"debug", no_argument, NULL, 'd'}, /* --debug or -d */
		{"version", no_argument, NULL, 'v'}, /* --version or -v */
		{"disable-tls", no_argument, NULL, 's'}, /* --disable-tls or -s */
		{0, 0, 0, 0} /* terminating -0 item */
	};

	global_args.debug_flag = DEBUG_MODE_OFF;
	global_args.config_path = NULL;
	global_args.enable_tls = true;

	opt = getopt_long(argc, argv, opt_string, long_options, &long_index);

	while(opt != -1){
		switch (opt) {
			case 'd':
				global_args.debug_flag = DEBUG_MODE_ON;
				break;
			case 'c':
				global_args.config_path = strdup(optarg);
				break;
			case 'v':
				printf("%s\n", jal_version_as_string());
				return VERSION_CALLED;
				break;
			case 's':
				global_args.enable_tls = false;
				break;
			case 0:
				break;
			default:
				usage();
		}
		opt = getopt_long(argc, argv, opt_string, long_options, &long_index);
	}
	if (!global_args.config_path) {
		usage();
	}

	return 0;
}

__attribute__((noreturn)) void usage()
{
        fprintf(stderr, "Usage: jal_subscribe -c, --config <config_directory> [-d, --debug] [-s, --disable-tls] [-v, --version]\n");
        exit(1);
}

int config_load(config_t *config, char *config_path)
{
	int rc = 0;

	if (!config || !config_path) {
		if (global_args.debug_flag) {
			DEBUG_LOG("Failed to load config!");
		}
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
	rc = config_read_file(config, config_path);
	if (rc != CONFIG_TRUE) {
		if (global_args.debug_flag) {
			DEBUG_LOG("Failure reading config file, rc: %d, %s, line: %d", rc,
			       config_error_text(config),
			       config_error_line(config));
		}
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
out:
	return rc;
}

void init_global_config(void)
{
	global_config.private_key = NULL;
	global_config.public_cert = NULL;
	global_config.remote_cert = NULL;
	global_config.session_timeout = NULL;
	global_config.data_class = NULL;
	global_config.host = NULL;
	global_config.mode = NULL;
	global_config.db_root = NULL;
	global_config.schemas_root = NULL;
	global_config.data_classes = 0;
}

void free_global_args(void)
{
	free((void*) global_args.config_path);
}

void print_config(void)
{
	if (global_args.debug_flag) {
		DEBUG_LOG("\n===\nBEGIN CONFIG VALUES:\n===");
		if (global_args.enable_tls) {
			DEBUG_LOG("PRIVATE KEY:\t\t%s", global_config.private_key);
			DEBUG_LOG("PUBLIC CERT:\t\t%s", global_config.public_cert);
			DEBUG_LOG("REMOTE CERT:\t\t%s", global_config.remote_cert);
		} else {
			DEBUG_LOG("!!!!!!!! TLS IS DISABLED !!!!!!!!");
		}
		DEBUG_LOG("SESSION TIMEOUT:\t%s", global_config.session_timeout);
		//DEBUG_LOG("DATA CLASS:\t\t%s\n", global_config.data_class);
		DEBUG_LOG("DATA CLASS LENGTH:\t%d", global_config.len_data_class);
		DEBUG_LOG("PORT:\t\t\t%lld", global_config.port);
		DEBUG_LOG("HOST:\t\t\t%s", global_config.host);
		DEBUG_LOG("MODE:\t\t\t%s", global_config.mode);
		DEBUG_LOG("PENDING DIGEST MAX:\t%lld", global_config.pending_digest_max);
		DEBUG_LOG("PENDING DIGEST TIMEOUT:\t%lld", global_config.pending_digest_timeout);
		DEBUG_LOG("DB ROOT:\t\t%s\n", global_config.db_root);
		DEBUG_LOG("SCHEMAS ROOT:\t\t%s\n", global_config.schemas_root);
		DEBUG_LOG("\n===\nEND CONFIG VALUES:\n===");
	}
}

int set_global_config(config_t *config)
{
	int rc = 0;
	if (!config){
		if (global_args.debug_flag) {
			DEBUG_LOG("Config is NULL!");
		}
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
	// REQUIRED CONFIG VALUES
	rc = 0;
	if (global_args.enable_tls) {
		rc = config_lookup_string(config, PRIVATE_KEY, &global_config.private_key);
		if (rc == CONFIG_FALSE){
			if (global_args.debug_flag) {
				DEBUG_LOG("Missing setting for '%s'", PRIVATE_KEY);
			}
			rc = JAL_E_CONFIG_LOAD;
			goto out;
		}
		rc = config_lookup_string(config, PUBLIC_CERT, &global_config.public_cert);
		if (rc == CONFIG_FALSE){
			if (global_args.debug_flag) {
				DEBUG_LOG("Missing setting for '%s'", PUBLIC_CERT);
			}
			rc = JAL_E_CONFIG_LOAD;
			goto out;
		}
		rc = config_lookup_string(config, REMOTE_CERT, &global_config.remote_cert);
		if (rc == CONFIG_FALSE){
			if (global_args.debug_flag) {
				DEBUG_LOG("Missing setting for '%s'", REMOTE_CERT);
			}
			rc = JAL_E_CONFIG_LOAD;
			goto out;
		}
	}
	rc = config_lookup_int64(config, PORT, &global_config.port);
	if (rc == CONFIG_FALSE){
		if (global_args.debug_flag) {
			DEBUG_LOG("Missing setting for '%s'", PORT);
		}
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
	rc = config_lookup_string(config, HOST, &global_config.host);
	if (rc == CONFIG_FALSE){
		if (global_args.debug_flag) {
			DEBUG_LOG("Missing setting for '%s'", HOST);
		}
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
	rc = config_lookup_string(config, MODE, &global_config.mode);
	if (rc == CONFIG_FALSE){
		if (global_args.debug_flag) {
			DEBUG_LOG("Missing setting for '%s'", MODE);
		}
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
	rc = config_lookup_int64(config, PENDING_DIGEST_MAX, &global_config.pending_digest_max);
	if (rc == CONFIG_FALSE){
		if (global_args.debug_flag) {
			DEBUG_LOG("Missing setting for '%s'", PENDING_DIGEST_MAX);
		}
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
	rc &= config_lookup_int64(config, PENDING_DIGEST_TIMEOUT, &global_config.pending_digest_timeout);
	if (rc == CONFIG_FALSE){
		if (global_args.debug_flag) {
			DEBUG_LOG("Missing setting for '%s'", PENDING_DIGEST_TIMEOUT);
		}
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
	global_config.data_class = config_lookup(config, DATA_CLASS);	// Array
	if (!global_config.data_class) {
		if (global_args.debug_flag) {
			DEBUG_LOG("Data class was not found in configuration file and is required!");
		}
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
	if (!config_setting_is_array(global_config.data_class)) {
		if (global_args.debug_flag) {
			DEBUG_LOG("Expected data_class to be an array!");
		}
		rc = JAL_E_CONFIG_LOAD;
		goto out;
	}
	global_config.len_data_class = config_setting_length(global_config.data_class);

	// Iterate through the data classes and create the
	//	appropriate record_type mask
	for (int i = 0; i < global_config.len_data_class; i++){
		const char *value = config_setting_get_string_elem(
						global_config.data_class,
						i);
		if (0 == strcmp(value, "journal")){
			global_config.data_classes =
					global_config.data_classes |
					JALN_RTYPE_JOURNAL;
		}
		if (0 == strcmp(value, "audit")){
			global_config.data_classes =
					global_config.data_classes |
					JALN_RTYPE_AUDIT;
		}
		if (0 == strcmp(value, "log")){
			global_config.data_classes =
					global_config.data_classes |
					JALN_RTYPE_LOG;
		}
	}

	// OPTIONAL CONFIG VALUES
	rc = config_lookup_string(config, SESSION_TIMEOUT, &global_config.session_timeout);
	if (rc == CONFIG_FALSE){
		global_config.session_timeout = NULL; // NULL or Zero is INFINITE
	}

	rc = config_lookup_string(config, DB_ROOT, &global_config.db_root);
	if (rc == CONFIG_FALSE){
		global_config.db_root = NULL;
	}

	rc = config_lookup_string(config, SCHEMAS_ROOT, &global_config.schemas_root);
	if (rc == CONFIG_FALSE) {
		global_config.schemas_root = NULL;
	}
out:
	return rc;
}

void *timer_do_work(void *ptr)
{
	// If ptr is NULL or seconds is Zero,
	//	subscriber runs indefinitely.
	char *session_timeout = NULL;
	if (ptr){
		// session_timeout was specified
		session_timeout = strdup((char *) ptr);  // Format - hh:mm:ss
		unsigned int seconds = get_seconds_from_timeout(session_timeout);

		if (global_args.debug_flag) {
			DEBUG_LOG("timer_do_work: session_timeout - %s\t%s",
				  session_timeout, (char *) ptr);
			DEBUG_LOG("timer_do_work: total_seconds - %d",
				  seconds);
		}
		if (seconds > 0) {
			// Seconds was non-zero
			alarm(seconds);

			while(timer_keep_going
				&& !jsub_is_conn_closed){
				sleep(1); // Sleep for 1 second
			}
			if (global_args.debug_flag) {
				DEBUG_LOG("Session timeout elapsed!");
			}
			global_quit = true;
		}
	}
	// Cleanup
	free(session_timeout);
	DEBUG_LOG("timer_do_work: thread exited!");
	return NULL;
}

unsigned int get_seconds_from_timeout(char *session_timeout)
{
	char *str_hour = NULL;
	char *str_minute = NULL;
	char *str_second = NULL;
	unsigned int total_seconds = 0;
	int hour = 0;
	int minute = 0;
	int second = 0;

	if (!session_timeout){
		goto out;
	}
	str_hour = strtok(session_timeout, ":");
	str_minute = strtok(NULL, ":");
	str_second = strtok(NULL,"\0");

	hour = atoi(str_hour);
	minute = atoi(str_minute);
	second = atoi(str_second);

	total_seconds += hour * 60 * 60;
	total_seconds += minute * 60;
	total_seconds += second;
out:
	return total_seconds;
}

//
// Taken from: www.gnu.org/s/hello/manual/libc/Handler-Returns.html#Handler-Returns
//
// Signal handler clears the flag and re-enables itself.
void catch_alarm(int sig)
{
	timer_keep_going = 0;
	signal(sig, catch_alarm);
}

void *subscriber_do_work(void *ptr)
{
	char port[MAX_PORT_LENGTH];
	int ret = sprintf(port, "%lld", global_config.port);
	struct jaln_connection *conn = NULL;
	struct global_config_t *cfg = (struct global_config_t *) ptr;
	cfg = cfg;
	jaln_context *net_ctx = jaln_context_create();
	struct jal_digest_ctx *dc1 = jal_sha256_ctx_create();
	enum jal_status err;
	enum jaln_publish_mode mode = JALN_UNKNOWN_MODE;

	if (0 > ret){
		if (global_args.debug_flag) {
			DEBUG_LOG("Port wasn't converted to string! Quitting.");
		}
		goto err;
	}
	jaln_register_digest_algorithm(net_ctx, dc1);
	if (global_args.enable_tls) {
		err = jaln_register_tls(net_ctx,
					global_config.private_key,
					global_config.public_cert,
					global_config.remote_cert);
		if (JAL_OK != err) {
			if (global_args.debug_flag) {
				DEBUG_LOG("Error w/ registration of TLS! Quitting.");
			}
			goto err;
		}
	}
	err = jaln_register_encoding(net_ctx, "xml");
	err = jsub_callbacks_init(net_ctx);
	if (JAL_OK != err) {
		if (global_args.debug_flag) {
			DEBUG_LOG("Error w/ registration of encoding, digest or callbacks! Quitting.");
		}
		goto err;
	}
	if (0 == strcmp("archive",global_config.mode)) {
		mode = JALN_ARCHIVE_MODE;
	} else if (0 == strcmp("live",global_config.mode)) {
		mode = JALN_LIVE_MODE;
	} else {
		DEBUG_LOG("Bad mode specification in config file! Quitting.");
		goto err;
	}
	conn = jaln_subscribe(
				net_ctx,
				global_config.host,
				port,
				global_config.data_classes,
				mode,
				jsub_db_ctx);
	if (!conn){
		if (global_args.debug_flag) {
			DEBUG_LOG("conn null, quitting!");
		}
		goto err;
	}
	while(!jsub_is_conn_closed){
		if (global_quit) {
			if (global_args.debug_flag) {
				DEBUG_LOG("Subscribe thread ending!");
			}
			err = jaln_disconnect(conn);
			if (JAL_OK != err) {
				if (global_args.debug_flag) {
					DEBUG_LOG("Subscriber failed to disconnect!");
				}
			}
			break;
		}
		sleep(1);
	}
err:
	timer_keep_going = false;
	err = jaln_shutdown(conn);
	if (JAL_OK != err) {
		if (global_args.debug_flag) {
			DEBUG_LOG("Subscriber failed to shutdown network connection!");
		}
	}
	jaln_context_destroy(&net_ctx);
	free(conn);
	if (global_args.debug_flag) {
		printf("Subscribe thread exited!");
	}
	return NULL;
}

