/**
 * @file
 *
 * @brief This file contains functions the main function of the
 * jal_subscribe program.
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

#include <argp.h>
#include <syslog.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <jalop/jaln_network.h>
#include <jalop/jal_version.h>
#include "jaldb_context.hpp"
#include "jal_config.h"
#include "jalu_daemonize.h"
#include "jsub_db_layer.hpp"
#include "jsub_callbacks.hpp"

#include "jal_seccomp_enforcer.h"
#include "jal_subscribe_config_context.h"

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
#define WINDOW_SIZE "window_size"
#define DB_ROOT "db_root"
#define DIGEST_ALGORITHMS "digest_algorithms"
#define JOURNAL_RESUME_THRESHOLD "journal_resume_threshold_size"
#define DATABASE_OPTION "database_option"
#define MAX_PORT_LENGTH 10
#define VERSION_CALLED 1

//The size here is in kilobytes, so 4KB.
#define DEFAULT_WINDOW_SIZE 4

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
	int data_classes;
	int window_size;
	const char *digest_algorithms;
	long long int resume_threshold;

	/**This setting is used by LMDB builds only and is the LMDB flags set by the database_option config setting*/
	enum jaldb_flags jdb_flags;

	/**Stores the string value for the database_option config setting**/
	char *database_option;

} global_config;

struct global_args_t {
	char *digest_algorithms; /* --digest-algorithms option */
	char *config_path;	/* --config option */
	char *mode;  /* --mode option */
	char *dbpath;  /* --home option */
	char *ipaddr;  /* --ipaddr option */
	int port;  /* --port option */
	int debug_flag;		/* --debug option */
	bool enable_tls;	/* --disable_tls option */
	int window_size; /*beep channel window size */
} global_args;

// argp
const char *argp_program_version = "1";
const char *argp_program_bug_address = 0;
static char args_doc[] = "--config config_file";
static char doc[] = "jal_subscribe - JALoPv1 Network Store that creates a BEEP connection to a remote JALoPv1 peer and subscribes for JALoP records.";
static struct argp_option options[] =
{
	{"digest-algorithms", 'a', "algs", 0, "Allowable digest algorithms", 0},
	{"config", 'c', "file", 0, "REQUIRED: Specify the path to the configuration file.", 0},
	{"mode", 'm', "mode", 0, "Mode to run on. Valid values are 'archive' or 'live'.", 0},
	{"home", 'h', "db-root", 0, "Specify the root of the JALoP database.", 0},
	{"ipaddr", 'i', "ip-address", 0, "IP Address to listen on.", 0},
	{"port", 't', "port", 0, "Port to listen on.", 0},
	{"debug", 'd', NULL, 0, "Enable debug output.", 0},
	{"disable-tls", 's', NULL, 0, "Disable TLS authentication.", 0},
	{"window-size", 'w', NULL, 0, "The BEEP windows size.", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};
static struct argp argp = {options, jal_subscribe_parse_opt, args_doc, doc, NULL, NULL, NULL};

static int process_options(int argc, char **argv);
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
	jsub_is_conn_closed = false; // Externed in jsub_callbacks
	struct jal_seccomp_enforcer_t* seccomp_enforcer = NULL;

	rc = setup_signals();
	if (0 != rc) {
		goto out;
	}

	init_global_config();
	if (VERSION_CALLED == process_options(argc, argv)) {
		goto version_out;
	}

	DEBUG_LOG("Config Path: %s\tDebug: %d",
		global_args.config_path, global_args.debug_flag);
	if (!global_args.config_path){
		rc = JAL_CFG_FAILURE;
		goto out;
	}

	rc = jal_config_init(&config);
	if (JAL_CFG_SUCCESS != rc) {
		goto out;
	}

	seccomp_enforcer = jal_seccomp_enforcer_create(global_args.config_path);
	if(NULL == seccomp_enforcer){
		goto out;
	}

	if (0 != jal_seccomp_enforcer_apply_initial(seccomp_enforcer)){
		goto out;
	}

	rc = jal_config_read_file(&config, global_args.config_path);

	if (JAL_CFG_SUCCESS != rc) {
		goto out;
	}

	jsub_debug = global_args.debug_flag;

	if (global_args.debug_flag) {
		DEBUG_LOG("Config load result: %d", rc);
	}

	rc = set_global_config(&config);
	if (rc != JAL_CFG_SUCCESS){
		goto out;
	}
	print_config();
	jsub_db_ctx = jsub_setup_db_layer(global_config.db_root, global_config.jdb_flags);
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
	if (0 != rc_timer){
		goto out;
	}

	rc_subscriber = pthread_create(
				&thread_subscriber,
				NULL,
				subscriber_do_work,
				(void *) &global_config);
	if (0 != rc_subscriber){
		goto out;
	}

	if (0 != jal_seccomp_enforcer_apply_final(seccomp_enforcer)){
		goto out;
	}

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
	jal_seccomp_enforcer_destroy(&seccomp_enforcer);
	return rc;

version_out:
	config_destroy(&config);
	return 0;
}

void init_global_args(void)
{
	global_args.digest_algorithms = NULL;
	global_args.config_path = NULL;
	global_args.mode = NULL;
	global_args.dbpath = NULL;
	global_args.ipaddr = NULL;
	global_args.port = 0;
	global_args.debug_flag = 0;
	global_args.enable_tls = true;
	global_args.window_size = 0;
}

int process_options(int argc, char **argv)
{
	init_global_args();

	struct jal_subscribe_config_context js_conf_ctx = {
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		0,
		0,
		0,
		0
	};

	int err = argp_parse(&argp, argc, argv, 0, 0, &js_conf_ctx);
	if(0 != err) {
		fprintf(stderr, "ERROR: Cannot parse command line arguments.\n");
		exit(1);
	}
	// Used in several functions to report additional error information
	if(js_conf_ctx.conf == NULL)
	{
		fprintf(stderr, "Config file is required\n");
		exit(1);
	}

	//Sets global args
	global_args.config_path = strdup(js_conf_ctx.conf);

	if (js_conf_ctx.debug != 0)
	{
		global_args.debug_flag = DEBUG_MODE_ON;
	}

	if (js_conf_ctx.disableTls != 0)
	{
		global_args.enable_tls = false;
	}

	if (js_conf_ctx.window_size != NULL)
	{
		global_args.window_size = atoi(js_conf_ctx.window_size);
		if (global_args.window_size<1){
			fprintf(stderr, "window_size must be an integer greater then 0. \n");
			exit(1);
		}
	}

	if (js_conf_ctx.digest_algorithms != NULL)
	{
		global_args.digest_algorithms = strdup(js_conf_ctx.digest_algorithms);
	}

	if(js_conf_ctx.port != NULL)
	{
		int portno;
		int portlen = strlen(js_conf_ctx.port);
		int scanLen;
		int ret = sscanf(js_conf_ctx.port, "%d%n", &portno, &scanLen);

		if(ret == 1 && portlen == scanLen) // no error
		{
			global_args.port = portno;
		}
		else
		{
			fprintf(stderr, "Could not convert port number: %s to integral type\n", js_conf_ctx.port);
			exit(1);
		}
	}

	if(NULL != js_conf_ctx.ipaddr)
	{
		global_args.ipaddr = strdup(js_conf_ctx.ipaddr);
	}

	if(js_conf_ctx.dbpath != NULL)
	{
		global_args.dbpath = strdup(js_conf_ctx.dbpath);
	}

	if(js_conf_ctx.inmode != NULL)
	{
		global_args.mode = strdup(js_conf_ctx.inmode);
	}

	jal_subscribe_config_drop_memory(&js_conf_ctx);

	return 0;
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
	global_config.data_classes = 0;
	global_config.window_size = DEFAULT_WINDOW_SIZE;
	global_config.digest_algorithms = NULL;
	global_config.database_option = NULL;
}

void free_global_args(void)
{
	free((void*) global_args.config_path);
	free((void*) global_args.digest_algorithms);
	free((void*) global_args.ipaddr);
	free((void*) global_args.dbpath);
	free((void*) global_args.mode);
}

void print_config(void)
{
	printf("\n===\nBEGIN CONFIG VALUES:\n===\n");
	if(global_args.debug_flag) {
		printf("DEBUG:\t\tenabled\n");
	} else {
		printf("DEBUG:\t\tdisabled\n");
	}
	if (global_args.enable_tls) {
		printf("PRIVATE KEY:\t\t%s\n", global_config.private_key);
		printf("PUBLIC CERT:\t\t%s\n", global_config.public_cert);
		printf("REMOTE CERT:\t\t%s\n", global_config.remote_cert);
	} else {
		printf("!!!!!!!! TLS IS DISABLED !!!!!!!!\n");
	}
	printf("SESSION TIMEOUT:\t%s\n", global_config.session_timeout);
	printf("DATA CLASS LENGTH:\t%d\n", global_config.len_data_class);
	printf("DATA CLASSES ENABLED: ");
	if(global_config.data_classes & JALN_RTYPE_JOURNAL) {
		printf("\tjournal ");
	}
	if(global_config.data_classes & JALN_RTYPE_AUDIT) {
		printf("\taudit ");
	}
	if(global_config.data_classes & JALN_RTYPE_LOG) {
		printf("\tlog ");
	}
	printf("\n");
	printf("PORT:\t\t\t%lld\n", global_config.port);
	printf("HOST:\t\t\t%s\n", global_config.host);
	printf("MODE:\t\t\t%s\n", global_config.mode);
	printf("PENDING DIGEST MAX:\t%lld\n", global_config.pending_digest_max);
	printf("PENDING DIGEST TIMEOUT:\t%lld\n", global_config.pending_digest_timeout);
	printf("DB ROOT:\t\t%s\n", global_config.db_root);
	printf("WINDOW_SIZE:\t\t%d\n", global_config.window_size);
	printf("DIGEST ALGORITHMS:\t%s\n", global_config.digest_algorithms);
	printf("RESUME THRESHOLD:\t%lld\n", global_config.resume_threshold);

	#ifdef JALDB_TYPE_LMDB
	if (global_config.database_option)
	{
		printf("DATABASE OPTION:\t%s\n", global_config.database_option);
	}
	#endif
	printf("\n===\nEND CONFIG VALUES:\n===\n");
}

int set_global_config(config_t *config)
{
	int rc = JAL_CFG_SUCCESS;
	if (!config){
		if (global_args.debug_flag) {
			DEBUG_LOG("Config is NULL!");
		}
		rc = JAL_CFG_FAILURE;
		return rc;
	}

	// Because all of the config strings are stored as const, we need to put the value
	// into a temporary variable and assign the pointer to the const
	char * config_string = NULL;
	config_setting_t *root = config_root_setting(config);

	// REQUIRED CONFIG VALUES
	if (global_args.enable_tls) {
		rc |= jal_config_lookup_string(root, PRIVATE_KEY, &config_string, JAL_CFG_REQUIRED);
		char *expanded_priv_key_path = jal_expand_path(config_string, PRIVATE_KEY);
		if (expanded_priv_key_path != NULL) {
			global_config.private_key = expanded_priv_key_path;
		}
		else {
			rc |= JAL_CFG_FAILURE;
		}
		free(config_string);
		config_string = NULL;

		rc |= jal_config_lookup_string(root, PUBLIC_CERT, &config_string, JAL_CFG_REQUIRED);
		char *expanded_pub_cert_path = jal_expand_path(config_string, PUBLIC_CERT);
		if (expanded_pub_cert_path != NULL) {
			global_config.public_cert = expanded_pub_cert_path;
		}
		else {
			rc |= JAL_CFG_FAILURE;
		}
		free(config_string);
		config_string = NULL;

		rc |= jal_config_lookup_string(root, REMOTE_CERT, &config_string, JAL_CFG_REQUIRED);
		char *expanded_remote_cert_path = jal_expand_path(config_string, REMOTE_CERT);
		if (expanded_pub_cert_path != NULL) {
			global_config.remote_cert = expanded_remote_cert_path;
		}
		else {
			rc |= JAL_CFG_FAILURE;
		}
		free(config_string);
		config_string = NULL;
	}

	if (global_args.port != 0)
	{
		global_config.port = global_args.port;
	}
	else
	{
		rc |= jal_config_lookup_int64(root, PORT, &global_config.port, JAL_CFG_REQUIRED);
	}

	if (global_args.ipaddr != NULL)
	{
		global_config.host = global_args.ipaddr;
	}
	else
	{
		rc |= jal_config_lookup_string(root, HOST, &config_string, JAL_CFG_REQUIRED);
		global_config.host = config_string;
		config_string = NULL;
	}

	if (global_args.mode != NULL)
	{
		global_config.mode = global_args.mode;
	}
	else
	{
		rc |= jal_config_lookup_string(root, MODE, &config_string, JAL_CFG_REQUIRED);
		global_config.mode = config_string;
		config_string = NULL;
	}

	rc |= jal_config_lookup_int64(root, PENDING_DIGEST_MAX, &global_config.pending_digest_max, JAL_CFG_REQUIRED);
	rc |= jal_config_lookup_int64(root, PENDING_DIGEST_TIMEOUT, &global_config.pending_digest_timeout, JAL_CFG_REQUIRED);
	global_config.resume_threshold = 0;
	rc |= jal_config_lookup_int64(root, JOURNAL_RESUME_THRESHOLD, &global_config.resume_threshold, JAL_CFG_OPTIONAL);
	rc |= jal_config_lookup_list(root, DATA_CLASS, &global_config.data_class, &global_config.len_data_class, JAL_CFG_REQUIRED);

	// Iterate through the data classes and create the
	//	appropriate record_type mask
	for (int i = 0; i < global_config.len_data_class; i++){
		char *value = NULL;
		rc |= jal_config_get_elem_string(global_config.data_class, i, &value, DATA_CLASS);

		if (0 == strcmp(value, "journal")){
			global_config.data_classes =
					global_config.data_classes |
					JALN_RTYPE_JOURNAL;
		}
		else if (0 == strcmp(value, "audit")){
			global_config.data_classes =
					global_config.data_classes |
					JALN_RTYPE_AUDIT;
		}
		else if (0 == strcmp(value, "log")){
			global_config.data_classes =
					global_config.data_classes |
					JALN_RTYPE_LOG;
		}
		else {
			rc |= JAL_CFG_FAILURE;
			DEBUG_LOG("data_class: \"%s\" not recognized. "
				"Allowed data classes are: \"journal\", \"audit\", and \"log\".", value);
		}
		free(value);
	}

	// OPTIONAL CONFIG VALUES
	rc |= jal_config_lookup_string(root, SESSION_TIMEOUT, &config_string, JAL_CFG_OPTIONAL);
	global_config.session_timeout = config_string;
	config_string = NULL;

	if (global_args.dbpath != NULL)
	{
		char *expanded_db_root_path = jal_expand_path(global_args.dbpath, DB_ROOT);
		if (expanded_db_root_path != NULL) {
			global_config.db_root = expanded_db_root_path;
		}
		else {
			rc |= JAL_CFG_FAILURE;
		}
	}
	else
	{
		rc |= jal_config_lookup_string(root, DB_ROOT, &config_string, JAL_CFG_OPTIONAL);
		if (config_string != NULL)
		{
			char *expanded_db_root_path = jal_expand_path(config_string, DB_ROOT);
			if (expanded_db_root_path != NULL) {
				global_config.db_root = expanded_db_root_path;
			}
			else {
				rc |= JAL_CFG_FAILURE;
			}
		}
		free(config_string);
		config_string = NULL;
	}

	if(global_args.window_size > 0){
		global_config.window_size = global_args.window_size;
	}
	else{
		rc |= jal_config_lookup_int(root, WINDOW_SIZE, &global_config.window_size, JAL_CFG_OPTIONAL);

		if (global_config.window_size < 1) {
			rc |= JAL_CFG_FAILURE;
			DEBUG_LOG("window_size must be an integer greater then 0.");
		}
	}

	if(global_args.digest_algorithms) {
		global_config.digest_algorithms = global_args.digest_algorithms;
	}
	else {
		rc |= jal_config_lookup_string(root, DIGEST_ALGORITHMS, &config_string, JAL_CFG_OPTIONAL);
		global_config.digest_algorithms = config_string;
		config_string = NULL;
	}

	//Database option setting, only valid in lmdb builds otherwise defaults to JDB_NONE
	#ifdef JALDB_TYPE_LMDB
	rc |= jal_config_lookup_string(root, DATABASE_OPTION, &config_string, JAL_CFG_OPTIONAL);
	global_config.database_option = config_string;
	config_string = NULL;

	//Ensure valid entry was in the config file and parse the value
	if (JALDB_OK != jaldb_get_db_flags(global_config.database_option, &global_config.jdb_flags))
	{
		rc |= JAL_CFG_FAILURE;
		DEBUG_LOG("Error: failed to validate database_option\n");
	}
	#else
	global_config.database_option = NULL;
	global_config.jdb_flags = JDB_NONE;
	#endif

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
	bool config_err = false;
	while(global_quit==false){
		jsub_is_conn_closed = false;
		struct jaln_connection *conn = NULL;
		struct global_config_t *cfg = (struct global_config_t *) ptr;
		cfg = cfg;
		jaln_context *net_ctx = jaln_context_create();
		jaln_context_set_debug(net_ctx, global_args.debug_flag);
		jaln_context_set_resume_threshold(net_ctx, cfg->resume_threshold);
		enum jal_status err;
		enum jaln_publish_mode mode = JALN_UNKNOWN_MODE;

		size_t num_digests = 0;
		enum jal_digest_algorithm *digest_list = NULL;

		// If this is NULL, we don't have digest algorithms defined in the cfg or CLI
		// Skip digest algorithm configuration in this case. The default algorithm will be set later.
		if (global_config.digest_algorithms) {
			enum jal_status status = jal_parse_digest_algorithm_str(global_config.digest_algorithms, &digest_list, &num_digests);

			if (JAL_OK != status) {
				if (global_args.debug_flag) {
					DEBUG_LOG("Failed to parse digest list! Quitting.");
				}
				config_err = true;
				goto out;
			}

			for (size_t i = 0; i < num_digests; i ++ ) {
				jaln_register_digest_algorithm(net_ctx, jal_digest_ctx_create(digest_list[i]));
			}
		}

		if (0 > ret){
			if (global_args.debug_flag) {
				DEBUG_LOG("Port wasn't converted to string! Quitting.");
			}
			config_err = true;
			goto out;
		}

		if (global_args.enable_tls) {
			err = jaln_register_tls(net_ctx,
						global_config.private_key,
						global_config.public_cert,
						global_config.remote_cert);
			if (JAL_OK != err) {
				if (global_args.debug_flag) {
					DEBUG_LOG("Error w/ registration of TLS! Quitting.");
				}
				config_err = true;
				goto out;
			}
		}
		err = jaln_register_encoding(net_ctx, "xml");
		err = jsub_callbacks_init(net_ctx);
		if (JAL_OK != err) {
			if (global_args.debug_flag) {
				DEBUG_LOG("Error w/ registration of encoding, digest or callbacks! Quitting.");
			}
			config_err = true;
			goto out;
		}
		if (0 == strcmp("archive",global_config.mode)) {
			mode = JALN_ARCHIVE_MODE;
		} else if (0 == strcmp("live",global_config.mode)) {
			mode = JALN_LIVE_MODE;
		} else {
			DEBUG_LOG("Bad mode specification in config file! Quitting.");
			config_err = true;
			goto out;
		}
		while(conn==NULL && global_quit==false){
				conn = jaln_subscribe(
							net_ctx,
							global_config.host,
							port,
							global_config.data_classes,
							mode,
							jsub_db_ctx,
							global_config.pending_digest_max,
							global_config.pending_digest_timeout,
							global_config.window_size);
				if (conn==NULL){
					if (global_args.debug_flag) {
						DEBUG_LOG("Waiting to connect to: %s:%i \n", global_config.host, (int)global_config.port);
					}
					sleep(1);
				}
			}

		while(!jsub_is_conn_closed){
			if (global_quit) {
				jaln_disconnect(conn);
				break;
			}
			sleep(1);
		}
	out:
		if(global_quit==true){
			timer_keep_going = false;
			sleep(2);
			err = jaln_shutdown(conn);
			if(JAL_OK != err){
				DEBUG_LOG("Subscriber failed to shutdown network connection!");
			}
		}
		free(digest_list);
		jaln_context_destroy(&net_ctx);
		free(conn);
		if(config_err || global_quit==true){
				break;
		}
	}
	return NULL;
}

