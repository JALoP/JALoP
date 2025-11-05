/**
 * @file
 *
 * @brief This file contains the implementation of a daemon process that
 * listens for subscribe requests from remotes.
 *
 * ### LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <axl.h>
#include <errno.h>
#include <argp.h>
#include <jalop/jaln_network.h>
#include <jalop/jal_digest.h>
#include <limits.h>
#include <libconfig.h>
#include <pthread.h>
#include <signal.h>
#include <sstream>
#include <iostream>
#include <string>
#include <unistd.h>
#include <time.h>
#include <pwd.h>

#include <jalop/jal_version.h>
#include "jal_socket.hpp"
#include "jal_base64_internal.h"
#include "jaldb_context.hpp"
#include "jalns_strings.h"
#include "jalu_daemonize.h"
#include "jal_config.h"
#include "jaldb_config.h"
#include "jaldb_segment.h"
#include "jaldb_record.h"

#include "jal_asprintf_internal.h"
#include "jaldb_strings.h"

#include "jaldb_utils.h"
#include "jal_alloc.h"
#include "jal_ts_utils.h"
#include "jal_seccomp_enforcer.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <regex>

using namespace std;

#define VERSION_CALLED 1
#define DEFAULT_SOCKET_PATH "jald_filter_socket"

#define DEBUG_LOG_SUB_SESSION(ch_info, args...) \
do { \
	if (global_args.debug_flag) { \
		const char *__rec_type = NULL; \
		switch (ch_info->type) { \
		case JALN_RTYPE_JOURNAL: \
			__rec_type = (const char*)"journal"; \
			break; \
		case JALN_RTYPE_AUDIT: \
			__rec_type = (const char*)"audit"; \
			break; \
		case JALN_RTYPE_LOG: \
			__rec_type = (const char*)"log"; \
			break; \
		default: \
			__rec_type = (const char*)"unknown"; \
		} \
		time_t rawtime; \
		time(&rawtime); \
		char timestr[26]; \
		strftime(timestr, 26, "%Y-%m-%dT%H:%M:%S", gmtime(&rawtime)); \
		fprintf(stderr, "jald %s[%d](%s)[%s:sub:%s]", __FUNCTION__, __LINE__, \
				timestr, ch_info->hostname, __rec_type); \
		fprintf(stderr, ##args); \
		fprintf(stderr, "\n"); \
	} \
} while (0)

#define DEBUG_LOG(args...) \
do { \
	if (global_args.debug_flag) { \
		time_t rawtime; \
		time(&rawtime); \
		char timestr[26]; \
		strftime(timestr, 26, "%Y-%m-%dT%H:%M:%S", gmtime(&rawtime)); \
		fprintf(stderr, "jald %s[%d](%s) ", __FUNCTION__, __LINE__, \
				timestr); \
		fprintf(stderr, ##args); \
		fprintf(stderr, "\n"); \
	} \
} while(0)

int not_exiting = 1;

struct session_ctx_t {
	struct jaldb_record *rec;
	jaldb_context_t* db_ctx;
};

static jaldb_context_t* setup_db_layer(std::string db_home);

static void sig_handler(__attribute__((unused)) int sig)
{
	not_exiting = 0;
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

	if (0 != sigaction(SIGPIPE, &action_on_sig, NULL)) {
		fprintf(stderr, "failed to register SIGPIPE.\n");
		goto err_out;
	}

	return 0;
err_out:
	return -1;
}
#define JALD_LISTEN_BACKLOG 20

struct global_args_t {
	char *db_home;
	char *socket_path;
	char *config_path;  /* --config option */
	bool debug_flag;    /* --debug option */
	int archive_mode;
	int mark_unsent;
} global_args;
struct thread_args_t {
	std::string socket_path;
	std::string record_type;
	int client_fd;
};

struct thread_args_t server_thread_args;

struct global_config_t {
	char *db_root;
	char* pid_file;
	char* log_dir;
	char* socket_path;
	int archive_mode;
	int mark_unsent;
	char* database_option;
	jaldb_flags jdb_flags;
	int map_size;
} global_config;

enum jald_marker_status {
	JALD_MARKER_E_CONFIG_LOAD = -1024,
	JALD_MARKER_E_DB_INIT,
	JALD_MARKER_E_NOMEM,
	JALD_MARKER_E_GEN,
	JALD_MARKER_OK = 0,
};

static void free_global_config(void);
static void print_config(void);
static enum jald_marker_status set_global_config(const char* config_path);

struct thread_args_t journal_thread_args;
struct thread_args_t audit_thread_args;
struct thread_args_t log_thread_args;
// argp
const char *argp_program_version = jal_version_as_string();
const char *argp_program_bug_address = 0;
static char args_doc[] = "";
/* keys for options without short-options*/
#define OPT_NO_DAEMON 1 /* --no-daemon */
static char doc[] =
	"jald_marker -- JALoPv2 Publisher Filter";
static error_t parse_opt(int key, char *arg, struct argp_state *state);

static struct argp_option options[] =
{
	{"debug", 'd', NULL, 0, "run jald-marker in debug mode", 0},
	{"config", 'c', "path", 0, "jald-marker configuration file path", 0},
	{"db_home", 'h', "path", 0, "jald-marker database home path", 0},
	{"socket_path", 's', "socket path", 0,
		"Filter socket path.", 0},
	{"live_mode", 'l', 0, 0,
		"Run in live mode.", 0},
	{"mark_unsent", 'm', 0, 0,
		"Mark unsynced records unsent.", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

struct session_ctx_t ctx;
enum jaldb_status send_next_record();

UDSSendSocket auditToPub;
UDSSendSocket logToPub;
UDSSendSocket journalToPub;

struct RecvCommandMessage : public UDSRecvMessage {
	uint16_t dummy;
	uint64_t payloadLength;
	void* payloadData = NULL;

	int dummyID;
	int payloadLengthID;
	int payloadDataID;
	int breakID;

	RecvCommandMessage() {
		// Capture the "id" of each field as it is added so we know how to refer to them later
		dummyID = addField(sizeof(uint16_t));
		payloadLengthID = addField(sizeof(uint64_t));
		payloadDataID = addDependentField(payloadLengthID);
		breakID = addField(sizeof("BREAK")-1);
	}

	~RecvCommandMessage() {
		free(payloadData);
	}

	int process() {
		try {
			if(std::string("BREAK") != getString(breakID, sizeof("BREAK") - 1)) {
				fprintf(stderr, "Second BREAK segment does not contain BREAK\n");
				return -1;
			}
			dummy = getField<uint16_t>(dummyID);
			payloadLength = getField<uint64_t>(payloadLengthID);
			payloadData = stealBuffer(payloadDataID, payloadLength);
		} catch (const std::exception &e) {
			fprintf(stderr, "ERROR: Encountered exception parsing record data: %s\n", e.what());
			return -1;
		}
		return 0;
	}
};

static pthread_mutex_t filter_lock;

/*sample nonce="74c27f93-7722-4cd9-89b0-764eb631e6a8_2025-05-16T14:17:56.171210_1312388_3393181440"*/
regex pattern("^([0-9]|[a-z]){8}-([0-9]|[a-z]){4}-([0-9]|[a-z]){4}-([0-9]|[a-z]){4}-([0-9]|[a-z]){12}_[0-9]{4}-[0-1][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]\\.[0-9]{6}_[0-9]{1,15}_[0-9]{1,15}$");
smatch matches;
bool validateRequest(struct mark_request request){
		if (request.mark!=MARK_UNSYNCED_RECORDS_UNSENT
			&& request.mark!=MARK_SENT
			&& request.mark!=MARK_UNSENT
			&& request.mark!=MARK_SYNCED)
		{
			fprintf(stderr, "Bad Mark");
			return false;
		}
		if (request.record_type!=JALDB_RTYPE_LOG
			&& request.record_type!=JALDB_RTYPE_AUDIT
			&& request.record_type!=JALDB_RTYPE_JOURNAL)
		{
			fprintf(stderr, "Bad Record Type");
			return false;
		}

		string nonce = string(request.nonce);

		if(request.mark==MARK_SENT || request.mark==MARK_SYNCED || request.mark==MARK_UNSENT){
			if (!regex_search(nonce, matches, pattern)){
			fprintf(stderr, "Bad nonce %s\n", request.nonce);
				return false;
			}
		}
		else{
			if (nonce.size()>0){
				fprintf(stderr, "Bad nonce not empty %s\n", request.nonce);
				return false;
			}
		}
		return true;
}
__attribute__((noreturn))
void * mark_records(void *in_args)
{
	int jaldb_mark_unsynced_counter = 0;
	int jaldb_mark_sent_counter = 0;
	int jaldb_mark_synced_counter = 0;
	int jaldb_not_ok_counter = 0;
	int jaldb_ok_counter = 0;
	int jaldb_invalid_counter = 0;
	int counter = 0;
	enum jaldb_status jaldb_ret = JALDB_OK;
	struct thread_args_t *args = (struct thread_args_t *) in_args;
	fprintf(stderr, "%s threading\n", args->record_type.c_str());

	struct mark_request request;

	UDSRecvSocket pubToFilter(global_config.socket_path);
	int poll_status = -1;
	while(not_exiting && -1 == poll_status) {
		fprintf(stderr, "Waiting for connection on socket: %s\n", global_config.socket_path);
		poll_status = pubToFilter.pollSocket();
		if(-1 == poll_status) {
			sleep(1);
		}
	}
	fprintf(stderr, "Connected on socket: %s\n", global_config.socket_path);

	while(not_exiting){
		RecvCommandMessage commandMessage;
		UDSRecvRV rv = pubToFilter.recvMsg(commandMessage);
		pthread_mutex_lock(&filter_lock);
		switch(rv.status) {
			case UDSRecvStatus::Success:
				try {
					commandMessage.process();
					memcpy(&request, commandMessage.payloadData, sizeof(request));
				} catch (std::exception &e) {
					fprintf(stderr, "Failed to process data received from socket. Shutting down.\n");
					not_exiting = 0;
					pthread_mutex_unlock(&filter_lock);
					continue;
				}
				break;
			case UDSRecvStatus::Timeout:
				// No data received for 1 second, coming up for air. Continue
				pthread_mutex_unlock(&filter_lock);
				continue;
			case UDSRecvStatus::LowLevelFailure:
				fprintf(stderr, "revcmsg returned error code: %d. Shutting down.\n",
					rv.lowLevelError);
				not_exiting = 0;
				pthread_mutex_unlock(&filter_lock);
				continue;
			case UDSRecvStatus::SocketShutdown:
				fprintf(stderr, "Filter closed socket. Shutting down.\n");
				not_exiting = 0;
				pthread_mutex_unlock(&filter_lock);
				continue;
			case UDSRecvStatus::LogicError:
				fprintf(stderr, "Logic Error receiving. Shutting down\n");
				not_exiting = 0;
				pthread_mutex_unlock(&filter_lock);
				continue;
			case UDSRecvStatus::LengthMismatch:
				fprintf(stderr, "Other error receiving. Shutting down\n");
				not_exiting = 0;
				pthread_mutex_unlock(&filter_lock);
				continue;
			default:
				fprintf(stderr, "Invalid status from receive call. Shutting down\n");
				not_exiting = 0;
				pthread_mutex_unlock(&filter_lock);
				continue;
		}
		if(validateRequest(request)){
			if (request.mark == MARK_UNSYNCED_RECORDS_UNSENT)
			{
				jaldb_mark_unsynced_counter++;
			}
			else if (request.mark == MARK_SENT)
			{
				jaldb_ret = jaldb_mark_sent(ctx.db_ctx, request.record_type, (const char *) &request.nonce, 1);
				jaldb_mark_sent_counter++;
			}
			else if (request.mark == MARK_UNSENT)
			{
				jaldb_ret = jaldb_mark_sent(ctx.db_ctx, request.record_type, (const char *) &request.nonce, 0);
				jaldb_mark_sent_counter++;
			}
			else if (request.mark == MARK_SYNCED)
			{
				jaldb_ret = jaldb_mark_synced(ctx.db_ctx, request.record_type, (const char *) &request.nonce);
				jaldb_mark_synced_counter++;
			}
			if (jaldb_ret != JALDB_OK)
			{
				jaldb_not_ok_counter++;
				fprintf(stderr, "%s JALDB_NOT_OK\n", args->record_type.c_str());
			}
			else
			{
				jaldb_ok_counter++;
			}
		}
		else{
			jaldb_invalid_counter++;
		}
		pthread_mutex_unlock(&filter_lock);
	}
	fprintf(stderr,  "marked jaldb_mark_unsynced_counter %i\n", jaldb_mark_unsynced_counter);
	fprintf(stderr, "marked jaldb_mark_sent_counter %i\n", jaldb_mark_sent_counter);
	fprintf(stderr, "marked jaldb_mark_synced_counter %i\n", jaldb_mark_synced_counter);
	fprintf(stderr, "marked jaldb_not_ok_counter %i\n", jaldb_not_ok_counter);
	fprintf(stderr, "marked jaldb_ok_counter %i\n", jaldb_ok_counter);
	fprintf(stderr, "marked counter %i\n", counter);
	fprintf(stderr, "marked jaldb_invalid_counter %i\n", jaldb_invalid_counter);
	(void)fflush(stdout);
	pthread_exit((void*) NULL);
}

struct JalFilterRecord : public UDSSendMessage {
	JalFilterRecord(__attribute__((unused)) struct jaldb_record *rec, char *nonce) {
		uint16_t dummy = 12;
		addFieldByCopy((void*)&dummy, sizeof(uint16_t));

		char host[10] = "127.0.0.1";
		uint16_t host_size = strlen(host);
		addFieldByCopy((void*)&host_size, sizeof(uint16_t));
		addFieldByCopy((void*)&rec->payload->length, sizeof(uint64_t));
		addFieldByCopy((void*)&rec->app_meta->length, sizeof(uint64_t));
		addFieldByCopy((void*)&rec->sys_meta->length, sizeof(uint16_t));
		uint16_t nonce_size = strlen(nonce);
		addFieldByCopy((void*)&nonce_size, sizeof(uint16_t));
		uint16_t ts_size = 27;
		addFieldByCopy((void*)&ts_size, sizeof(uint16_t));
		addFieldByCopy((void*)&rec->payload->on_disk, sizeof(uint16_t));
		addFieldByCopy((void*)&host, host_size);

		if (rec->payload->on_disk==0) {
			addFieldByCopy((void*)rec->payload->payload, rec->payload->length);
			char* break_str1 = strdup("BREAK");
		 	addFieldByOwningPointer((void**)&break_str1, strlen(break_str1));
		}
		else{
			addFd(rec->payload->fd);
		}
		if (rec->app_meta->length>0) {
			addFieldByCopy((void*)rec->app_meta->payload, rec->app_meta->length);
			char* break_str2 = strdup("BREAK");
		 	addFieldByOwningPointer((void**)&break_str2, strlen(break_str2));
		}
		if (rec->sys_meta->length>0) {
			addFieldByCopy((void*)rec->sys_meta->payload, rec->sys_meta->length);
			char* break_str3 = strdup("BREAK");
		 	addFieldByOwningPointer((void**)&break_str3, strlen(break_str3));
		}
		addFieldByCopy((void*)nonce, strlen(nonce));
		char* break_str4 = strdup("BREAK");
		addFieldByOwningPointer((void**)&break_str4, strlen(break_str4));

		addFieldByCopy((void*)rec->timestamp, 27);
		char* break_str5 = strdup("BREAK");
		addFieldByOwningPointer((void**)&break_str5, strlen(break_str5));
	}
};
__attribute__((noreturn))
void * send_next_record( __attribute__((unused)) void *in_args){
	struct thread_args_t *args = (struct thread_args_t *) in_args;
	jaldb_rec_type RTYPE = JALDB_RTYPE_UNKNOWN;
	UDSSendSocket recordToPub;
	std::string recordSockePath;
	if(args->record_type.compare("log")==0){
		RTYPE = JALDB_RTYPE_LOG;
		recordSockePath = "jald_filter_socket_L";
	}
	else if(args->record_type.compare("audit")==0){
		RTYPE = JALDB_RTYPE_AUDIT;
		recordSockePath = "jald_filter_socket_A";
	}
	else if(args->record_type.compare("journal")==0){
		RTYPE = JALDB_RTYPE_JOURNAL;
		recordSockePath = "jald_filter_socket_J";
	}
	recordToPub.connected = 0;
	while(!recordToPub.connected && not_exiting){
		fprintf(stderr, "Attempting to connect: %s\n",
			recordSockePath.c_str());
			recordToPub.connectSocket(recordSockePath);
		sleep(1);
	}

	if(global_config.archive_mode){
		fprintf(stderr, "%s sending in archive mode\n", args->record_type.c_str());
	}
	else{
		fprintf(stderr, "%s sending in live mode\n", args->record_type.c_str());
	}
	if(global_config.mark_unsent){
		pthread_mutex_lock(&filter_lock);
		jaldb_mark_unsynced_records_unsent(ctx.db_ctx, RTYPE);
		pthread_mutex_unlock(&filter_lock);
		fprintf(stderr, "%s marking unsent  \n", args->record_type.c_str());
	}
	else{
		fprintf(stderr, "%s not marking unsent  \n", args->record_type.c_str());
	}
	char * timestamp = jal_gen_timestamp_usec();
	int sent_bytes;
	jaldb_status open_fd_status;
	while(not_exiting){
		enum jaldb_status ret = JALDB_E_NOT_FOUND;
		char * nonce = NULL;
		struct jaldb_record *rec = NULL;
		if(global_config.archive_mode){
			while(ret == JALDB_E_NOT_FOUND && not_exiting){
				ret = jaldb_next_unsynced_record(ctx.db_ctx, RTYPE, &nonce, &rec);
				if (ret == JALDB_E_NOT_FOUND){
					sleep(1);
				}
			}
		}
		else{
			while(ret == JALDB_E_NOT_FOUND && not_exiting){
				ret = jaldb_next_chronological_record(ctx.db_ctx, RTYPE, &nonce, &rec, &timestamp);
				if (ret == JALDB_E_NOT_FOUND){
					sleep(1);
				}
			}
		}

		if (ret==JALDB_OK){
			open_fd_status = JALDB_OK;
			sent_bytes = -1;
			if (rec->payload->on_disk==1){
				open_fd_status = jaldb_open_segment_for_read(ctx.db_ctx, rec->payload);
			}
			if (open_fd_status==JALDB_OK){
				sent_bytes = recordToPub.sendMsg(JalFilterRecord(rec, nonce));
			}
			if(sent_bytes==0){
				if(global_config.archive_mode==1){
					pthread_mutex_lock(&filter_lock);
					ret = jaldb_mark_sent(ctx.db_ctx, RTYPE, (const char *) nonce, 1);
					pthread_mutex_unlock(&filter_lock);
				}
			}
			else{
				fprintf(stderr, "Not sent RT %i NONCE %s \n", (int)RTYPE, nonce);
			}

			if (rec->payload->on_disk==1 && open_fd_status==JALDB_OK) {
				close(rec->payload->on_disk);
			}
			if(rec){
				jaldb_destroy_record(&rec);
			}
			rec = NULL;
			if (ret != JALDB_OK){
				fprintf(stderr, "Not OK %i\n", (int)ret);
			}

		}
		else{
			sleep(1);
		}

		if(nonce){
			free(nonce);
		}
	}
	pthread_exit((void*) NULL);
}
int main(int argc, char **argv)
{
	//Initialize global args
	global_args.db_home = NULL;
	global_args.socket_path = NULL;
	global_args.config_path = NULL;
	global_args.debug_flag = false;
	global_args.mark_unsent = -1;
	global_args.archive_mode = -1;

	int rc = argp_parse(&argp, argc, argv, 0, 0, NULL);
	if (0 != rc)
	{
		fprintf(stderr, "ARGP_ERR_UNKNOWN: %d\n", ARGP_ERR_UNKNOWN);
		return -1;
	}

	DEBUG_LOG("Config Path: %s\tDebug: %d\n", global_args.config_path, global_args.debug_flag);

	if (!global_args.config_path) {
		fprintf(stderr, "Configuration file path is required.\n");
		return -1;
	}

	rc = set_global_config(global_args.config_path);
	if (rc != JALD_MARKER_OK) {
		free_global_config();
		return -1;
	}

	print_config();

	int ret = setup_signals();
	if (ret!=0){
		free_global_config();
		return -1;
	}

	ctx.db_ctx = setup_db_layer(global_config.db_root);
	if (!ctx.db_ctx){
		free_global_config();
		return -1;
	}

	pthread_t journal_thread;
	pthread_t audit_thread;
	pthread_t log_thread;
	pthread_t server_thread;

	pthread_mutex_init(&filter_lock, NULL);

	server_thread_args.record_type = "all";
	server_thread_args.socket_path = global_config.socket_path;

	journal_thread_args.record_type = "journal";
	audit_thread_args.record_type = "audit";
	log_thread_args.record_type = "log";

	fprintf(stderr, "start threading\n");

	if(0 != pthread_create(&server_thread, NULL, mark_records, &server_thread_args)) {
		not_exiting = 0;
		fprintf(stderr, "Could not create server thread\n");
		return -1;
	}
	sleep(2);
	if(0 != pthread_create(&journal_thread, NULL, send_next_record, &journal_thread_args)) {
		not_exiting = 0;
		fprintf(stderr, "Could not create journal thread\n");
		return -1;
	}
	sleep(2);
	if(0 != pthread_create(&audit_thread, NULL, send_next_record, &audit_thread_args)) {
		not_exiting = 0;
		fprintf(stderr, "Could not create audit thread\n");
		return -1;
	}
	sleep(2);
	if(0 != pthread_create(&log_thread, NULL, send_next_record, &log_thread_args)) {
		not_exiting = 0;
		fprintf(stderr, "Could not create log thread\n");
		return -1;
	}

	while(not_exiting){
		sleep(1);
	}

	pthread_kill(server_thread, SIGINT);
	pthread_kill(journal_thread, SIGINT);
	pthread_kill(audit_thread, SIGINT);
	pthread_kill(log_thread, SIGINT);

	pthread_join(server_thread, NULL);
	pthread_join(journal_thread, NULL);
	pthread_join(audit_thread, NULL);
	pthread_join(log_thread, NULL);

	pthread_mutex_destroy(&filter_lock);

	free_global_config();
	fprintf(stderr, "Done.\n");

	return 0;
}
//f8555a9f-a991-4d5d-80b0-5c4ea522d3f9_2025-05-17T01:17:57.742275_1360636_1127827200
//f8555a9f-a991-4d5d-80b0-5c4ea522d3f9_2025-05-17T01:17:57.742275_1360636_1127827200
static jaldb_context_t* setup_db_layer(std::string db_home)
{
	enum jaldb_status jaldb_ret = JALDB_OK;
	jaldb_context_t* db_ctx = jaldb_context_create();
	jaldb_ret = jaldb_context_init(db_ctx, db_home.c_str(), global_config.jdb_flags, global_config.map_size);
	if (JALDB_OK != jaldb_ret) {
		fprintf(stderr, "Cannot connect to database.\n");
		jaldb_context_destroy(&db_ctx);
	}
	else{
		fprintf(stderr, "Database connected!\n");
	}

	return db_ctx;
}

enum jald_marker_status set_global_config(const char* config_path)
{
	// 0-initialize the global_config struct
	memset(&global_config, 0, sizeof(global_config));

	// Load config file as config_t object
	config_t config;
	if(JAL_CFG_SUCCESS != jal_config_init(&config)) {
		// Error printed internally
		return JALD_MARKER_E_CONFIG_LOAD;
	}

	// Now that the config_t is initialized, create a tiny struct to guarantee destruction
	// of the config_t no matter how we exit this function
	struct ConfigWrapper
	{
		config_t& configRef;
		~ConfigWrapper() { config_destroy(&configRef); }
	} configWrapper{config};

	// Attempt to read from the provided config file path
	if(JAL_CFG_SUCCESS != jal_config_read_file(&config, config_path))
	{
		// Error printed internally
		return JALD_MARKER_E_CONFIG_LOAD;
	}

	// Extract root configuration setting
	config_setting_t *root = config_root_setting(&config);

	// Extract db_root - optional
	char* db_root = NULL;
	if (NULL != global_args.db_home)
	{
		db_root = global_args.db_home;
	}
	else
	{
		if(JAL_CFG_SUCCESS != jal_config_lookup_string(
			root,
			JALNS_DB_ROOT,
			&db_root,
			JAL_CFG_OPTIONAL)) {
				// Error printed internally
				return JALD_MARKER_E_CONFIG_LOAD;
		}
	}
	if (NULL != db_root) {
		global_config.db_root = jal_expand_path(db_root, JALNS_DB_ROOT);
		if (global_config.db_root  == NULL) {
			//Error already displayed from method call above
			free(db_root);
			return JALD_MARKER_E_CONFIG_LOAD;
		}
		free(db_root);
	}

	// Extract socket_path - optional
	if (NULL != global_args.socket_path)
	{
		global_config.socket_path = jal_strdup(global_args.socket_path);
	}
	else
	{
		if(JAL_CFG_SUCCESS != jal_config_lookup_string(
			root,
			JALNS_FILTER_SOCKET,
			&global_config.socket_path,
			JAL_CFG_OPTIONAL)) {
				// Error printed internally
				return JALD_MARKER_E_CONFIG_LOAD;
		}

		//If not specified, set default
		if (NULL == global_config.socket_path)
		{
			global_config.socket_path = jal_strdup((char*)DEFAULT_SOCKET_PATH);
		}
	}

	// Extract pid_file - optional
	char* pid_file = NULL;
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALNS_PID_FILE,
		&pid_file,
		JAL_CFG_OPTIONAL)) {
			// Error printed internally
			return JALD_MARKER_E_CONFIG_LOAD;
	}
	//Since pid_file is optional, ensure not null before processing
	if (pid_file != NULL) {
		global_config.pid_file = jal_expand_home_dir(pid_file, JALNS_PID_FILE);
		if (global_config.pid_file == NULL)
		{
			//Error already displayed from method call above
			free(pid_file);
			return JALD_MARKER_E_CONFIG_LOAD;
		}
		free(pid_file);
	}

	// Extract log_dir path - optional
	char* log_dir = NULL;
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALNS_LOG_DIR,
		&log_dir,
		JAL_CFG_OPTIONAL)) {
			// Error printed internally
			return JALD_MARKER_E_CONFIG_LOAD;
	}

	//Since log_file is optional, ensure not null before processing
	if (log_dir != NULL)
	{
		global_config.log_dir = jal_expand_path(log_dir, JALNS_LOG_DIR);
		if (global_config.log_dir == NULL) {
			//Error already displayed from method call above
			free(log_dir);
			return JALD_MARKER_E_CONFIG_LOAD;
		}
		free(log_dir);
	}

	if (global_args.mark_unsent == -1){
		if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
				root,
				JALNS_MARK_UNSENT,
				&global_config.mark_unsent,
				JAL_CFG_OPTIONAL)
			)
		{
			// Error printed internally
			return JALD_MARKER_E_CONFIG_LOAD;
		}
	}
	if (global_args.archive_mode == -1){
		if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
				root,
				JALNS_ARCHIVE_MODE,
				&global_config.archive_mode,
				JAL_CFG_OPTIONAL)
			)
		{
			// Error printed internally
			return JALD_MARKER_E_CONFIG_LOAD;
		}
	}

	//Attempts to load optional LMDB_CONFIG file in db_root
	//If present, this will override the lmdb performance level
	//and lmdb map size, otherwise default values will be used.
	jaldb_config *jdb_config = NULL;
	enum jaldb_config_status jcs = get_jaldb_config(global_config.db_root, &jdb_config);
	if (jcs != JALDB_CONFIG_OK && jcs != JALDB_CONFIG_E_NOTFOUND) {
		return JALD_MARKER_E_CONFIG_LOAD;
	}

	//Only override map size if present in config
	global_config.jdb_flags = JDB_LMDB_PERFORMANCE_LEVEL2;
	global_config.database_option = strdup(JDB_LMDB_PERFORMANCE_LEVEL2_STR);
	global_config.map_size = DEFAULT_LMDB_MAP_SIZE;

	if (jcs != JALDB_CONFIG_E_NOTFOUND)
	{
		if (jdb_config->map_size != 0)
		{
			global_config.map_size = jdb_config->map_size;
		}

		//Only override database option if present in config
		if (NULL != jdb_config->database_option)
		{
			global_config.jdb_flags = jdb_config->jdb_flags;
			free(global_config.database_option);
			global_config.database_option = strdup(jdb_config->database_option);
		}
		free(jdb_config);
	}

	return JALD_MARKER_OK;
}

void free_global_config(void)
{
	free(global_config.db_root);
	free(global_config.pid_file);
	free(global_config.log_dir);
	free(global_config.socket_path);
	free(global_config.database_option);
}

void print_config(void)
{
	fprintf(stderr, "\n===\nBEGIN CONFIG VALUES:\n===\n");
	fprintf(stderr, "DB ROOT:\t\t%s\n", global_config.db_root);
	fprintf(stderr, "FILTER_SOCKET:\t\t%s\n", global_config.socket_path);
	fprintf(stderr, "ARCHIVE_MODE:\t\t%i\n", global_config.archive_mode);
	fprintf(stderr, "MARK_UNSENT:\t\t%i\n", global_config.mark_unsent);
	fprintf(stderr, "DATABASE_OPTION:\t%s\n", global_config.database_option);
	fprintf(stderr, "LMDB_MAP_SIZE (GB):\t%i\n", global_config.map_size);
	if(global_config.pid_file) {
		fprintf(stderr, "PID FILE:\t\t%s\n", global_config.pid_file);
	}
	if(global_config.log_dir) {
		fprintf(stderr, "LOG DIRECTORY:\t\t%s\n", global_config.log_dir);
	}

	fprintf(stderr, "===\nEND CONFIG VALUES:\n===\n\n");
	(void)fflush(stdout);
}

static error_t parse_opt(int key_in,
		char *arg, __attribute__((unused)) struct argp_state *state)
{
	switch (key_in)
	{
		case 'h':
			global_args.db_home = strdup(arg);
			break;
		case 's':
			global_args.socket_path = strdup(arg);
			break;
		case 'c':
			global_args.config_path = strdup(arg);
			break;
		case 'd':
			global_args.debug_flag = true;
			break;
		case 'l':
			global_args.archive_mode = 1;
			break;
		case 'm':
			global_args.mark_unsent = 1;
			break;
		case ARGP_KEY_END:
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
