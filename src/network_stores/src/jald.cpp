/**
 * @file
 *
 * @brief This file contains the implementation of a daemon process that
 * listens for subscribe requests from remotes.
 *
 * ### LICENSE
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <argp.h>
#include <jalop/jaln_network.h>
#include <jalop/jal_digest.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <time.h>

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <thread>
#include <map>
#include <fcntl.h>

#include <jalop/jal_version.h>

#include "jal_base64_internal.h"
#include "jal_asprintf_internal.h"
#include "jaldb_context.hpp"
#include "jalns_strings.h"
#include "jalu_daemonize.h"
#include "jaldb_segment.h"
#include "jaldb_record.h"
#include "jaldb_utils.h"
#include "jaldb_config.h"
#include "jaldb_strings.h"
#include "jal_alloc.h"
#include "jal_ts_utils.h"
#include "jaldb_record_dbs.h"
#include "jal_socket.hpp"
#include <jalop/jal_seccomp_enforcer.h>
#include "jald_callbacks.hpp"
#include "jald_config.hpp"
#include "jald_common_definitions.hpp"
#include "jald_filter_extension.hpp"

#define VERSION_CALLED 1


JaldConfig global_config;

struct global_args_t global_args;

enum jald_status {
	JALD_E_CONFIG_LOAD = -1024,
	JALD_E_DB_INIT,
	JALD_E_NOMEM,
	JALD_OK = 0,
};

static jaln_context *jctx = NULL;

// A counter of threads which need to close before we shut down
int threads_to_exit = 0;
// A mutex to ensure threads_to_exist remains coherent
pthread_mutex_t exit_count_lock;

// short hand for long map type names
using SessionHostMap = std::map<std::string, std::shared_ptr<session_ctx_t>>;
using SessionTokenMap = std::map<uint16_t, std::shared_ptr<session_ctx_t>>;

// NOTE - these maps have program lifetime (static globals). They are accessed with
// unguarded .at() calls essentially everywhere, which will throw if the specified
// entry does not exist.
// The journal, audit, log entries are created immediately in main and should never
// be removed. Failure to adhere to this will cause program termination by exception.
//
// Set up a map of hostname string to session_ctx_t, store by shared_ptr so we can
// refer to this same session_ctx_t from our subscriber_token map safely
std::map<enum jaln_record_type, SessionHostMap> sessionHostMaps;
// Set up a similar map to the matching lock
std::map<enum jaln_record_type, std::shared_ptr<pthread_mutex_t>> mapLocks;
// When using the filter, we also need to map from subscriber tokens to sessions
std::map<enum jaln_record_type, SessionTokenMap> sessionTokenMaps;


// When non-0, the CLI should clean up and exit
int exiting = 0;
// Lock to serialize write access to the inline filter socket
pthread_mutex_t request_socket_lock;
UDSSendSocket requestSocket;
pthread_t journal_receive_thread;
pthread_t audit_receive_thread;
pthread_t log_receive_thread;

// argp
const char *argp_program_version = jal_version_as_string();
const char *argp_program_bug_address = 0;
static char args_doc[] = "--config config_file";
/* keys for options without short-options*/
#define OPT_NO_DAEMON 1 /* --no-daemon */
static char doc[] =
	"jald -- JALoPv1 Network Store that attempts to connect to and then publish JALoP records to a remote JALoPv1 subscriber.";
static error_t parse_opt(int key, char *arg, struct argp_state *state);
static struct argp_option options[] = {
	{"config", 'c', "config-file", 0,
		"Instruct jald to get its configuration from the file config-file.", 0},
	{"debug", 'd', 0, 0,
		"Output debugging information.", 0},
	{"no-daemon", OPT_NO_DAEMON, 0, 0,
		"Prevent jald from forking to the background.", 0},
	{"use-filter", 'f', 0, 0,
		"use-filter", 0},
	{"disable-tls", 's', 0, 0,
		"Disable attempts at TLS negotiation. This option should not be used in production environment since there will be no privacy over the connection.", 0},
	{"pid", 'p', "pid-path", 0,
		"PID Path", 0},
	{"digest-algorithms", 'a', "algs", 0,
		"Provide a list of supported digest algorithms. These algorithms should be ordered by preference in a single double-quoted string with a space separating the algorithms.", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

static void free_global_args(void);

int journal_socket_fd;
int audit_socket_fd;
int log_socket_fd;

static enum jaldb_rec_type db_type_from_rec_type(enum jaln_record_type type) {
	enum jaldb_rec_type db_type;
	switch (type) {
		case JALN_RTYPE_JOURNAL:
			db_type = JALDB_RTYPE_JOURNAL;
			break;
		case JALN_RTYPE_AUDIT:
			db_type = JALDB_RTYPE_AUDIT;
			break;
		case JALN_RTYPE_LOG:
			db_type = JALDB_RTYPE_LOG;
			break;
		default:
			db_type = JALDB_RTYPE_UNKNOWN;
			break;
	}
	return db_type;
}

enum jaldb_status pub_get_next_record_on_socket(jaln_session *sess,
			const struct jaln_channel_info *ch_info)
{
	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(ch_info->type);

	//sessionTokenMap is not used in this method.
	(void)sessionTokenMap;
	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		// This would indicate the channel is going down, just return gracefully.
		// Jald's other mechanisms will handle the rest
		pthread_mutex_unlock(mapLock.get());
		return JALDB_E_NETWORK_DISCONNECTED;
	}

	while(1) {

		//we have commanded jald to stop
		if(exiting) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Shutting down...");
			return JALDB_OK;
		}

		if(ctxPtr->shutting_down || JAL_OK != jaln_session_is_ok(sess)) {
			return JALDB_E_NETWORK_DISCONNECTED;
		}

		pthread_mutex_lock(&(ctxPtr->staging_data_lock));

		// Wait until a record is staged
		// TODO: We could do a pthread_cond_wait here, but it would change the once-a-second
		// looking for record hearbeat behavior we get in the direct-DB mode
		// pthread_cond
		if(!ctxPtr->staged_data_occupied) {
			struct timespec timeToWake;
			struct timeval now;

			gettimeofday(&now, NULL);
			timeToWake.tv_sec = now.tv_sec + 1;
			timeToWake.tv_nsec = now.tv_usec*1000UL;

			DEBUG_LOG_SUB_SESSION(ch_info, "Waiting for record from filter");
			int status = pthread_cond_timedwait(&(ctxPtr->get_next_signal), &(ctxPtr->staging_data_lock), &timeToWake);
			if(0 != status && ETIMEDOUT != status) {
				DEBUG_LOG_SUB_SESSION(ch_info, "Error waiting for signal");
			}
			// pthread_cond_timedwait acquires the lock for us, but we don't need it just now
			// We'll reacquire at the top of the loop
			pthread_mutex_unlock(&(ctxPtr->staging_data_lock));
			continue;
		}
		break;
	}

	// We have the lock and we have a record ready for us.
	// Create and populate a record using the receive data
	// Consult jaldb_record.h for jaldb_record fields.
	// They should be created in that order here
	ctxPtr->rec = jaldb_create_record();

	ctxPtr->rec->network_nonce = ctxPtr->nonce;
	ctxPtr->nonce = NULL;

	// pid, uid - unknown at this time, will be populated by the subscriber using
	// the system metadata. We can ignore it
	//
	// sys_meta
	{
		struct jaldb_segment * sys_meta_seg = jaldb_create_segment();
		sys_meta_seg->length = ctxPtr->sys_meta_len;
		ctxPtr->sys_meta_len = 0;
		sys_meta_seg->payload = ctxPtr->sys_meta_buf;
		ctxPtr->sys_meta_buf = NULL;
		sys_meta_seg->on_disk = 0;
		sys_meta_seg->fd = -1;
		ctxPtr->rec->sys_meta = sys_meta_seg;
	}

	// app_meta
	{
		struct jaldb_segment * app_meta_seg = jaldb_create_segment();

		app_meta_seg->length = ctxPtr->app_meta_len;
		ctxPtr->app_meta_len = 0;
		app_meta_seg->payload = ctxPtr->app_meta_buf;
		ctxPtr->app_meta_buf = NULL;
		app_meta_seg->on_disk = 0;
		app_meta_seg->fd = -1;
		ctxPtr->rec->app_meta = app_meta_seg;
	}

	{
		struct jaldb_segment * payload_seg = jaldb_create_segment();
		payload_seg->length = ctxPtr->payload_len;
		ctxPtr->payload_len = 0;
		payload_seg->payload = ctxPtr->payload_buf;
		ctxPtr->payload_buf = NULL;
		if(ctxPtr->on_disk) {
			payload_seg->on_disk = 1;
			payload_seg->fd = ctxPtr->fd;
		} else {
			payload_seg->on_disk = 0;
			payload_seg->fd = -1;
		}
		// Note - the fd we are handed by the filter is already open
		// unlike the jaldb_get_next_record, do not open the segment here
		ctxPtr->on_disk = 0;
		ctxPtr->fd = -1;
		ctxPtr->rec->payload = payload_seg;
	}

	// source, hostname - ignore, not sent to the subscriber
	ctxPtr->rec->timestamp = ctxPtr->timestamp;
	ctxPtr->timestamp = NULL;

	// username, sec_lbl, version - ignore, not sent to the subscriber

	// we know that the type must be valid, else we would throw in select_channel
	ctxPtr->rec->type = db_type_from_rec_type(ch_info->type);

	// synced, confirmed, have_uid, host_uuid, uuid - ignore, not sent to the subscrber

	// We have now completely consumed the staged record. Mark the landing zone
	// as empty
	ctxPtr->staged_data_occupied = false;

	// Release the staging data lock
	pthread_mutex_unlock(&(ctxPtr->staging_data_lock));

	// If the socket thread is waiting on us, signal it to proceed immediately
	pthread_cond_signal(&(ctxPtr->socket_thread_signal));
	return JALDB_OK;
}

enum jaldb_status pub_get_next_record(
			jaln_session *sess,
			const struct jaln_channel_info *ch_info,
			char **timestamp,
			enum jaldb_rec_type db_type)
{
	enum jaldb_status ret = JALDB_E_NOT_FOUND;
	struct jaldb_record *rec = NULL;
	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(ch_info->type);

	//sessionTokenMap is not used in this method.
	(void)sessionTokenMap;

	std::shared_ptr<struct session_ctx_t> ctxPtr;

	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		// This would indicate the channel is going down, just return gracefully.
		// Jald's other mechanisms will handle the rest
		pthread_mutex_unlock(mapLock.get());
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session");
		goto out;
	}

	if ((ctxPtr->rec) && (JALDB_RTYPE_JOURNAL == db_type)) {
		/* Journal resume, so we already have a record */
		// Make a copy to match behavior of jaldb_next_*_record functions
		ret = JALDB_OK;
	} else {
		while (JALDB_E_NOT_FOUND == ret) {
			// Have to use timestamp since sess->mode is internal to the network library
			if (!*timestamp) {
				// Archive mode
				DEBUG_LOG_SUB_SESSION(ch_info, "Looking for a record in Archive Mode");
				// jaldb_next_* want to return a nonce, so we need to create a place to put it
				// even though we aren't going to use it
				char* nonce = NULL;
				ret = jaldb_next_unsynced_record(ctxPtr->db_ctx, db_type, &nonce, &(ctxPtr->rec));
				free(nonce);
			} else {
				// Live mode
				DEBUG_LOG_SUB_SESSION(ch_info, "Looking for a record in Live Mode, timestamp: %s",*timestamp);
				// jaldb_next_* want to return a nonce, so we need to create a place to put it
				// even though we aren't going to use it
				char* nonce = NULL;
				ret = jaldb_next_chronological_record(ctxPtr->db_ctx,
								     db_type,
								     &nonce,
								     &(ctxPtr->rec),
								     timestamp);
				free(nonce);
			}

			if (JALDB_E_NOT_FOUND == ret) {
				sleep(global_config.poll_time);
			}
			// Check if the session has gone down (usually a graceless remote disconnect)
			if (JAL_OK != jaln_session_is_ok(sess)) {
				ret = JALDB_E_NETWORK_DISCONNECTED;
				goto out;
			}
			// or if we have commanded jald to stop
			else if(exiting) {
				ret = JALDB_OK;
				goto out;
			}
		}
	}

	if (JALDB_OK != ret) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed to get next record");
		goto out;
	}

	rec = ctxPtr->rec;

	// Open fds if our payloads are on disk
	// This is currently only ever true for journals
	if(rec->sys_meta) {
		if (rec->sys_meta->on_disk) {
		// sets rec->sys_meta->fd internally
			ret = jaldb_open_segment_for_read(ctxPtr->db_ctx, rec->sys_meta);
			if (JALDB_OK != ret) {
				ret = JALDB_E_INVAL;
				goto out;
			}
		}
	}

	if (rec->app_meta) {
		if (rec->app_meta->on_disk) {
			// sets rec->app_meta->fd internally
			ret = jaldb_open_segment_for_read(ctxPtr->db_ctx, rec->app_meta);
			if (JALDB_OK != ret) {
				ret = JALDB_E_INVAL;
				goto out;
			}
		}
	}

	if (rec->payload) {
		if (rec->payload->on_disk) {
			// sets rec->payload->fd internally
			ret = jaldb_open_segment_for_read(ctxPtr->db_ctx, rec->payload);
			if (JALDB_OK != ret) {
				ret = JALDB_E_INVAL;
				goto out;
			}
		}
 	}

	ret = JALDB_OK;
out:
	return ret;
}

enum jal_status pub_send_records_feeder(
			jaln_session *sess,
			const struct jaln_channel_info *ch_info,
			char **timestamp,
			uint16_t subscriber_token)
{
	enum jal_status ret = JAL_E_INVAL;
	enum jaldb_status db_ret = JALDB_E_INVAL;
	enum jaln_record_type type = ch_info->type;

	enum jaldb_rec_type db_type = db_type_from_rec_type(type);
	if(JALDB_RTYPE_UNKNOWN == db_type) {
		return jaln_finish(sess);
	}

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);

	//sessionTokenMap is not used
	(void)sessionTokenMap;

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		// This would indicate the channel is going down
		pthread_mutex_unlock(mapLock.get());

		return jaln_finish(sess);
	}

	if(!global_args.use_filter) {
		// If not using the filter, initialize the db handle
		ctxPtr->db_ctx = setup_db_layer();
		if(NULL == ctxPtr->db_ctx) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to setup db");
			ret = JAL_E_INVAL;
			goto out;
		}
		// If not using the filter, and in archive mode, clear sent flags
		DEBUG_LOG_SUB_SESSION(ch_info, "Verifying previously sent records.");
		// Have to use timestamp since sess->mode is internal to the network library
		if (!*timestamp) {
			ctxPtr->archive_mode = true;
			db_ret = jaldb_mark_unsynced_records_unsent(ctxPtr->db_ctx, db_type);
			if (JALDB_OK != db_ret) {
				DEBUG_LOG_SUB_SESSION(ch_info, "Failed to verify records.");
				ret = JAL_E_INVAL;
				goto out;
			}
		}
	} else {
		// If we are using the filter, we need to stimulate the filter to start
		// sending us records for this session
		// Form up data for the message
		StartStreamArgs args;
		args.subscriberToken = subscriber_token;
		args.type = db_type;
		if(*timestamp) {
			args.mode = JALN_LIVE_MODE;
		} else {
			args.mode = JALN_ARCHIVE_MODE;
		}
		if(ctxPtr->resume_nonce) {
			// Give a non-owning pointer to the JalFilterStartStream message
			// We know the ctxPtr->resume_nonce will outlive the message, so this is safe
			// so long as we use addFieldByNonOwningPointer in the message constructor
			args.resumeNonce = ctxPtr->resume_nonce;
		}
		// Create and send the message
		pthread_mutex_lock(&request_socket_lock);
		requestSocket.sendMsg(JalFilterStartStream(args));
		pthread_mutex_unlock(&request_socket_lock);
	}

	do {
		// nonce will be a new copy that the caller must free
		// The buffers will point to the record stored within the session
		// The record is cleaned up by pub_on_record_complete
		if (global_args.use_filter){
			db_ret = pub_get_next_record_on_socket(sess,
						ch_info);
		}
		else{
			db_ret = pub_get_next_record(sess,
					ch_info,
					timestamp,
					db_type);
		}

		// Break out of this loop without handling the record if jald has been commanded to stop
		if(exiting) {
			ret = JAL_OK;
			goto out;
		}

		if (JALDB_OK != db_ret) {
			if (JALDB_E_NOT_FOUND == db_ret) {
				ret = JAL_OK;
				goto out;
			}
			if (JALDB_E_NETWORK_DISCONNECTED == db_ret) {
				ret = JAL_E_NOT_CONNECTED;
				goto out;
			}
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to get next record (%d)", db_ret);
			ret = JAL_E_INVAL;
			goto out;
		}

		ret = jaln_send(sess, ctxPtr->rec);

		// If we're using the filter, we need to send recordError if the send
		// failed for any reason
		// Note that this doesn't send record failure for digest challenge failures.
		// That's handled elsewhere, this is strictly for transport layer failures.
		if (global_args.use_filter && JAL_OK != ret){
			// Form up the message data
			RecordResponseArgs args;
			args.mType = FilterMessageType::RecordError;
			args.subscriberToken = subscriber_token;
			args.type = db_type;
			args.recordNonce = ctxPtr->rec->network_nonce;

			// Create and send the message
			pthread_mutex_lock(&request_socket_lock);
			requestSocket.sendMsg(JalFilterRecordResponse(args));
			pthread_mutex_unlock(&request_socket_lock);
		}

		if (JAL_OK != ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to send record (%d)", ret);
			goto out;
		}
	} while (JALDB_OK == db_ret);

out:
	// If we are using the filter, we need to stimulate the filter to stop
	// sending us records for this session
	if (global_args.use_filter){
		StopStreamArgs args;
		args.subscriberToken = subscriber_token;
		args.type = db_type;
		pthread_mutex_lock(&request_socket_lock);
		requestSocket.sendMsg(JalFilterStopStream(args));
		pthread_mutex_unlock(&request_socket_lock);

		// ensure shutting_down is set so the receive thread will terminate
		// regardless of how we got here, and signal the receive thread to
		// resume processing so it exits quickly
		pthread_cond_signal(&(ctxPtr->socket_thread_signal));
	}

	if(JALDB_E_NETWORK_DISCONNECTED == db_ret || JAL_E_NOT_CONNECTED == ret) {
		ret = jaln_finish(sess);
		ctxPtr->channel_closed = true;
	}
	return ret;
}

/*
 * Called in a thread to handle journal data publishing.  Allocates memory for return status.
 * Caller is responsible for freeing this memory
 */
__attribute__((noreturn))
void *pub_send(__attribute__((unused)) void *args)
{
	enum jal_status *ret = (enum jal_status *) jal_malloc(sizeof(enum jal_status));
	*ret = JAL_E_INVAL;
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	const struct jaln_channel_info *ch_info = data->ch_info;

	char *timestamp = NULL;

	if (data->timestamp) {
		timestamp = jal_strdup(data->timestamp);
	}

	jaln_add_session_ref(sess);
	*ret = pub_send_records_feeder(sess, ch_info, &timestamp, data->subscriber_token);
	jaln_remove_session_ref(sess);
	free(timestamp);
	pthread_exit((void*)ret);
}

static void sig_handler(__attribute__((unused)) int sig)
{
	exiting = 1;
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
	// Initialize global maps for session_ctx_t storage/mapping
	// Add empty maps for each of journal, audit, log
	sessionHostMaps.insert({JALN_RTYPE_JOURNAL, {}});
	sessionHostMaps.insert({JALN_RTYPE_AUDIT, {}});
	sessionHostMaps.insert({JALN_RTYPE_LOG, {}});
	sessionTokenMaps.insert({JALN_RTYPE_JOURNAL, {}});
	sessionTokenMaps.insert({JALN_RTYPE_AUDIT, {}});
	sessionTokenMaps.insert({JALN_RTYPE_LOG, {}});
	try {
		mapLocks.insert({JALN_RTYPE_JOURNAL, std::make_shared<pthread_mutex_t>()});
		if (0 != pthread_mutex_init(mapLocks.at(JALN_RTYPE_JOURNAL).get(), NULL)) {
			fprintf(stderr, "Error initializing journal session lock");
			return -1;
		}
		mapLocks.insert({JALN_RTYPE_AUDIT, std::make_shared<pthread_mutex_t>()});
		if (0 != pthread_mutex_init(mapLocks.at(JALN_RTYPE_AUDIT).get(), NULL)) {
			fprintf(stderr, "Error initializing audit session locks");
			return -1;
		}
		mapLocks.insert({JALN_RTYPE_LOG, std::make_shared<pthread_mutex_t>()});
		if (0 != pthread_mutex_init(mapLocks.at(JALN_RTYPE_LOG).get(), NULL)) {
			fprintf(stderr, "Error initializing log session locks");
			return -1;
		}
	} catch(std::out_of_range& e) {
		fprintf(stderr, "Error initializing session locks");
		return -1;
	}

	struct jaln_connection_callbacks *conn_cbs = NULL;
	struct jaln_publisher_callbacks *pub_cbs = NULL;
	struct jal_digest_ctx *dctx = NULL;
	enum jal_status jaln_ret;
	int rc = 0;
	std::stringstream ss(std::ios_base::out);
	struct jal_seccomp_enforcer_t* seccomp_enforcer = NULL;

	enum jal_digest_algorithm *digest_list = (enum jal_digest_algorithm *) jal_malloc(sizeof(enum jal_digest_algorithm));
	size_t num_digests = 0;

	rc = setup_signals();
	if (0 != rc) {
		goto out;
	}

	// initialize global_args
	global_args.daemon = 1;
	global_args.debug_flag = false;
	global_args.config_path = NULL;
	global_args.enable_tls = true;
	global_args.pid_path = NULL;
	global_args.use_filter = false;

	// parse command line option
	rc = argp_parse(&argp, argc, argv, 0, 0, NULL);
	if (0 != rc)
	{
		printf("ARGP_ERR_UNKNOWN: %d\n", ARGP_ERR_UNKNOWN);
		goto version_out;
	}

	DEBUG_LOG("Config Path: %s\tDebug: %d\n", global_args.config_path, global_args.debug_flag);

	if (!global_args.config_path) {
		rc = JALD_E_CONFIG_LOAD;
		goto out;
	}

	seccomp_enforcer = jal_seccomp_enforcer_create(global_args.config_path);
	if(NULL == seccomp_enforcer){
		goto out;
	}

	if (0 != jal_seccomp_enforcer_apply_initial(seccomp_enforcer)){
		goto out;
	}

	try {
		global_config = JaldConfig(global_args.config_path);
	} catch(std::runtime_error &e) {
		DEBUG_LOG("Failed to read config file: %s\n", e.what());
		rc = JALD_E_CONFIG_LOAD;
		goto out;
	}

	global_config.print_config();

	if (global_args.daemon) {
		DEBUG_LOG("Handing off process to daemon");
		DEBUG_LOG("For additional logs, set log_dir in config file and refer to <log_dir>/std*");
		if(0 != jalu_daemonize(global_config.log_dir.c_str(), global_config.pid_file.c_str())) {
			// Depending on exactly what fails in the daemonizing process, this log
			// may not actually get written anywhere, as stdin/out/err are all closed
			// and only reopened if log_dir is set and is accessible
			DEBUG_LOG("Failed to daemonize process");
			rc = -1;
			goto out;
		}
	}

	if (-1 == jalu_pid(global_args.pid_path))
	{
		DEBUG_LOG("Failed to write pid file");
		rc = -1;
		goto out;
	}

	conn_cbs = jaln_connection_callbacks_create();
	conn_cbs->connect_request_handler = on_connect_request;
	conn_cbs->on_channel_close = on_channel_close;
	conn_cbs->on_connection_close = on_connection_close;
	conn_cbs->connect_ack = on_connect_ack;
	conn_cbs->connect_nack = on_connect_nack;


	pub_cbs = jaln_publisher_callbacks_create();
	pub_cbs->on_journal_resume = pub_on_journal_resume;
	pub_cbs->on_subscribe = pub_on_subscribe;
	pub_cbs->on_record_complete = pub_on_record_complete;
	pub_cbs->sync = pub_sync;
	pub_cbs->notify_digest = pub_notify_digest;
	pub_cbs->peer_digest = pub_peer_digest;

	jctx = jaln_context_create();
	if (!jctx) {
		DEBUG_LOG("Failed to create the jaln_context");
		rc = -1;
		goto out;
	}
	jaln_context_set_debug(jctx, global_args.debug_flag);
	if (JAL_OK != jaln_register_encoding(jctx, "xml")) {
		DEBUG_LOG("Failed to register default encoding");
		rc = -1;
		goto out;
	}

	if (JAL_OK != jal_get_digest_algorithm_list(global_config.digest_algorithms.c_str(), global_args.digest_algorithms, &digest_list, &num_digests)) {
		DEBUG_LOG("Failed to parse digest list");
		rc = -1;
		goto out;
	}

	for (size_t i = 0; i < num_digests; i++) {
		dctx = jal_digest_ctx_create(digest_list[i]);

		if (JAL_OK != jaln_register_digest_algorithm(jctx, dctx)) {
			DEBUG_LOG("Failed to register digest algorithm");
			jal_digest_ctx_destroy(&dctx);
			dctx = NULL;
			rc = -1;
			goto out;
		}
	}

	// The jaln_context owns the digest algorithm, so don't keep a
	// reference to it.
	dctx = NULL;
	if (global_args.enable_tls) {
		jaln_ret = jaln_register_tls(
			jctx,
			global_config.private_key.c_str(),
			global_config.public_cert.c_str(),
			global_config.remote_cert_dir.c_str());
		if (JAL_OK != jaln_ret) {
			DEBUG_LOG("Failed to register TLS");
			rc = -1;
			goto out;
		}
	}

	jaln_ret = jaln_register_connection_callbacks(jctx, conn_cbs);
	if (JAL_OK != jaln_ret) {
		DEBUG_LOG("Failed to register connection callbacks");
		rc = -1;
		goto out;
	}
	jaln_ret = jaln_register_publisher_callbacks(jctx, pub_cbs);
	if (JAL_OK != jaln_ret) {
		DEBUG_LOG("Failed to register publisher callbacks");
		rc = -1;
		goto out;
	}

	if (0 != pthread_mutex_init(&exit_count_lock, NULL)) {
		DEBUG_LOG("Failed to initialize exit_count_lock");
		rc = -1;
		goto out;
	}
	if (0 != pthread_mutex_init(&request_socket_lock, NULL)) {
		DEBUG_LOG("Failed to initialize request_socket_lock");
		rc = -1;
		goto out;
	}

	ss << global_config.port;

	// If we're using the filter, create the threads which monitor the receive record
	// sockets now. They depend on the *_subs hashmaps existing, even if they won't be
	// populated with anything yet
	//
	// Set up the listening sockets first, so it doesn't matter which order the two
	// CLIs start up in
	if (global_args.use_filter) {
		pthread_attr_t attr;
		if (0 != pthread_attr_init(&attr)) {
			DEBUG_LOG("Failed to initialize pthread attr struct");
			rc = -1;
			goto out;
		}
		if (0 != pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
			DEBUG_LOG("ERROR in pthread_attr_setdetachstate()");
			rc = -1;
			goto out;
		}

		// Give the threads ownership of the args to the thread so we won't have to
		// manage its lifetime in main
		if(0 != pthread_create(
				&journal_receive_thread,
				&attr,
				record_receive_thread,
				(void*)new ReceiveThreadArgs {
					JALN_RTYPE_JOURNAL,
					global_config.filter_socket_basename + "_J"
				}))
		{
			DEBUG_LOG("ERROR creating a thread");
			rc = -1;
			goto out;
		}
		if(0 != pthread_create(
				&audit_receive_thread,
				&attr,
				record_receive_thread,
				(void*)new ReceiveThreadArgs {
					JALN_RTYPE_AUDIT,
					global_config.filter_socket_basename + "_A"
				}))
		{
			DEBUG_LOG("ERROR creating a thread");
			rc = -1;
			goto out;
		}
		if(0 != pthread_create(
				&log_receive_thread,
				&attr,
				record_receive_thread,
				(void*)new ReceiveThreadArgs {
					JALN_RTYPE_LOG,
					global_config.filter_socket_basename + "_L"
				}))
		{
			DEBUG_LOG("ERROR creating a thread");
			rc = -1;
			goto out;
		}
		pthread_attr_destroy(&attr);
	}

	// The listening sockets are already set up, so we can block on waiting for the filter
	// to start up here
	if (global_args.use_filter) {
		if(global_config.filter_socket_basename.empty()) {
			DEBUG_LOG("filter_socket_basename required when running with use_filter flag");
			rc = -1;
			goto out;
		}
		std::string requestSocketPath = global_config.filter_socket_basename;
		requestSocketPath += std::string("_request");
		printf("Setting up filter request socket: %s\n", requestSocketPath.c_str());
		while(!requestSocket.connected && !exiting){
			DEBUG_LOG("Attempting to connect to filter request socket: %s...",
				requestSocketPath.c_str());
			pthread_mutex_lock(&request_socket_lock);
			requestSocket.connectSocket(requestSocketPath);
			pthread_mutex_unlock(&request_socket_lock);
			sleep(1);
		}
		printf("Connected to filter request socket: %s\n", requestSocketPath.c_str());
	}
	else{
		printf("NOT Setting up filter request socket.\n");
	}

	jaln_ret = jaln_listen(jctx, global_config.host.c_str(), ss.str().c_str(), NULL);
	if (JAL_OK != jaln_ret) {
		DEBUG_LOG("Failed to start listening");
		rc = -1;
		goto out;
	}

	if (0 != jal_seccomp_enforcer_apply_final(seccomp_enforcer)){
		goto out;
	}

	while (!exiting) {
		sleep(60);
	}

out:
	while (threads_to_exit > 0) {
		sleep(1);
	}
	jaln_listener_shutdown(jctx);
	jaln_listener_wait(jctx);
	free_global_args();
	pthread_mutex_destroy(&request_socket_lock);
	pthread_mutex_destroy(&exit_count_lock);
	jaln_publisher_callbacks_destroy(&pub_cbs);
	free(digest_list);
	jal_seccomp_enforcer_destroy(&seccomp_enforcer);
	free((char*)argp_program_version);
	jaln_context_destroy(&jctx);
	return rc;

version_out:
	free(digest_list);
	return 0;
}

static error_t parse_opt(int key_in,
		char *arg, __attribute__((unused)) struct argp_state *state)
{
	switch (key_in)
	{
		case 'd':
			global_args.debug_flag = true;
			break;
		case 'c':
			if (global_args.config_path) {
				free(global_args.config_path);
			}
			global_args.config_path = strdup(arg);
			break;
		case OPT_NO_DAEMON:
			global_args.daemon = 0;
			break;
		case 's':
			// disable TLS
			global_args.enable_tls = false;
			break;
		case 'f':
			// enable filter
			global_args.use_filter = true;
			break;
		case 'p':
			if (global_args.pid_path) {
				free(global_args.pid_path);
			}
			global_args.pid_path = strdup(arg);
			break;
		case 'a':
			if (global_args.digest_algorithms) {
				free(global_args.digest_algorithms);
			}
			global_args.digest_algorithms = strdup(arg);
			break;
		case ARGP_KEY_END:
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

__attribute__((noreturn)) void usage()
{
	fprintf(stderr, "Usage: jald -c, --config <config_file> [-d, --debug] [-s, --disable-tls] [-v, --version] [--no-daemon] [-a, --digest-algorithms <digest-algorithms>]\n");
	exit(1);
}

void free_global_args(void)
{
	free((void*) global_args.config_path);
	free((void*) global_args.pid_path);
	free((void*) global_args.digest_algorithms);
}
