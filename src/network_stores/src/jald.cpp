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
#include <chrono>
#include <jalop/jaln_network.h>
#include <jalop/jal_digest.h>
#include <limits.h>
#include <libconfig.h>
#include <pthread.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <fcntl.h>

#include <jalop/jal_version.h>

#include "jal_asprintf_internal.h"
#include "jaldb_context.hpp"
#include "jalns_strings.h"
#include "jalu_daemonize.h"
#include "jal_config.h"
#include "jaldb_config.h"
#include "jaldb_segment.h"
#include "jaldb_strings.h"
#include "jaldb_record.h"
#include "jaldb_utils.h"
#include "jal_alloc.h"
#include "jaldb_record_dbs.h"
#include "jal_socket.hpp"
#include <jalop/jal_seccomp_enforcer.h>
#include "jald_common_definitions.hpp"
#include "jald_filter_extension.hpp"
#include "jald_callbacks.hpp"
#include "jald_config.hpp"

#include <sys/socket.h>
#include <sys/un.h>

#include <thread>

#define VERSION_CALLED 1

JaldConfig global_config;

global_args_t global_args;

enum jald_status {
	JALD_E_CONFIG_LOAD = -1024,
	JALD_E_DB_INIT,
	JALD_E_NOMEM,
	JALD_E_GEN,
	JALD_OK = 0,
};

// A counter of threads which need to close before we shut down
int threads_to_exit = 0;
// A mutex to ensure threads_to_exist remains coherent
pthread_mutex_t exit_count_lock;

// short hand for long map type names
using SessionHostMap = std::map<std::string, std::shared_ptr<session_ctx_t>>;
using SessionTokenMap = std::map<uint16_t, std::shared_ptr<session_ctx_t>>;

// NOTE - these maps have program lifetime. They are accessed with
// unguarded .at() calls essentially everywhere, which will throw if the specified
// entry does not exist.
// The journal, audit, log entries are created immediately in main and should never
// be removed. Failure to adhere to this will cause program termination by exception.
//
// Set up a map of hostname string to session_ctx_t, store by shared_ptr so we can
// refer to this same session_ctx_t from our subscriber_token map safely
// Shared via extern with jald_filter_extension.cpp and jald_common_definitions.hpp
std::map<enum jaln_record_type, SessionHostMap> sessionHostMaps;
// Set up a similar map to the matching lock
// Shared via extern with jald_filter_extension.cpp and jald_common_definitions.hpp
std::map<enum jaln_record_type, std::shared_ptr<pthread_mutex_t>> mapLocks;
// When using the filter, we also need to map from subscriber tokens to sessions
// Shared via extern with jald_filter_extension.cpp and jald_common_definitions.hpp
std::map<enum jaln_record_type, SessionTokenMap> sessionTokenMaps;


// When non-0, the CLI should clean up and exit
// Shared via extern with jald_filter_extension.cpp
int exiting = 0;
// Lock to serialize write access to the inline filter socket
pthread_mutex_t request_socket_lock;
UDSSendSocket requestSocket;
uint16_t next_subscriber_token = 1;
pthread_t journal_receive_thread;
pthread_t audit_receive_thread;
pthread_t log_receive_thread;

// argp
const char *argp_program_version = JAL_VERSION_AS_STR;
const char *argp_program_bug_address = 0;
static char args_doc[] = "--config config_file";
/* keys for options without short-options*/
#define OPT_NO_DAEMON 1 /* --no-daemon */
static char doc[] =
	"jald -- JALoPv2 Network Store that attempts to connect to and then publish JALoP records to a remote JALoPv2 peer subscriber.";
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
// Throws if SessionMaps can't be constructed

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

enum jaldb_status pub_get_next_record_on_socket(
			jaln_session *sess,
			const struct jaln_channel_info *ch_info)
{
	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(ch_info->type);

	//sessionTokenMap is not used in this method
	(void)sessionTokenMap;

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		pthread_mutex_unlock(mapLock.get());
		return JALDB_E_NETWORK_DISCONNECTED;
	}

	while(1) {

		// We've been commanded to shut down, return early
		if(exiting || ctxPtr->shutting_down) {
			return JALDB_E_NETWORK_DISCONNECTED;
		}

		// Check if jaln_session is fine.
		// this lets us know if the session was teriminated from the subscriber side
		// or there was a network failure
		if (JAL_OK != jaln_session_is_ok(sess)) {
			return JALDB_E_NETWORK_DISCONNECTED;
		}

		pthread_mutex_lock(&(ctxPtr->staging_data_lock));

		// Wait until a record is staged
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
			char** timestamp,
			enum jaldb_rec_type db_type)
{
	enum jaldb_status ret = JALDB_E_NOT_FOUND;
	struct jaldb_record *rec = NULL;

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(ch_info->type);

	//sessionTokenMap is not used
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
				char* nonce = NULL;
				ret = jaldb_next_unsynced_record(ctxPtr->db_ctx, db_type, &nonce, &(ctxPtr->rec));
				// For jald's purposes, we only care about the network nonce, which is already
				// stored in the record, discard the copy of nonce from the jaldb_next* functions
				free(nonce);

			} else {
				// Live mode
				DEBUG_LOG_SUB_SESSION(ch_info, "Looking for a record in Live Mode, timestamp: %s",*timestamp);
				char* nonce = NULL;
				ret = jaldb_next_chronological_record(ctxPtr->db_ctx,
									db_type,
									&nonce,
									&(ctxPtr->rec),
									timestamp);
				// For jald's purposes, we only care about the network nonce, which is already
				// stored in the record, discard the copy of nonce from the jaldb_next* functions
				free(nonce);
			}

			// Check if jaln_session is fine.
			if (JAL_OK != jaln_session_is_ok(sess)) {
				DEBUG_LOG_SUB_SESSION(ch_info, "Session issues detected 1");
				ret = JALDB_E_NETWORK_DISCONNECTED;
				goto out;
			}

			if (JALDB_E_NOT_FOUND == ret) {
				sleep(global_config.poll_time);

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
	if(JALDB_OK != ret) {
		jaldb_destroy_record(&ctxPtr->rec);
	}
	return ret;
}

void pub_send_records_feeder(
			jaln_session *sess,
			const struct jaln_channel_info *ch_info,
			char **timestamp,
			uint16_t subscriber_token)
{
	enum jal_status ret = JAL_E_INVAL;
	enum jaldb_status db_ret = JALDB_E_INVAL;
	enum jaln_record_type type = ch_info->type;

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	enum jaldb_rec_type db_type = db_type_from_rec_type(type);
	if(JALDB_RTYPE_UNKNOWN == db_type) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Unknown Record Type.\n");
		return;
	}
	enum jaln_publish_mode mode = jaln_session_get_publish_mode(sess);
	if(JALN_UNKNOWN_MODE == mode) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Unknown Mode.\n");
		return;
	}

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);

	pthread_mutex_lock(mapLock.get());

	// In the case of a journal resume, the session will already exist
	if (0 == sessionHostMap.count(std::string(ch_info->hostname))) {

		// The session does not alreaady exist. Create it
		// This is a shared pointer to allow both maps to point at the same context safely and ensures
		// the context object can't be destroyed while in use, even if it is removed from the maps
		ctxPtr = std::make_shared<struct session_ctx_t>(
			std::string(ch_info->hostname),
			subscriber_token);

		if (!global_args.use_filter){
			ctxPtr->db_ctx = setup_db_layer();
			if(NULL == ctxPtr->db_ctx) {
				DEBUG_LOG_SUB_SESSION(ch_info, "Failed to setup db");
				pthread_mutex_unlock(mapLock.get());
				ret = JAL_E_INVAL;
				goto out;
			}
		}

		// Insert this session by hostname and token to our maps
		std::string type_str = stringify_type(ch_info->type);
		DEBUG_LOG_SUB_SESSION(ch_info, "Inserting session with hostname: %s, token: %d, type: %s\n",
			ch_info->hostname, subscriber_token, type_str.c_str());
		sessionHostMap.insert({std::string(ch_info->hostname), ctxPtr});
		sessionTokenMap.insert({subscriber_token, ctxPtr});
	} else {
		// We just did a .count() with this value, so we know .at will not throw
		ctxPtr = sessionHostMap.at(ch_info->hostname);
	}
	pthread_mutex_unlock(mapLock.get());

	DEBUG_LOG_SUB_SESSION(ch_info, "Verifying previously sent records.");

	// Only need to clear sent flags for archive mode connection
	if(JALN_ARCHIVE_MODE == mode) {
		if (global_args.use_filter){
			DEBUG_LOG_SUB_SESSION(ch_info, "Using filter.");
		}
		else{
			db_ret = jaldb_mark_unsynced_records_unsent(ctxPtr->db_ctx, db_type);
			if (JALDB_OK != db_ret) {
				DEBUG_LOG_SUB_SESSION(ch_info, "Failed to verify records.");
				ret = JAL_E_INVAL;
				goto out;
			}
		}
	}

	// If we are using the filter, we need to stimulate the filter to start
	// sending us records for this session
	if (global_args.use_filter){
		// Form up data for the message
		StartStreamArgs args;
		args.subscriberToken = subscriber_token;
		args.type = db_type;
		args.mode = mode;
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

	while(true) {
		// The records will be placed in ctxPtr->rec
		if (global_args.use_filter){
			db_ret = pub_get_next_record_on_socket(
						sess,
						ch_info);
		}
		else{
			db_ret = pub_get_next_record(
						sess,
						ch_info,
						timestamp,
						db_type);
		}

		if (JALDB_OK != db_ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to get next record (%d)", db_ret);
			ret = JAL_E_INVAL;
			goto out;
		}

		ret = jaln_send(sess, ctxPtr->rec);
		// Success or fail, we're done with this record now
		// Make a copy of the network nonce before we destroy the record
		std::string nonce_copy = std::string(ctxPtr->rec->network_nonce);
		jaldb_destroy_record(&ctxPtr->rec);

		// Valid return values from jaln_send are:
		// JAL_OK - The record was sent successfully, the digest challenge (if configured) was
		// successful, and the record has been marked sent/sync in callbacks.
		// RECORD_FAILURE - A non-session related failure. Something is wrong with this record itself. Leave
		// it marked as sent so we don't keep retrying it in a loop.
		// SESSION_FAILURE - The session is suspect, bail out of the loop so we shut it down and 
		// try reconnecting. The record will be marked unsent when we re-enter this function
		// JAL_E_INVAL_PARAM - Something jald provided to jaln_send was invalid, kill the session
		switch(ret) {
			case JAL_OK:
				// The record has been fully handled and was successful
				// Nothing to do here
				break;
			case JAL_E_RECORD_FAILURE:
				DEBUG_LOG_SUB_SESSION(ch_info, "Failed to send record with status: (%d). ", ret);
			// The current record is suspect. We don't want to get trapped in a loop sending the same record
			// over and over again. Leave it marked sent and move on to the next record. This record will
			// be tried again (archive only) next time a session of this type is created
				if (global_args.use_filter){
					// Inform the filter that the record failed and must not be sent again during this session
					DEBUG_LOG_SUB_SESSION(ch_info, "Sending RecordErrorNoRetry to filter.\n");
					// Form up the message data
					RecordResponseArgs args;
					args.mType = FilterMessageType::RecordErrorNoRetry;
					args.subscriberToken = subscriber_token;
					args.type = db_type;
					args.recordNonce = nonce_copy.c_str();

					// Create and send the message
					pthread_mutex_lock(&request_socket_lock);
					requestSocket.sendMsg(JalFilterRecordResponse(args));
					pthread_mutex_unlock(&request_socket_lock);
				}
				// If not using the filter, we don't want to mark this record as unsent so we don't try
				// to send it again
				break;
			default:
				DEBUG_LOG_SUB_SESSION(ch_info, "Unexpected status from jaln_send: (%d). Treating as Session Failure.", ret);
				[[fallthrough]];
			case JAL_E_SESSION_FAILURE:
				DEBUG_LOG_SUB_SESSION(ch_info, "Failed to send record with status: (%d). ", ret);
				// The record failed to transfer, but for some reason not related to the record itself
				// The session will be terminated and the record may be retried
				//
				// If using the filter, when the session is terminated the filter will drop any in-progress
				// records from its tracking list. Sending RecordError is not necessary
				//
				// If not using the filter, the record will be marked as unsent when the session
				// is recreated anyway, so we don't need to mark it here

				// Break the loop, which will bring down the session and allow for a reconnect attempt
				goto out;
				break;
		}
	}

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
	jaln_finish(sess);
}

/*
 * Called in a thread to handle record data publishing.
 */
__attribute__((noreturn))
void *pub_send(__attribute__((unused)) void *args)
{
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	const struct jaln_channel_info *ch_info = data->ch_info;

	char *timestamp = NULL;

	if (data->timestamp) {
		timestamp = jal_strdup(data->timestamp);
		free(data->timestamp);
	}

	pub_send_records_feeder(sess, ch_info, &timestamp, data->subscriber_token);

	free(data);

	free(timestamp);

	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit -= 1;
	pthread_mutex_unlock(&exit_count_lock);

	pthread_exit((void*)NULL);
}

static void sig_handler(__attribute__((unused)) int sig)
{
	//#883 - Ignore SIGPIPE signal thrown by libcurl to prevent
	//the termination of jald when the c jal_subscriber is closed.
	if (SIGPIPE == sig)
	{
		fprintf(stdout, "Ignoring SIGPIPE\n");
	}
	else
	{
		exiting = 1;
	}
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
		
	jaln_context *jctx = NULL;
	enum jal_status jaln_ret;
	int rc = 0;
	struct jal_seccomp_enforcer_t* seccomp_enforcer = NULL;

	enum jal_digest_algorithm *digest_list = (enum jal_digest_algorithm *) jal_malloc(sizeof(enum jal_digest_algorithm));
	size_t num_digests = 0;

	rc = setup_signals();
	if (0 != rc) {
		goto quick_out;
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
		goto quick_out;
	}

	DEBUG_LOG("Config Path: %s\tDebug: %d\n", global_args.config_path, global_args.debug_flag);

	if (!global_args.config_path) {
		rc = JALD_E_CONFIG_LOAD;
		goto quick_out;
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
		fprintf(stderr, "Failed to load config file with error: %s\n", e.what());
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
					global_config.filter_socket_basename + std::string("_J")
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
					global_config.filter_socket_basename + std::string("_A")
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
					global_config.filter_socket_basename + std::string("_L")
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
	
	if (0 != jal_seccomp_enforcer_apply_final(seccomp_enforcer)){
		goto out;
	}

	// TODO: Try just while(!exiting) here, it prevents us trying to connect once
	// when we're already going down because a ctrl-c happened during startup
	do {
		// set up JALoP contexts for each peer
		for (PeerConfig& peer : global_config.peers) {
			if (peer.connected) {
				// alreay connected
				continue;
			}
			// Since the peer is no longer connected (or has not yet connected
			// the firt time) cleanly shutdown the active connection if it exists
			if(peer.conn) {
				jaln_connection_destroy(&(peer.conn));
			}

			jctx = peer.net_ctx;
			jaln_context_destroy(&jctx);
			sleep(1);
			jctx = jaln_context_create();

			if (!jctx) {
				DEBUG_LOG("Failed to create the jaln_context");
				rc = -1;
				goto out;
			}
			if (JAL_OK != jaln_register_compression(jctx, "none")) {
				DEBUG_LOG("Failed to register default compression");
				rc = -1;
				goto out;
			}

			if (JAL_OK != jal_get_digest_algorithm_list(global_config.digest_algorithms.c_str(), global_args.digest_algorithms, &digest_list, &num_digests)) {
				DEBUG_LOG("Failed to parse digest list");
				rc = -1;
				goto out;
			}

			for (size_t j = 0; j < num_digests; j++) {
				struct jal_digest_ctx *dctx = jal_digest_ctx_create(digest_list[j]);

				if (JAL_OK != jaln_register_digest_algorithm(jctx, dctx)) {
					DEBUG_LOG("Failed to register digest algorithm");
					jal_digest_ctx_destroy(&dctx);
					rc = -1;
					goto out;
				}
			}

			// The jaln_context owns the digest algorithm, so don't keep a
			// reference to it.
			if ((!peer.dc_config[0].empty() &&
				JAL_OK != jaln_register_digest_challenge_configuration(jctx, peer.dc_config[0].c_str())) ||
				(!peer.dc_config[1].empty() &&
				JAL_OK != jaln_register_digest_challenge_configuration(jctx, peer.dc_config[1].c_str())))
			{
				DEBUG_LOG("Failed to register digest challenge configuration");
				rc = -1;
				goto out;
			}
			if (JAL_OK != jaln_register_publisher_id(jctx, global_config.pub_id.c_str())) {
				DEBUG_LOG("Failed to register publisher ID");
				rc = -1;
				goto out;
			}
			if (global_args.enable_tls) {
				jaln_ret = jaln_register_tls(jctx, global_config.private_key.c_str(), global_config.public_cert.c_str(),
					peer.cert_dir.c_str());
				if (JAL_OK != jaln_ret) {
					DEBUG_LOG("Failed to register TLS");
					rc = -1;
					goto out;
				}
			}

			{ // local scope for conn_cbs
				struct jaln_connection_callbacks *conn_cbs = NULL;
				conn_cbs = jaln_connection_callbacks_create();
				conn_cbs->on_channel_close = on_channel_close;
				conn_cbs->on_connection_close = on_connection_close;
				conn_cbs->connect_ack = on_connect_ack;
				conn_cbs->connect_nack = on_connect_nack;

				jaln_ret = jaln_register_connection_callbacks(jctx, conn_cbs);
				if (JAL_OK != jaln_ret) {
					DEBUG_LOG("Failed to register connection callbacks");
					jaln_connection_callbacks_destroy(&conn_cbs);
					rc = -1;
					goto out;
				}
			}

			{ // local scope for pub_cbs
				struct jaln_publisher_callbacks *pub_cbs = NULL;
				pub_cbs = jaln_publisher_callbacks_create();
				pub_cbs->on_journal_resume = pub_on_journal_resume;
				pub_cbs->on_subscribe = pub_on_subscribe;
				pub_cbs->on_record_complete = pub_on_record_complete;
				pub_cbs->sync = pub_sync;
				pub_cbs->notify_digest = pub_notify_digest;
				pub_cbs->peer_digest = pub_peer_digest;

				jaln_ret = jaln_register_publisher_callbacks(jctx, pub_cbs);
				if (JAL_OK != jaln_ret) {
					DEBUG_LOG("Failed to register publisher callbacks");
					jaln_publisher_callbacks_destroy(&pub_cbs);
					rc = -1;
					goto out;
				}
			}

			setNetworkTimeout(jctx, global_config.network_timeout);
			setRetryConfig(jctx, global_config.http_client_retry_count, global_config.http_client_retry_delay);
			setAllowSelfSignedCerts(jctx, global_config.allow_self_signed_certs);
			peer.net_ctx = jctx;

			++peer.retries;
			std::stringstream ss(std::ios_base::out);
			ss << peer.port;
			peer.conn = jaln_publish(peer.net_ctx, peer.host.c_str(), ss.str().c_str(),
				peer.record_types, peer.mode, (void*)&peer);
			if (!peer.conn) {
				DEBUG_LOG("Failed connection attempt %lld to %s:%llu", peer.retries, peer.host.c_str(), peer.port);
			} else {
				peer.retries = 0;
				peer.connected = true;

				// Each time we successfully connect to a subscriber, roll the next_subscriber_token
				// This is used when generating unique tokens to map channels to subscribers for use
				// in the in-line filter. See pub_on_subscribe and pub_on_journal_resume
				next_subscriber_token++;
				
			}
		} // for loop over peers

		if (global_config.retry_interval == -1) {
			// don't retry
			// wait for a signal and then check if we should be exiting
			while (!exiting) {
				pause();
			}
			break;
		}

		unsigned int remaining = global_config.retry_interval;
		while ((remaining = sleep(remaining))) {
			// interrupted by a signal
			if (exiting) {
				break;
				}
			}
	} while (!exiting);

	// try to disconnect from each peer
	for (PeerConfig& peer : global_config.peers) {
		if (peer.conn) {
			jal_status status = jaln_disconnect(peer.conn);
			if (JAL_OK == status) {
			  DEBUG_LOG("Disconnected sessions with Subscriber");
			} else {
			  DEBUG_LOG("Failed to disconnect sessions with Subscriber");
			}
		}
	}

out:
	while (threads_to_exit > 0) {
		sleep(1);
	}
	// try to free the connection to each peer
	// also destroy any remaining jaln_context for each peer
	for (PeerConfig& peer : global_config.peers) {
		if (peer.conn) {
			jaln_connection_destroy(&(peer.conn));
		}
		if(peer.net_ctx) {
			jaln_context_destroy(&(peer.net_ctx));
		}
	}
	free_global_args();
	pthread_mutex_destroy(&exit_count_lock);

quick_out:
	free(digest_list);
	jal_seccomp_enforcer_destroy(&seccomp_enforcer);
	return rc;
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

void free_global_args(void)
{
	free((void*) global_args.config_path);
	free((void*) global_args.pid_path);
	free((void*) global_args.digest_algorithms);
}
