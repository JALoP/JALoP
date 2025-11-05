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
#include "jal_config.h"
#include "jaldb_segment.h"
#include "jaldb_record.h"
#include "jaldb_utils.h"
#include "jaldb_config.h"
#include "jaldb_strings.h"
#include "jal_alloc.h"
#include "jal_ts_utils.h"
#include "jaldb_record_dbs.h"
#include "jal_socket.hpp"
#include "jal_seccomp_enforcer.h"

#define VERSION_CALLED 1

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

#define LOG_STR_FIELD(_s, _f) DEBUG_LOG(#_f": %s", _s->_f? _s->_f : "(nil)")
#define LOG_INT_FIELD(_s, _f) DEBUG_LOG(#_f": %d", _s->_f)
#define LOG_ARR_FIELD(_s, _f, _i, _c) DEBUG_LOG(#_f": %s", _i < _s->_c? _s->_f? _s->_f[_i] : "(nil)" : "(bad index)")

enum class FilterMessageType: uint16_t {
	StartStream = 0x01,
	StopStream = 0x02,
	RecordSuccess = 0x04,
	RecordError = 0x08,
};

struct peer_config_t {
	enum jaln_record_type pub_allow;
	enum jaln_record_type sub_allow;
};

struct StartStreamArgs {
	uint16_t subscriberToken;
	enum jaldb_rec_type type;
	enum jaln_publish_mode mode;
	char* resumeNonce = NULL;
};

struct StopStreamArgs {
	uint16_t subscriberToken;
	enum jaldb_rec_type type;
};

// Create a specialization of UDSSendMessage for the filter-stop message
struct JalFilterStopStream : public UDSSendMessage {
	JalFilterStopStream(const StopStreamArgs& args) {
		// MessageType
		FilterMessageType mType = FilterMessageType::StopStream;
		addFieldByCopy(&mType, sizeof(FilterMessageType));
		// Subscriber Id
		addFieldByCopy(&args.subscriberToken, sizeof(uint16_t));
		// Record Type
		addFieldByCopy(&args.type, sizeof(uint16_t));
	}
};

struct RecordResponseArgs {
	FilterMessageType mType;
	uint16_t subscriberToken;
	enum jaldb_rec_type type;
	const char *recordNonce = NULL;
};

// Create a specialization of UDSSendMessage for the filter-stop message
struct JalFilterRecordResponse : public UDSSendMessage {
	JalFilterRecordResponse(const RecordResponseArgs& args) {
		// MessageType
		FilterMessageType mType = args.mType;
		addFieldByCopy(&mType, sizeof(FilterMessageType));
		// Subscriber Id
		addFieldByCopy(&args.subscriberToken, sizeof(uint16_t));
		// Record Type
		addFieldByCopy(&args.type, sizeof(uint16_t));
		// record Nonce
		if(args.recordNonce && (strlen(args.recordNonce) > 0)) {
			uint16_t nonceLen = strlen(args.recordNonce);
			addFieldByCopy(&nonceLen, sizeof(uint16_t));
			addFieldByNonOwningPointer(args.recordNonce, nonceLen);
		} else {
			uint16_t nonceLen = 0;
			addFieldByCopy(&nonceLen, sizeof(uint16_t));
		}
	}
};

struct session_ctx_t {
	// The record in progress
	struct jaldb_record *rec = NULL;
	// Handle to the db instance
	jaldb_context_t *db_ctx = NULL;
	// Flag indicating this session has been closed in response
	// to a network trigger (on_channel_closed or an error during sending a record)
	bool channel_closed = false;
	// Number of records which have been sent but for which we have not received
	// a sync message in response
	int num_outstanding_syncs = 0;
	// Set in pub_on_journal_resume to indicate a resume has been started
	// Used to ensure we don't reject the session in the subsequent on_subscribe
	// callback
	bool is_resume = false;

	bool archive_mode = false;

	// For filter use only
	uint16_t subscriber_token = 0xFFFF;
	std::string hostname;
	pthread_mutex_t staging_data_lock;
	pthread_cond_t socket_thread_signal = PTHREAD_COND_INITIALIZER;
	pthread_cond_t get_next_signal = PTHREAD_COND_INITIALIZER;
	bool staged_data_occupied = false;
	char* nonce = NULL;
	char* timestamp = NULL;
	uint8_t* sys_meta_buf = NULL;
	uint64_t sys_meta_len = 0;
	uint8_t* app_meta_buf = NULL;
	uint64_t app_meta_len = 0;
	uint8_t* payload_buf = NULL;
	uint64_t payload_len = 0;
	int fd = -1;
	bool on_disk = false;
	bool shutting_down = false;
	// indicates that a resume is needed if not NULL
	char* resume_nonce = NULL;

	session_ctx_t(std::string hostname_param, uint16_t subscriber_token_param) {
		this->hostname = hostname_param;
		this->subscriber_token = subscriber_token_param;
		pthread_mutex_init(&staging_data_lock, NULL);
	}

	~session_ctx_t() {
		// acquire lock to make sure we're not interrupting one of our
		// other threads
		pthread_mutex_lock(&staging_data_lock);
		// Indicate that nothing is valid and we should shut down
		staged_data_occupied = false;
		shutting_down = true;
		// Allow the socket handler thread to close
		pthread_mutex_unlock(&staging_data_lock);
		pthread_cond_signal(&socket_thread_signal);
		// wait for the socket handler thread and consumer to be done
		pthread_mutex_lock(&staging_data_lock);
		// delete any mid-flight data
		free(nonce);
		free(timestamp);
		free(sys_meta_buf);
		free(app_meta_buf);
		free(payload_buf);
		free(resume_nonce);
		// pthreads cleanup
		pthread_cond_destroy(&socket_thread_signal);
		pthread_mutex_unlock(&staging_data_lock);
		pthread_mutex_destroy(&staging_data_lock);
	}
};

struct global_config_t {
	std::map<std::string, peer_config_t> peers;
	char *private_key = NULL;
	char *public_cert = NULL;
	char *remote_cert_dir = NULL;
	char *db_root = NULL;
	char *host = NULL;
	char *pid_file = NULL;
	char *log_dir = NULL;
	long long int port = 0;
	long long int poll_time = 0;
	char *digest_algorithms = NULL;
	char* database_option = NULL;
	jaldb_flags jdb_flags = JDB_NONE;
	int map_size = 0;
	char* filter_socket_basename = NULL;
} global_config;

struct global_args_t {
	int daemon;		/* --no_daemon option */
	bool debug_flag;	/* --debug option */
	char *config_path;	/* --config option */
	char *pid_path;		/* --pid option */
	bool enable_tls;	/* --disable_tls option */
	char *digest_algorithms;	/* --digest-algorithms option */
	bool use_filter;    /* --use_filter */
} global_args;

enum jald_status {
	JALD_E_CONFIG_LOAD = -1024,
	JALD_E_DB_INIT,
	JALD_E_NOMEM,
	JALD_OK = 0,
};

static jaln_context *jctx = NULL;

// A counter of threads which need to close before we shut down
static int threads_to_exit = 0;
// A mutex to ensure threads_to_exist remains coherent
static pthread_mutex_t exit_count_lock;

// short hand for long map type names
using SessionHostMap = std::map<std::string, std::shared_ptr<session_ctx_t>>;
using SessionTokenMap = std::map<uint16_t, std::shared_ptr<session_ctx_t>>;

//Map to store subscriber token per subscriber hostname key
std::map<std::string, uint16_t> subscriberTokenMap;
static uint16_t next_subscriber_token = 1;
std::mutex subscriberTokenMapMutex;

// Convenience struct for select_channel return value
struct SessionMaps {
	SessionHostMap& sessionHostMap;
	SessionTokenMap& sessionTokenMap;
	std::shared_ptr<pthread_mutex_t> mapLock;
};
// NOTE - these maps have program lifetime (static globals). They are accessed with
// unguarded .at() calls essentially everywhere, which will throw if the specified
// entry does not exist.
// The journal, audit, log entries are created immediately in main and should never
// be removed. Failure to adhere to this will cause program termination by exception.
//
// Set up a map of hostname string to session_ctx_t, store by shared_ptr so we can
// refer to this same session_ctx_t from our subscriber_token map safely
static std::map<enum jaln_record_type, SessionHostMap> sessionHostMaps;
// Set up a similar map to the matching lock
static std::map<enum jaln_record_type, std::shared_ptr<pthread_mutex_t>> mapLocks;
// When using the filter, we also need to map from subscriber tokens to sessions
static std::map<enum jaln_record_type, SessionTokenMap> sessionTokenMaps;


// When non-0, the CLI should clean up and exit
static int exiting = 0;
// Lock to serialize write access to the inline filter socket
static pthread_mutex_t request_socket_lock;
static UDSSendSocket requestSocket;
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

static void free_global_config(void);
static void free_global_args(void);
static void print_peer_cfg(void);
static void print_record_types(enum jaln_record_type rtype);
static void print_config(void);
static enum jald_status set_global_config(config_t *config);
static enum jald_status handle_allow_mask(config_setting_t *parent, config_setting_t *list, const char *cfg_key, enum jaln_record_type *mask);
static enum jal_status pub_get_bytes(const uint64_t offset, uint8_t * const buffer, uint64_t *size, void *feeder_data);
static jaldb_context_t* setup_db_layer(void);

// Throws if SessionMaps can't be constructed
static inline SessionMaps select_channel(const enum jaln_record_type type);

int journal_socket_fd;
int audit_socket_fd;
int log_socket_fd;

uint16_t getSubscriberToken(const std::string& hostname)
{
	std::lock_guard<std::mutex> lock(subscriberTokenMapMutex);  //Locks the mutex for the scope
	uint16_t currSubscriberToken = next_subscriber_token;

	//If hostname exist in map, then return corresponding subscriber token
	auto it = subscriberTokenMap.find(hostname);
	if (it != subscriberTokenMap.end())
	{
		return it->second;
	}
	else //If host name doesn't exist in map, add new entry and increment the subscriber token
	{
		subscriberTokenMap.insert({hostname, next_subscriber_token});
		next_subscriber_token ++;
	}

	return currSubscriberToken;
}

void removeSubscriberToken(const std::string& hostname)
{
	std::lock_guard<std::mutex> lock(subscriberTokenMapMutex);  //Locks the mutex for the scope
	subscriberTokenMap.erase(hostname);
}

struct ReceiveThreadArgs {
	// for error printing, connection selection, and sanity check of record type
	enum jaln_record_type record_type;
	// for creating the socket
	std::string socket_path;
};

struct RecvRecordMessage : public UDSRecvMessage {
	uint16_t recordType;
	uint16_t subscriberToken;
	uint64_t payloadLength;
	uint64_t appMetaLength;
	uint64_t sysMetaLength;
	bool payloadOnDisk;
	void* payloadData = NULL;
	void* appMeta = NULL;
	void* sysMeta = NULL;
	std::string nonce;
	std::string timestamp;
	// Note - fd is handled by the base class
	// Do not specify fd here

	int messageTypeId;
	int subscriberTokenId;
	int payloadLengthId;
	int appMetaLengthId;
	int sysMetaLengthId;
	int nonceLengthId;
	int timestampLengthId;
	int payloadOnDiskId;
	int payloadId;
	int break1Id;
	int appMetaId;
	int break2Id;
	int sysMetaId;
	int break3Id;
	int nonceId;
	int break4Id;
	int timestampId;
	int break5Id;

	RecvRecordMessage() {
		// Capture the "id" of each field as it is added so we know how to refer to them later
		messageTypeId = addField(sizeof(uint16_t));
		subscriberTokenId = addField(sizeof(uint16_t));
		payloadLengthId = addField(sizeof(uint64_t));
		appMetaLengthId = addField(sizeof(uint64_t));
		sysMetaLengthId = addField(sizeof(uint16_t));
		nonceLengthId = addField(sizeof(uint16_t));
		timestampLengthId = addField(sizeof(uint16_t));
		payloadOnDiskId = addField(sizeof(uint16_t));
		payloadId = addOptionalDependentField(payloadOnDiskId, 0, payloadLengthId);
		// NOTE - we do not send the NULL terminator with the BREAK strings
		// subtract one from the expected size
		break1Id = addOptionalField(payloadOnDiskId, 0, sizeof("BREAK")-1);
		appMetaId = addDependentField(appMetaLengthId);
		break2Id = addField(sizeof("BREAK")-1);
		sysMetaId = addDependentField(sysMetaLengthId);
		break3Id = addField(sizeof("BREAK")-1);
		nonceId = addDependentField(nonceLengthId);
		break4Id = addField(sizeof("BREAK")-1);
		timestampId = addDependentField(timestampLengthId);
		break5Id = addField(sizeof("BREAK")-1);
	}

	int process() {
		try {
			// Sanity check on the break fields first to help guard against data alignment errors
			//
			// The first BREAK is only present if payloadOnDisk is false so we'll parse that field
			// out early
			uint16_t onDisk = getField<uint16_t>(payloadOnDiskId);
			payloadOnDisk = (0 != onDisk ? true : false);

			if(!payloadOnDisk) {
				if(std::string("BREAK") != getString(break1Id, strlen("BREAK"))) {
					fprintf(stderr, "First BREAK segment does not contain BREAK\n");
					return -1;
				}
			}
			if(std::string("BREAK") != getString(break2Id, strlen("BREAK"))) {
				fprintf(stderr, "Second BREAK segment does not contain BREAK\n");
				return -1;
			}
			if(std::string("BREAK") != getString(break3Id, strlen("BREAK"))) {
				fprintf(stderr, "Third BREAK segment does not contain BREAK\n");
				return -1;
			}
			if(std::string("BREAK") != getString(break4Id, strlen("BREAK"))) {
				fprintf(stderr, "Fourth BREAK segment does not contain BREAK\n");
				return -1;
			}
			if(std::string("BREAK") != getString(break5Id, strlen("BREAK"))) {
				fprintf(stderr, "First BREAK segment does not contain BREAK\n");
				return -1;
			}

			// Extract the data from our fields into a more useable form
			// These functions provide length checks which will throw if there is an unexpected
			// length
			recordType = getField<uint16_t>(messageTypeId);
			subscriberToken = getField<uint16_t>(subscriberTokenId);
			payloadLength = getField<uint64_t>(payloadLengthId);
			appMetaLength = getField<uint64_t>(appMetaLengthId);
			sysMetaLength = getField<uint16_t>(sysMetaLengthId);
			uint16_t nonceLength = getField<uint16_t>(nonceLengthId);
			uint16_t timestampLength = getField<uint16_t>(timestampLengthId);
			if(!payloadOnDisk) {
				payloadData = stealBuffer(payloadId, payloadLength);
			} else {
				// fd is captured by the base class, we should just be able to use it
				if(0 > fd) {
					fprintf(stderr, "onDisk is true, but no fd was received from the filter\n");
					return -1;
				}
			}
			appMeta = stealBuffer(appMetaId, appMetaLength);
			sysMeta = stealBuffer(sysMetaId, sysMetaLength);
			nonce = getString(nonceId, nonceLength);
			timestamp = getString(timestampId, timestampLength);
		} catch (const std::exception &e) {
			fprintf(stderr, "ERROR: Encountered exception parsing record data: %s\n", e.what());
			return -1;
		}
		return 0;
	}
};

// Thread for listening on a record socket from the filter and dispatching
// records to the appropriate connection
void *record_receive_thread(void *paramArgs) {
	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit += 1;
	pthread_mutex_unlock(&exit_count_lock);

	// Ensure we decrement the active threads counter and signal for the program to shut down
	// regardless of how we exit this thread. This thread needs to live as long as jald
	struct SelfDestruct {
		~SelfDestruct(){
			pthread_mutex_lock(&exit_count_lock);
			threads_to_exit -= 1;
			exiting = 1;
			pthread_mutex_unlock(&exit_count_lock);
		}
	} sd;

	// We need args to live
	if(NULL == paramArgs) {
		fprintf(stderr,  "FATAL: Failed to create record receive thread.");
		return NULL;
	}
	ReceiveThreadArgs* args = (ReceiveThreadArgs*)paramArgs;

	// Get the session map and mutex lock for the type of channel we care about
	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(args->record_type);

	//sessionHostMap is not used in this method.
	(void)sessionHostMap;
	UDSRecvSocket recvSock(args->socket_path);

	// Wait until the filter connects
	int poll_status = -1;
	while(!exiting && -1 == poll_status) {
		fprintf(stderr, "Waiting for connection on socket: %s\n", args->socket_path.c_str());
		poll_status = recvSock.pollSocket();
		if(-1 == poll_status) {
			sleep(1);
		}
	}

	if(-1 != poll_status) {
		fprintf(stderr, "Connection accepted on socket: %s\n", args->socket_path.c_str());
	}

	while(!exiting) {
		RecvRecordMessage recordMessage;
		UDSRecvRV rv = recvSock.recvMsg(recordMessage);
		switch(rv.status) {
			case UDSRecvStatus::Success:
				try {
					recordMessage.process();
				} catch (std::exception &e) {
					fprintf(stderr, "Failed to process data received from socket. Shutting down.\n");
					exiting = 1;
					continue;
				}
				break;
			case UDSRecvStatus::Timeout:
				// No data received for 1 second, coming up for air. Continue
				continue;
			case UDSRecvStatus::LowLevelFailure:
				fprintf(stderr, "revcmsg returned error code: %d. Shutting down.\n",
					rv.lowLevelError);
				exiting = 1;
				continue;
			case UDSRecvStatus::SocketShutdown:
				fprintf(stderr, "Filter closed socket. Shutting down.\n");
				exiting = 1;
				continue;
			case UDSRecvStatus::LogicError:
				fprintf(stderr, "Logic Error receiving. Shutting down\n");
				exiting = 1;
				continue;
			case UDSRecvStatus::LengthMismatch:
				fprintf(stderr, "Other error receiving. Shutting down\n");
				exiting = 1;
				continue;
			default:
				fprintf(stderr, "Invalid status from receive call. Shutting down\n");
				exiting = 1;
				continue;
		}

		// Get the session corresponding to this type and the subscriber token from the filter
		std::shared_ptr<struct session_ctx_t> ctxPtr;
		try {
			pthread_mutex_lock(mapLock.get());
			ctxPtr = sessionTokenMap.at(recordMessage.subscriberToken);
			pthread_mutex_unlock(mapLock.get());
		} catch (std::out_of_range& e) {
			pthread_mutex_unlock(mapLock.get());
			// This subscriber token corresponds to a hostname for which we have no active session
			// Warn, but continue
			fprintf(stderr, "WARNING: Received a record for unregistered subscriber token: %d\n.",
				recordMessage.subscriberToken);

			// Generate a record failure for the nonce so the filter doesn't wait for a response for
			// that record
			RecordResponseArgs responseArgs;
			responseArgs.mType = FilterMessageType::RecordError;
			responseArgs.subscriberToken = recordMessage.subscriberToken;
			responseArgs.type = (enum jaldb_rec_type)recordMessage.recordType;
			responseArgs.recordNonce = recordMessage.nonce.data();

			// Create and send the message
			pthread_mutex_lock(&request_socket_lock);
			requestSocket.sendMsg(JalFilterRecordResponse(responseArgs));
			pthread_mutex_unlock(&request_socket_lock);
			continue;
		}


		// Wait for the session's "next" record to not be in use
		// We're keeping a handle to the ctx, which is slightly dangerous. Ensure that ~session_ctx_t()
		// waits for this thread to finish before releasing control
		pthread_mutex_lock(&(ctxPtr->staging_data_lock));

		// It is expected that this loop will only fire once.
		// If staged_data_occupied is false, there's room for us to place a record.
		// We already have the mutex, so immediately proceed.
		// If ctx->shutting_down is true, this session is being removed, cease operations
		// If staged_data_occupied is true, we drop into pthread_cond_wait until we
		// are signalled either by the consumer when it finishes with th record, or by
		// an invocation of shutdown()
		while(ctxPtr->staged_data_occupied && !ctxPtr->shutting_down) {
			pthread_cond_wait(&(ctxPtr->socket_thread_signal), &(ctxPtr->staging_data_lock));
		}

		// pthread_cond_wait acquires the mutex when it is signalled so we now own the lock
		// Be sure to release it before exiting or hitting the end of the loop

		if(ctxPtr->shutting_down) {
			// We don't have any state to worry about yet, the RecordMessage can clean itself up
			// Just release the lock and go back to the top of the loop
			pthread_mutex_unlock(&(ctxPtr->staging_data_lock));
			continue;
		}

		// It is the responsibility of the consumer to properly steal the memory from
		// the session_ctx_t before signalling stated_data_occuped = false
		// We'll defensively zero out our fields here, but these should always be no-ops
		free(ctxPtr->sys_meta_buf);
		ctxPtr->sys_meta_buf = NULL;
		ctxPtr->sys_meta_len = 0;

		free(ctxPtr->app_meta_buf);
		ctxPtr->app_meta_buf = NULL;
		ctxPtr->app_meta_len = 0;

		free(ctxPtr->payload_buf);
		ctxPtr->payload_buf = NULL;
		ctxPtr->payload_len = 0;

		free(ctxPtr->nonce);
		ctxPtr->nonce = NULL;

		free(ctxPtr->timestamp);
		ctxPtr->timestamp = NULL;

		ctxPtr->fd = -1;
		ctxPtr->on_disk = false;

		// Steal ownership of the system metadata buffer in recordMessage
		// and hand it to the session_ctx_t
		if(0 < recordMessage.sysMetaLength) {
			ctxPtr->sys_meta_buf = (uint8_t*)recordMessage.sysMeta;
			recordMessage.sysMeta = NULL;

			ctxPtr->sys_meta_len = recordMessage.sysMetaLength;
			recordMessage.sysMetaLength = 0;
		}

		// Steal ownership of the application metadata buffer in recordMessage
		// and hand it to the session_ctx_t
		if(0 < recordMessage.appMetaLength) {
			ctxPtr->app_meta_buf = (uint8_t*)recordMessage.appMeta;
			recordMessage.appMeta = NULL;

			ctxPtr->app_meta_len = recordMessage.appMetaLength;
			recordMessage.appMetaLength = 0;
		}

		// Steal ownership of the payload  buffer in recordMessage
		// and hand it to the session_ctx_t
		if(0 < recordMessage.payloadLength) {
			ctxPtr->payload_buf = (uint8_t*)recordMessage.payloadData;
			recordMessage.payloadData = NULL;

			ctxPtr->payload_len = recordMessage.payloadLength;
			recordMessage.payloadLength = 0;
		}

		if(recordMessage.payloadOnDisk) {
			ctxPtr->fd = recordMessage.fd;
		}

		if(!recordMessage.nonce.empty()) {
			ctxPtr->nonce = strdup(recordMessage.nonce.c_str());
			recordMessage.nonce = std::string();
		}

		if(!recordMessage.timestamp.empty()) {
			ctxPtr->timestamp = strdup(recordMessage.timestamp.c_str());
			recordMessage.timestamp = std::string();
		}

		if(recordMessage.payloadOnDisk) {
			ctxPtr->on_disk = true;
		}

		// Indicate that a record has been placed and is ready for use.
		ctxPtr->staged_data_occupied = true;
		// Release the mutex lock
		pthread_mutex_unlock(&(ctxPtr->staging_data_lock));
		// Wake the get_next_record_on_socket thread, if it happens to be waiting on data
		pthread_cond_signal(&(ctxPtr->get_next_signal));
	}
	fprintf(stderr, "Exiting thread with path: %s\n", args->socket_path.c_str());
	delete args;
	pthread_exit(NULL);
}

enum jaln_connect_error on_connect_request(
		const struct jaln_connect_request *req,
		__attribute__((unused)) int *selected_encoding,
		__attribute__((unused)) int *selected_digest,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("initialize received:");
	DEBUG_LOG("ack/nack response fields: ");
	LOG_STR_FIELD(req, hostname);
	LOG_STR_FIELD(req, addr);
	LOG_INT_FIELD(req, jaln_version);
	LOG_STR_FIELD(req, jaln_agent);
	LOG_INT_FIELD(req, mode);

	// If these fields are -1, then we are about to send a nack.
	// In that case, don't print anything for these as -1 is an invalid index.
	if (-1 != *selected_encoding) {
		LOG_ARR_FIELD(req, encodings, *selected_encoding, enc_cnt);
	}

	if (-1 != *selected_digest) {
		LOG_ARR_FIELD(req, digests, *selected_digest, dgst_cnt);
	}

	auto it = global_config.peers.find(std::string(req->hostname));
	if (global_config.peers.end() == it) {
		it = global_config.peers.find(std::string(req->addr));
	}
	if (global_config.peers.end() == it) {
		return JALN_CE_UNAUTHORIZED_MODE;
	}

	struct peer_config_t peer_cfg = it->second;

	if (req->role == JALN_ROLE_PUBLISHER) {
		// TODO: add support for jald to act as a subscriber.
		return JALN_CE_UNSUPPORTED_MODE;
	}
	enum jaln_record_type mask = (enum jaln_record_type)0;
	switch (req->role) {
	case JALN_ROLE_SUBSCRIBER:
		mask = peer_cfg.sub_allow;
		break;
	case JALN_ROLE_PUBLISHER:
		mask = peer_cfg.pub_allow;
		break;
	default:
		// Shouldn't happen.
		DEBUG_LOG("[%s] Invalid role in connection request?", req->ch_info->hostname);
	}
	if (mask & req->type) {
		return JALN_CE_ACCEPT;
	}
	return JALN_CE_UNAUTHORIZED_MODE;
}

void on_channel_close(
		const struct jaln_channel_info *ch_info,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Session is closing");

	//Ensure type is valid
	switch (ch_info->type) {
		case JALN_RTYPE_JOURNAL:
				break;
		case JALN_RTYPE_AUDIT:
				break;
		case JALN_RTYPE_LOG:
				break;
		default:
			DEBUG_LOG_SUB_SESSION(ch_info, "Illegal Record Type - no channel to close.");
			return;
	}

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(ch_info->type);
	std::shared_ptr<struct session_ctx_t> ctxPtr = nullptr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(ch_info->hostname);

		// Note that erasing the item from our maps doesn't actually destroy the session_ctx_t
		// until all shared_ptrs pointing to it go out of scope, so we can keep using ctxPtr
		sessionHostMap.erase(ctxPtr->hostname);
		sessionTokenMap.erase(ctxPtr->subscriber_token);
		// mapLock is per record type, not per session, so we don't remove that ever

		//Removes subscriber token for this connection from map, so that when this subscriber reconnects
		//a new subscriber token is generated.
		//NOTE: This will remove the token for all 3 record types when one record type disconnects.
		//Assumption is on_channel_close only occurs when the subscriber is closing, which will close all 3 channels.
		//The reference to the subscriber token still exists in sessionHostMap per channel until each channel is closed.
		removeSubscriberToken(ctxPtr->hostname);

		// (currently only used by the receive thread)
		// indicate that this session is closing
		ctxPtr->shutting_down = true;
		ctxPtr->channel_closed = true;
		// Destroy in progress record, if any
		if(ctxPtr->rec) {
			jaldb_destroy_record(&ctxPtr->rec);
		}

		// If we're using the db, close the handle
		if(!global_args.use_filter) {
			jaldb_context_destroy(&ctxPtr->db_ctx);
		}

		// If we're using the sockets, signal the pthread_cond associated with this thread so the
		// record_receive_thread will wake, just in case it's already blocked waiting on us
		else {
			pthread_cond_signal(&(ctxPtr->socket_thread_signal));
		}

		pthread_mutex_unlock(mapLock.get());

	} catch(std::out_of_range& e) {
		pthread_mutex_unlock(mapLock.get());
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: No context or DB context associated with closing channel");
	}
}

void on_connection_close(
		__attribute__((unused)) const struct jaln_connection *jal_conn,
		__attribute__((unused)) void *user_data)
{
	// don't need to to anything here.
}
void on_connect_ack(
		__attribute__((unused)) const struct jaln_connect_ack *ack,
		__attribute__((unused)) void *user_data)
{
	// Not applicable for our context since we only act as a listener, and
	// do not initiate any connections.
}

void on_connect_nack(
		__attribute__((unused)) const struct jaln_connect_nack *nack,
		__attribute__((unused)) void *user_data)
{
	// Not applicable for our context since we only act as a listener, and
	// do not initiate any connections.
}

// If a resume is requested, pub_on_journal_resume is called prior to (and in addition to)
// pub_on_subscribe. In this case, pub_on_journal_resume creates the session context and inserts
// it to the hash map. pub_on_subscribe detects this by finding ctx != NULL
// "offset" is unused here because it is set in session->pub_data->payload_off
// by the jaln_nextwork layer, and that value is used internally by jaln_send_payload_feeder anyway
enum jal_status pub_on_journal_resume(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		struct jaln_record_info *record_info,
		__attribute__((unused)) uint64_t offset,
		uint8_t **system_metadata_buffer,
		uint8_t **application_metadata_buffer,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Journal Resume");
	uint16_t nextSubcriberToken = getSubscriberToken(ch_info->hostname);
	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(JALN_RTYPE_JOURNAL);

	pthread_mutex_lock(mapLock.get());

	// A resume should create a new session context, ensure a session with this hostname does not
	// already exist
	if(0 != sessionHostMap.count(std::string(ch_info->hostname))) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Subscriber already exists");
		pthread_mutex_unlock(mapLock.get());
		return JAL_E_INVAL;
	}

	// The session does not already exist. Create it
	// This is a shared pointer to allow both maps to point at the same context safely and ensures
	// the context object can't be destroyed while in use, even if it is removed from the maps
	std::shared_ptr<struct session_ctx_t> ctxPtr = std::make_shared<struct session_ctx_t>(
		std::string(ch_info->hostname),
		nextSubcriberToken);

	// Insert this session by hostname and token to our maps
	sessionHostMap.insert({std::string(ch_info->hostname), ctxPtr});
	sessionTokenMap.insert({nextSubcriberToken, ctxPtr});
	pthread_mutex_unlock(mapLock.get());

	ctxPtr->rec = NULL;
	// When not using the filter, immediately retrieve the record identified by record_info->nonce
	// from the DB
	if (!global_args.use_filter){
		ctxPtr->db_ctx = setup_db_layer();
		if(NULL == ctxPtr->db_ctx) {
			return JAL_E_INVAL;
		}

		enum jaldb_status db_ret = JALDB_E_INVAL;

		db_ret = jaldb_get_record(ctxPtr->db_ctx, JALDB_RTYPE_JOURNAL, record_info->nonce, &(ctxPtr->rec));
		if (JALDB_OK != db_ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to retrieve journal from db");
			return JAL_E_INVAL;
		}

		*system_metadata_buffer = ctxPtr->rec->sys_meta->payload;
		if (ctxPtr->rec->app_meta) {
			*application_metadata_buffer = ctxPtr->rec->app_meta->payload;
		} else {
			*application_metadata_buffer = NULL;
		}
	}
	// When using the filter, store the nonce for later retrieval
	// sess->pub_data->payload_off is already set for later use
	else {
		ctxPtr->resume_nonce = strdup(record_info->nonce);

		//Sets journal resume to true
		ctxPtr->is_resume = true;
	}
	return JAL_OK;
}

enum jaldb_status pub_get_next_record_on_socket(jaln_session *sess,
			const struct jaln_channel_info *ch_info,
			char **nonce,
			char **timestamp,
			uint8_t **sys_meta_buf,
			uint64_t *sys_meta_len,
			uint8_t **app_meta_buf,
			uint64_t *app_meta_len,
			uint8_t **payload_buf,
			uint64_t *payload_len)
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

	// We have the lock and we have a record ready for us. Pass the data to our out-param
	// buffers.
	*nonce = ctxPtr->nonce;
	ctxPtr->nonce = NULL;

	// If we had a previous timestamp (live mode) free the old one first
	// In the non-filter case, this is done inside jaldb_next_chronological_record
	if(*timestamp) {
		free(*timestamp);
	}

	*timestamp = ctxPtr->timestamp;
	ctxPtr->timestamp = NULL;

	*sys_meta_len = ctxPtr->sys_meta_len;
	ctxPtr->sys_meta_len = 0;

	*sys_meta_buf = ctxPtr->sys_meta_buf;
	ctxPtr->sys_meta_buf = NULL;

	*app_meta_len = ctxPtr->app_meta_len;
	ctxPtr->app_meta_len = 0;

	*app_meta_buf = ctxPtr->app_meta_buf;
	ctxPtr->app_meta_buf = NULL;

	*payload_len = ctxPtr->payload_len;
	ctxPtr->payload_len = 0;

	*payload_buf = ctxPtr->payload_buf;
	ctxPtr->payload_buf = NULL;

	// TODO: I think the only piece of this that actually gets used is the fd
	// With some work, we can probably get rid of this bit
	// payload_len is unsigned and cannot be less than 0
	if (ctxPtr->on_disk && *payload_len > 0) {
		ctxPtr->rec = jaldb_create_record();
		struct jaldb_segment * seg = jaldb_create_segment();
		seg->length = *payload_len;
		seg->payload = *payload_buf;
		seg->fd = ctxPtr->fd;
		seg->on_disk = 1;

		ctxPtr->rec->payload = seg;
	}

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
			char **nonce,
			char **timestamp,
			uint8_t **sys_meta_buf,
			uint64_t *sys_meta_len,
			uint8_t **app_meta_buf,
			uint64_t *app_meta_len,
			uint8_t **payload_buf,
			uint64_t *payload_len,
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
		*nonce = jal_strdup(ctxPtr->rec->network_nonce);
		ret = JALDB_OK;
	} else {
		while (JALDB_E_NOT_FOUND == ret) {
			// Have to use timestamp since sess->mode is internal to the network library
			if (!*timestamp) {
				// Archive mode
				DEBUG_LOG_SUB_SESSION(ch_info, "Looking for a record in Archive Mode");
				ret = jaldb_next_unsynced_record(ctxPtr->db_ctx, db_type, nonce, &(ctxPtr->rec));
			} else {
				// Live mode
				DEBUG_LOG_SUB_SESSION(ch_info, "Looking for a record in Live Mode, timestamp: %s",*timestamp);
				ret = jaldb_next_chronological_record(ctxPtr->db_ctx,
								     db_type,
								     nonce,
								     &(ctxPtr->rec),
								     timestamp);
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

	*sys_meta_buf = NULL;
	*sys_meta_len = rec->sys_meta->length;
	if (rec->sys_meta->on_disk) {
		// TODO: Handle for on disk (once the LS is updated to support it). i.e. memmap the file or whatever
	} else {
		*sys_meta_buf = rec->sys_meta->payload;
	}

	*app_meta_buf = NULL;
	*app_meta_len = 0;
	if (rec->app_meta) {
		*app_meta_len = rec->app_meta->length;
		if (rec->app_meta->on_disk) {
			// TODO: Handle this for app meta
		} else {
			*app_meta_buf = rec->app_meta->payload;
		}
	}

	*payload_buf = NULL;
	*payload_len = 0;
	if (rec->payload) {
		*payload_len = rec->payload->length;
		if (rec->payload->on_disk) {
			ret = jaldb_open_segment_for_read(ctxPtr->db_ctx, rec->payload);
			if (JALDB_OK != ret) {
				ret = JALDB_E_INVAL;
				goto out;
			}
		} else {
			*payload_buf = rec->payload->payload;
		}
	}

	ret = JALDB_OK;
out:
	return ret;
}

// Create a specialization of UDSSendMessage for the filter-start message
struct JalFilterStartStream : public UDSSendMessage {
	JalFilterStartStream(const StartStreamArgs& args) {
		// MessageType
		FilterMessageType mType = FilterMessageType::StartStream;
		addFieldByCopy(&mType, sizeof(FilterMessageType));
		// Subscriber Id
		addFieldByCopy(&args.subscriberToken, sizeof(uint16_t));
		// Record Type
		addFieldByCopy(&args.type, sizeof(uint16_t));
		// Mode
		addFieldByCopy(&args.mode, sizeof(uint16_t));
		// journal resume request nonce
		if(args.resumeNonce) {
			uint16_t nonceLen = strlen(args.resumeNonce);
			addFieldByCopy(&nonceLen, sizeof(uint16_t));
			addFieldByNonOwningPointer(args.resumeNonce, nonceLen);
		} else {
			uint16_t nonceLen = 0;
			addFieldByCopy(&nonceLen, sizeof(uint16_t));
		}
	}
};

/*
 * Should support every record type in the future.
 * TODO: Convert log and audit record handling to feeders
 */
enum jal_status pub_send_records_feeder(
			jaln_session *sess,
			const struct jaln_channel_info *ch_info,
			char **timestamp,
			enum jal_status (*send)(jaln_session *, char *, uint8_t *,
						uint64_t, uint8_t *, uint64_t,
						uint64_t, struct jaln_payload_feeder *),
			uint16_t subscriber_token)
{
	enum jal_status ret = JAL_E_INVAL;
	enum jaldb_status db_ret = JALDB_E_INVAL;
	enum jaln_record_type type = ch_info->type;
	char *nonce = NULL;
	uint8_t *sys_meta_buf = NULL;
	uint64_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	uint64_t app_meta_len = 0;
	uint8_t *payload_buf = NULL;
	uint64_t payload_len = 0;
	struct jaln_payload_feeder feeder;

	enum jaldb_rec_type db_type;
	switch (type) {
	case JALN_RTYPE_JOURNAL:
		db_type = JALDB_RTYPE_JOURNAL;
		break;
	default:
		ret = jaln_finish(sess);
		return ret;
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

	feeder.feeder_data = ctxPtr.get();
	feeder.get_bytes = pub_get_bytes;

	do {
		// nonce will be a new copy that the caller must free
		// The buffers will point to the record stored within the session
		// The record is cleaned up by pub_on_record_complete
		if (global_args.use_filter){
			db_ret = pub_get_next_record_on_socket(sess,
						ch_info,
						&nonce,
						timestamp,
						&sys_meta_buf,
						&sys_meta_len,
						&app_meta_buf,
						&app_meta_len,
						&payload_buf,
						&payload_len);
		}
		else{
			db_ret = pub_get_next_record(sess,
					ch_info,
					&nonce,
					timestamp,
					&sys_meta_buf,
					&sys_meta_len,
					&app_meta_buf,
					&app_meta_len,
					&payload_buf,
					&payload_len,
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

		ret = send(sess, nonce, sys_meta_buf, sys_meta_len,
				app_meta_buf, app_meta_len, payload_len, &feeder);

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
			args.recordNonce = nonce;

			// Create and send the message
			pthread_mutex_lock(&request_socket_lock);
			requestSocket.sendMsg(JalFilterRecordResponse(args));
			pthread_mutex_unlock(&request_socket_lock);
		}

		free(nonce);
		nonce = NULL;
		if (global_args.use_filter){
			free(sys_meta_buf);
			free(app_meta_buf);
			free(payload_buf);
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
	free(nonce);
	return ret;
}



enum jal_status pub_send_records(
			jaln_session *sess,
			const struct jaln_channel_info *ch_info,
			char **timestamp,
			enum jal_status (*send)(jaln_session *, char *, uint8_t *,
						uint64_t, uint8_t *, uint64_t,
						uint8_t *, uint64_t),
			uint16_t subscriber_token)
{
	enum jal_status ret = JAL_E_INVAL;
	enum jaldb_status db_ret = JALDB_E_INVAL;
	enum jaln_record_type type = ch_info->type;
	char *nonce = NULL;
	uint8_t *sys_meta_buf = NULL;
	uint64_t sys_meta_len = 0;
	uint8_t *app_meta_buf = NULL;
	uint64_t app_meta_len = 0;
	uint8_t *payload_buf = NULL;
	uint64_t payload_len = 0;

	enum jaldb_rec_type db_type;
	switch (type) {
	case JALN_RTYPE_AUDIT:
		db_type = JALDB_RTYPE_AUDIT;
		break;
	case JALN_RTYPE_LOG:
		db_type = JALDB_RTYPE_LOG;
		break;
	default:
		return jaln_finish(sess);
	}

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);

	//sessionTokenMap is not used in this method.
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

	if (!global_args.use_filter){
		// If not using the filter, initialize the db handle
		ctxPtr->db_ctx = setup_db_layer();
		if(NULL == ctxPtr->db_ctx) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to setup db");
			ret = JAL_E_INVAL;
			goto out;
		}

		// If not using the filter, and in archive mode, clear sent flags
		DEBUG_LOG_SUB_SESSION(ch_info, "Verifying previously sent records.");
		// Only need to clear sent flags for archive mode connection
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
		StartStreamArgs args;
		args.subscriberToken = subscriber_token;
		args.type = db_type;
		if(*timestamp) {
			args.mode = JALN_LIVE_MODE;
		} else {
			args.mode = JALN_ARCHIVE_MODE;
		}
		// for non-journal records, we will never request a resume
		args.resumeNonce = NULL;
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
						ch_info,
						&nonce,
						timestamp,
						&sys_meta_buf,
						&sys_meta_len,
						&app_meta_buf,
						&app_meta_len,
						&payload_buf,
						&payload_len);
		}
		else{
			db_ret = pub_get_next_record(sess,
						ch_info,
						&nonce,
						timestamp,
						&sys_meta_buf,
						&sys_meta_len,
						&app_meta_buf,
						&app_meta_len,
						&payload_buf,
						&payload_len,
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

		ret = send(sess, nonce, sys_meta_buf, sys_meta_len,
				app_meta_buf, app_meta_len, payload_buf, payload_len);

		// If we're using the filter, we need to send RecordError if the send
		// failed for any reason
		// Note that this doesn't send record failure for digest challenge failures.
		// That's handled elsewhere, this is strictly for transport layer failures.
		if (global_args.use_filter && JAL_OK != ret){
			// Form up the message data
			RecordResponseArgs args;
			args.mType = FilterMessageType::RecordError;
			args.subscriberToken = subscriber_token;
			args.type = db_type;
			args.recordNonce = nonce;

			// Create and send the message
			pthread_mutex_lock(&request_socket_lock);
			requestSocket.sendMsg(JalFilterRecordResponse(args));
			pthread_mutex_unlock(&request_socket_lock);
		}

		free(nonce);
		nonce = NULL;
		if (global_args.use_filter){
			free(sys_meta_buf);
			free(app_meta_buf);
			free(payload_buf);
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
	free(nonce);
	return ret;
}

struct thread_data {
	jaln_session *sess;
	const struct jaln_channel_info *ch_info;
	char *timestamp;

	// This id is used only when running the inline-filter
	// A unique identifier to help the filter disambiguate commands
	// and which it will parrot back to help us disambiguate received records
	// TODO: It is extremely unlikely that a user will create/destroy sufficiently many
	// sessions that the uint16_t next_subscriber_token will roll over, but it might be worth
	// keeping a list of actives ids in the future
	uint16_t subscriber_token;
};

/*
 * Called in a thread to handle journal data publishing.  Allocates memory for return status.
 * Caller is responsible for freeing this memory
 */
__attribute__((noreturn))
void *pub_send_journal(__attribute__((unused)) void *args)
{
	enum jal_status *ret = (enum jal_status *) jal_malloc(sizeof(enum jal_status));
	*ret = JAL_E_INVAL;
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	const struct jaln_channel_info *ch_info = data->ch_info;

	char *journal_timestamp = NULL;

	if (data->timestamp) {
		journal_timestamp = jal_strdup(data->timestamp);
	}

	jaln_add_session_ref(sess);
	*ret = pub_send_records_feeder(sess, ch_info, &journal_timestamp, &jaln_send_journal, data->subscriber_token);
	jaln_remove_session_ref(sess);
	free(journal_timestamp);
	pthread_exit((void*)ret);
}

/*
* Called in a thread to handle audit data publishing.  Allocates memory for return status.
* Caller is reponsible for freeing this memory
*/
__attribute__((noreturn))
void *pub_send_audit(void *args)
{
	enum jal_status *ret = (enum jal_status *) jal_malloc(sizeof(enum jal_status));
	*ret = JAL_E_INVAL;
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	const struct jaln_channel_info *ch_info = data->ch_info;

	char *audit_timestamp = NULL;

	if (data->timestamp) {
		audit_timestamp = jal_strdup(data->timestamp);
	}

	jaln_add_session_ref(sess);
	*ret = pub_send_records(sess, ch_info, &audit_timestamp, &jaln_send_audit, data->subscriber_token);
	jaln_remove_session_ref(sess);
	free(audit_timestamp);
	pthread_exit((void*)ret);
}

/*
 * Called in a thread to handle log data publishing.  Allocates memory for return status.
 * Caller is reponsible for freeing this memory
 */
__attribute__((noreturn))
void *pub_send_log(void *args)
{
	enum jal_status *ret = (enum jal_status *) jal_malloc(sizeof(enum jal_status));
	*ret = JAL_E_INVAL;
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	const struct jaln_channel_info *ch_info = data->ch_info;

	char *log_timestamp = NULL;

	if (data->timestamp) {
		log_timestamp = jal_strdup(data->timestamp);
	}

	jaln_add_session_ref(sess);
	*ret = pub_send_records(sess, ch_info, &log_timestamp, &jaln_send_log, data->subscriber_token);
	jaln_remove_session_ref(sess);
	free(log_timestamp);
	pthread_exit((void*)ret);
}

// If a resume is requested, pub_on_journal_resume is called prior to (and in addition to)
// pub_on_subscribe. In this case, pub_on_journal_resume creates the session context and inserts
// it to the hash map. pub_on_subscribe detects this by finding ctxPtr != NULL
enum jal_status pub_on_subscribe(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info_param,
		enum jaln_record_type type,
		enum jaln_publish_mode mode,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	// Under some exit conditions (for instance if the subscriber and publisher
	// both receive a ctrl-C very close to the same time) the jaln_network
	// closes down very quickly and rips the ch_info data out from under us.
	// Save a copy and use that, using a C++ destructor to guarantee the
	// copy is freed
	// Also use this object to ensure we increment and decrement our thread count
	// no matter how we leave this function
	struct ChInfo {
		struct jaln_channel_info ch_info = {NULL, NULL, NULL, NULL, JALN_RTYPE_JOURNAL};
		ChInfo(const struct jaln_channel_info* param) {
			if(param->hostname) ch_info.hostname = strdup(param->hostname);
			if(param->addr) ch_info.addr = strdup(param->addr);
			if(param->encoding) ch_info.encoding = strdup(param->encoding);
			if(param->digest_method) ch_info.digest_method = strdup(param->digest_method);
			ch_info.type = param->type;

			pthread_mutex_lock(&exit_count_lock);
			threads_to_exit += 1;
			pthread_mutex_unlock(&exit_count_lock);
		}
		~ChInfo() {
			free(ch_info.hostname);
			free(ch_info.addr);
			free(ch_info.encoding);
			free(ch_info.digest_method);
			pthread_mutex_lock(&exit_count_lock);
			threads_to_exit -= 1;
			pthread_mutex_unlock(&exit_count_lock);
		}
	} ch_info_container(ch_info_param);
	const struct jaln_channel_info* ch_info = &(ch_info_container.ch_info);
	uint16_t nextSubcriberToken = getSubscriberToken(ch_info->hostname);
	// Get the appropriate hash/lock and ensure this subscription doesn't already exist
	// This can happen if the subscriber is restarted very quickly before we finish
	// tearing down this thread
	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);

	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	pthread_mutex_lock(mapLock.get());

	// In the case of a journal resume, the session will already exist
	std::shared_ptr<struct session_ctx_t> ctxPtr;
	if (0 == sessionHostMap.count(std::string(ch_info->hostname))) {

		DEBUG_LOG_SUB_SESSION(ch_info, "Inserting new session");

		// The session does not already exist. Create it
		// This is a shared pointer to allow both maps to point at the same context safely and ensures
		// the context object can't be destroyed while in use, even if it is removed from the maps
		ctxPtr = std::make_shared<struct session_ctx_t>(
			std::string(ch_info->hostname),
			nextSubcriberToken);

		if (!global_args.use_filter){
			ctxPtr->db_ctx = setup_db_layer();
			if(NULL == ctxPtr->db_ctx) {
				pthread_mutex_unlock(mapLock.get());
				return JAL_E_INVAL;
			}
		}

		// Insert this session by hostname and token to our maps
		fprintf(stderr, "DEBUG: inserting with hostname: %s, token: %d\n", ch_info->hostname, nextSubcriberToken);
		sessionHostMap.insert({std::string(ch_info->hostname), ctxPtr});
		sessionTokenMap.insert({nextSubcriberToken, ctxPtr});
	}
	else {
		// We just did a .count() with this value, so we know .at will not throw
		ctxPtr = sessionHostMap.at(ch_info->hostname);
		// If this is a resume, it is valid (and expected) for the session to already exist
		// in our hash map
		if(!ctxPtr->is_resume) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: Subscription to host: %s already in use", ch_info->hostname);
			pthread_mutex_unlock(mapLock.get());
			return JAL_E_INVAL;
		}
	}


	// Once we have handled the resume once, we don't want to allow any additional sessions
	// of this type to this host, so mark is_resume false
	// Waiting to unlock the mapLock until we've set this final bit of state that will
	// prevent duplicate sessions from being created
	ctxPtr->is_resume = false;

	pthread_mutex_unlock(mapLock.get());

	struct thread_data data;
	data.sess = sess;
	data.ch_info = ch_info;
	data.timestamp = NULL;
	// Unused when not using the filter
	data.subscriber_token = nextSubcriberToken;

	if (JALN_LIVE_MODE == mode) {
		data.timestamp = jal_gen_timestamp_usec();
		if (!data.timestamp) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Error: Error generating timestamp");
			return JAL_E_INVAL_TIMESTAMP;
		}
	} else if (JALN_ARCHIVE_MODE != mode) {
		// Bad mode
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: Bad mode");
		return JAL_E_INVAL;
	}

	// Select send function to execute based on record type
	void*(*send_func_ptr)(void*) = NULL;

	switch (type) {
		case JALN_RTYPE_JOURNAL:
			send_func_ptr = pub_send_journal;
				break;
		case JALN_RTYPE_AUDIT:
				send_func_ptr = pub_send_audit;
				break;
		case JALN_RTYPE_LOG:
				send_func_ptr = pub_send_log;
				break;
		default:
			DEBUG_LOG_SUB_SESSION(ch_info, "Illegal Record Type");
			return JAL_E_INVAL;
	}

	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	pthread_t thread;
	int create_status = pthread_create(&thread, &attr, send_func_ptr, &data);
	pthread_attr_destroy(&attr);

	if(0 != create_status) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
		return JAL_E_INVAL;
	}

	void* thread_status = NULL;

	// Wait for thread to terminate
	int join_status = pthread_join(thread, &thread_status);
	if (join_status) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: return code from pthread_join() is %d\n",
			join_status);
		free(thread_status);
		return JAL_E_INVAL;
	}

	// Once every second until either the session vanishes (shouldn't be possible)
	// or the channel_closed value is set, refresh our handle to the session ctx
	// and check again
	while(true) {

		// If the session handle has gone bad, fail out, there's nothing more we can do
		if(!ctxPtr || (!global_args.use_filter && !ctxPtr->db_ctx)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "No context or DB context associated with closing channel");
			return JAL_E_INVAL;
		}
		// If the session has closed by the remote host break out of the loop and move on
		// We will receive no more incoming messages
		else if(ctxPtr->channel_closed) {
			break;
		}
		// If we're closing from our side, wait for up to 5 seconds to collect any outstanding
		// record responses
		else if(exiting) {
			const int SLEEP_MAX = 5;
			for(int i = 0; i < SLEEP_MAX; i++) {
				if(ctxPtr->num_outstanding_syncs > 0) {
					DEBUG_LOG_SUB_SESSION(ch_info, "Waiting for channel to quiesce: %d.", i);
					sleep(1);
				} else {
					break;
				}
			}

			if(ctxPtr->num_outstanding_syncs > 0 ) {
				// After 5 seconds, break out even if we didn't get all the syncs we expected,
				// but display a warning
				DEBUG_LOG_SUB_SESSION(ch_info,
					"Didn't receive all expected syncs. Num oustanding: %d.",
					ctxPtr->num_outstanding_syncs);
			}
			break;
		}
		// Otherwise wait 1 second
		else {
			sleep(1);
		}
	}

	if(!global_args.use_filter) {
		jaldb_context_destroy(&ctxPtr->db_ctx);
	}

	enum jal_status ret = *((enum jal_status *) thread_status);
	free(thread_status);
	if (JAL_OK != ret && JAL_E_NOT_CONNECTED != ret) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed while sending records to subscriber");
	}

	return ret;
}

enum jal_status pub_on_record_complete(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		char *nonce,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "On record complete: %s", nonce);

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);

	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		pthread_mutex_unlock(mapLock.get());
		return JAL_E_INVAL;
	}

	if (ctxPtr->archive_mode && !global_args.use_filter) {

		pthread_mutex_lock(mapLock.get());
		enum jaldb_status jaldb_ret = jaldb_mark_sent(ctxPtr->db_ctx, ctxPtr->rec->type, nonce, 1);
		pthread_mutex_unlock(mapLock.get());

		if (JALDB_OK != jaldb_ret) {
			fprintf(stderr, "Failed to mark %s as sent: %d", nonce, jaldb_ret);
			return JAL_E_INVAL;
		} else {
			DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as sent", nonce);
		}
	}

	jaldb_destroy_record(&ctxPtr->rec);
	ctxPtr->num_outstanding_syncs++;
	return JAL_OK;
}

void pub_sync(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		enum jaln_publish_mode mode,
		const char *nonce,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "sync: %s", nonce);

	enum jaldb_status jaldb_ret = JALDB_E_INVAL;
	enum jaldb_rec_type db_type = JALDB_RTYPE_UNKNOWN;

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);
	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		pthread_mutex_unlock(mapLock.get());
		return;
	}

	switch(type) {
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
		// shouldn't happen.
		return;
	}

	// If using the filter, signal the filter that the record was handled completely
	// with success.
	if (global_args.use_filter){
		RecordResponseArgs args;
		args.mType = FilterMessageType::RecordSuccess;
		args.subscriberToken = ctxPtr->subscriber_token;
		args.type = db_type;
		args.recordNonce = nonce;

		// Create and send the message
		pthread_mutex_lock(&request_socket_lock);
		requestSocket.sendMsg(JalFilterRecordResponse(args));
		pthread_mutex_unlock(&request_socket_lock);
	}
	else {
		// Only sync the record in the DB in archive mode with digest challenges
		if (mode == JALN_ARCHIVE_MODE) {
			pthread_mutex_lock(mapLock.get());
			jaldb_ret = jaldb_mark_synced(ctxPtr->db_ctx, db_type, nonce);
			pthread_mutex_unlock(mapLock.get());

			if (JALDB_OK != jaldb_ret) {
				DEBUG_LOG_SUB_SESSION(ch_info, "Failed to mark %s as synced: %d", nonce, jaldb_ret);
			} else {
				DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as synced", nonce);
			}
		}

	}

	if(ctxPtr->num_outstanding_syncs > 0) {
		ctxPtr->num_outstanding_syncs--;
	} else {
		DEBUG_LOG_SUB_SESSION(ch_info, "Unexpected sync with ID: %s", nonce);
	}
}

void pub_notify_digest(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		const char *nonce,
		const uint8_t *digest,
		const uint32_t size,
		__attribute__((unused)) void *user_data)
{
	char *b64 = jal_base64_enc(digest, size);
	DEBUG_LOG_SUB_SESSION(ch_info, "Digest for %s: %s", nonce, b64);
	free(b64);
}

void pub_peer_digest(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *nonce,
		const uint8_t *local_digest,
		const uint32_t local_size,
		const uint8_t *peer_digest,
		const uint32_t peer_size,
		__attribute__((unused)) void *user_data)
{
	enum jaldb_rec_type db_type = JALDB_RTYPE_UNKNOWN;
	enum jaldb_status db_ret = JALDB_E_INVAL;

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
		// shouldn't happen.
		db_type = JALDB_RTYPE_UNKNOWN;
		return;
	}

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);
	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		pthread_mutex_unlock(mapLock.get());
		return;
	}

	// Check for error conditions
	if (!local_digest || !peer_digest) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Error: Missing peer or local digest.");
		goto error;
	}
	if ((0 == local_size) || (0 == peer_size) || (local_size != peer_size)) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Error: Digests have different lengths for %s. Local[%u] Peer[%u]", nonce, local_size, peer_size);
		goto error;
	}
	if (0 != memcmp(local_digest, peer_digest, local_size)) {
		char *local_b64 = jal_base64_enc(local_digest, local_size);
		char *peer_b64 = jal_base64_enc(peer_digest, peer_size);
		DEBUG_LOG_SUB_SESSION(ch_info, "Error: Digests do not match for %s. Local[%s] Peer[%s]",nonce, local_b64, peer_b64);
		free(local_b64);
		free(peer_b64);
		goto error;
	}
	// Digest match
	DEBUG_LOG_SUB_SESSION(ch_info, "Digest match for %s", nonce);
	goto out;

error:
	// The digests do not match. We need to mark the record as unsent so it can be sent again by the publisher.
	if(ctxPtr)
	{
		if (global_args.use_filter){
			RecordResponseArgs args;
			args.mType = FilterMessageType::RecordError;
			args.subscriberToken = ctxPtr->subscriber_token;
			args.type = db_type;
			args.recordNonce = nonce;

			// Create and send the message
			pthread_mutex_lock(&request_socket_lock);
			requestSocket.sendMsg(JalFilterRecordResponse(args));
			pthread_mutex_unlock(&request_socket_lock);
			db_ret = JALDB_OK;
		}
		else
		{
			db_ret = jaldb_mark_sent(ctxPtr->db_ctx, db_type, nonce, 0);
		}
	}

	if (JALDB_OK != db_ret) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Error: Failed to update record as unsent %s. Return code: %d", nonce, db_ret);
		goto out;
	} else {
		DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as unsent", nonce);
	}

out:
	return;
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
	config_t config;
	std::stringstream ss(std::ios_base::out);
	struct jal_seccomp_enforcer_t* seccomp_enforcer = NULL;

	enum jal_digest_algorithm *digest_list = (enum jal_digest_algorithm *) jal_malloc(sizeof(enum jal_digest_algorithm));
	size_t num_digests = 0;

	rc = jal_config_init(&config);

	if (JAL_CFG_SUCCESS != rc) {
		fprintf(stderr, "Error initializing config file");
		goto out;
	}

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

	rc = jal_config_read_file(&config, global_args.config_path);
	if (rc != JALD_OK) {
		goto out;
	}

	rc = set_global_config(&config);
	if (rc != JALD_OK) {
		goto out;
	}

	print_config();

	if (global_args.daemon) {
		DEBUG_LOG("Handing off process to daemon");
		DEBUG_LOG("For additional logs, set log_dir in config file and refer to <log_dir>/std*");
		if(0 != jalu_daemonize(global_config.log_dir, global_config.pid_file)) {
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

	if (JAL_OK != jal_get_digest_algorithm_list(global_config.digest_algorithms, global_args.digest_algorithms, &digest_list, &num_digests)) {
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
		jaln_ret = jaln_register_tls(jctx, global_config.private_key, global_config.public_cert,
				global_config.remote_cert_dir);
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
					std::string(global_config.filter_socket_basename) + "_J"
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
					std::string(global_config.filter_socket_basename) + "_A"
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
					std::string(global_config.filter_socket_basename) + "_L"
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
		if(NULL == global_config.filter_socket_basename) {
			DEBUG_LOG("filter_socket_basename required when running with use_filter flag");
			rc = -1;
			goto out;
		}
		std::string requestSocketPath = std::string(global_config.filter_socket_basename);
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

	jaln_ret = jaln_listen(jctx, global_config.host, ss.str().c_str(), NULL);
	if (JAL_OK != jaln_ret) {
		DEBUG_LOG("Failed to start listening");
		rc = -1;
		goto out;
	}

	if(global_args.debug_flag){
		int fd2;
		fd2 = open("SECCOMP_PROCESS_IS_DONE_SETTING_UP", 0, 0600);
		if (fd2>0){
			close(fd2);
		}
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
	free_global_config();
	free_global_args();
	pthread_mutex_destroy(&request_socket_lock);
	pthread_mutex_destroy(&exit_count_lock);
	jaln_publisher_callbacks_destroy(&pub_cbs);
	config_destroy(&config);
	free(digest_list);
	jal_seccomp_enforcer_destroy(&seccomp_enforcer);
	free((char*)argp_program_version);
	jaln_context_destroy(&jctx);
	return rc;

version_out:
	config_destroy(&config);
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

void free_global_config(void)
{
	free(global_config.private_key);
	free(global_config.public_cert);
	free(global_config.remote_cert_dir);
	free(global_config.db_root);
	free(global_config.host);
	free(global_config.pid_file);
	free(global_config.log_dir);
	free(global_config.digest_algorithms);
	free(global_config.database_option);
	free(global_config.filter_socket_basename);
}

void print_record_types(enum jaln_record_type rtype)
{
	const char *str;
	if (rtype & JALN_RTYPE_JOURNAL) {
		str = "journal";
	} else {
		str = "";
	}
	printf("%8s", str);
	if (rtype & JALN_RTYPE_AUDIT) {
		str = "audit";
	} else {
		str = "";
	}
	printf("%6s", str);
	if (rtype & JALN_RTYPE_LOG) {
		str = "log";
	} else {
		str = "";
	}
	printf("%4s", str);
}

void print_peer_cfg()
{
	for (std::map<std::string, peer_config_t>::iterator it = global_config.peers.begin(); it != global_config.peers.end(); ++it)
	{
		char *host = (char*)it->first.c_str();
		struct peer_config_t peer_cfg = it->second;
		printf("\n%15s | ", host);
		print_record_types(peer_cfg.pub_allow);
		printf(" | ");
		print_record_types(peer_cfg.sub_allow);
	}
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
		printf("REMOTE CERT DIR:\t\t%s\n", global_config.remote_cert_dir);
	} else {
		printf("!!!!!!!! TLS DISABLED !!!!!!!!\n");
	}
	printf("PORT:\t\t\t%lld\n", global_config.port);
	printf("HOST:\t\t\t%s\n", global_config.host);
	printf("POLL TIME:\t%lld\n", global_config.poll_time);
	printf("DB ROOT:\t\t%s\n", global_config.db_root);
	if (global_config.pid_file) {
		printf("PID FILE:\t\t%s\n", global_config.pid_file);
	}
	if (global_config.log_dir) {
		printf("LOG DIRECTORY:\t\t%s\n", global_config.log_dir);
	}
	if (global_config.digest_algorithms) {
		printf("DIGEST ALGORITHMS:\t%s\n", global_config.digest_algorithms);
	}

	if (global_args.use_filter || global_args.use_filter) {
		printf("FILTER SOCKET:\t\t%s\n", global_config.filter_socket_basename);
	}

	if(global_config.database_option) {
		printf("DATABASE_OPTION:\t%s\n", global_config.database_option);
	}
	printf("LMDB_MAP_SIZE (GB):\t%d\n", global_config.map_size);
	printf("PEERS\n%15s | %18s | %18s\n", "HOST", "PUBLISH_ALLOW", "SUBSCRIBE_ALLOW");
	print_peer_cfg();
	printf("\n===\nEND CONFIG VALUES:\n===\n");
}

std::string get_ipv4(std::string hostname){
	std::string result = "";
	struct addrinfo hints = {};
	struct addrinfo* results = NULL;
	struct sockaddr_in addr = {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = 0;
	hints.ai_protocol = 0;
	int ret = getaddrinfo(hostname.c_str(), NULL, &hints, &results);
	if (ret==0 ){
		if (results->ai_addrlen <= sizeof(addr)){
			memcpy(&addr, results->ai_addr, results->ai_addrlen);
			result = std::string(inet_ntoa(addr.sin_addr));
		}
	}
	if (results){
		freeaddrinfo(results);
	}
	return result;
}
enum jald_status set_global_config(config_t *config)
{
	int rc;

	if (!config) {
		return JALD_E_CONFIG_LOAD;
	}
	config_setting_t *root = config_root_setting(config);
	int error_seen = JAL_CFG_SUCCESS;

	if (global_args.enable_tls) {
		error_seen |= jal_config_lookup_string(root, JALNS_PRIVATE_KEY, &global_config.private_key, JAL_CFG_REQUIRED);
		char *expanded_priv_key_path = jal_expand_path(global_config.private_key, JALNS_PRIVATE_KEY);
		if (expanded_priv_key_path != NULL) {
			free(global_config.private_key);
			global_config.private_key = expanded_priv_key_path;
		}
		else {
			error_seen |= JAL_CFG_FAILURE;
		}

		error_seen |= jal_config_lookup_string(root, JALNS_PUBLIC_CERT, &global_config.public_cert, JAL_CFG_REQUIRED);
		char *expanded_pub_key_path = jal_expand_path(global_config.public_cert, JALNS_PUBLIC_CERT);
		if (expanded_pub_key_path != NULL) {
			free(global_config.public_cert);
			global_config.public_cert = expanded_pub_key_path;
		}
		else {
			error_seen |= JAL_CFG_FAILURE;
		}

		error_seen |= jal_config_lookup_string(root, JALNS_REMOTE_CERT_DIR, &global_config.remote_cert_dir, JAL_CFG_REQUIRED);
		char *expanded_remote_cert_path = jal_expand_path(global_config.remote_cert_dir, JALNS_REMOTE_CERT_DIR);
		if (expanded_remote_cert_path != NULL) {
			free(global_config.remote_cert_dir);
			global_config.remote_cert_dir = expanded_remote_cert_path;
		}
		else {
			error_seen |= JAL_CFG_FAILURE;
		}
	}

	rc = jal_config_lookup_string(root, JALNS_DB_ROOT, &global_config.db_root, JAL_CFG_OPTIONAL);
	if (JAL_CFG_SUCCESS == rc) {
		char *expanded_db_root_path = jal_expand_path(global_config.db_root, JALNS_DB_ROOT);
		if (expanded_db_root_path != NULL) {
			free(global_config.db_root);
			global_config.db_root = expanded_db_root_path;
		}
		else {
			error_seen |= JAL_CFG_FAILURE;
		}
	}

	error_seen |= jal_config_lookup_int64(root, JALNS_PORT, &global_config.port, JAL_CFG_REQUIRED);
	error_seen |= jal_config_lookup_string(root, JALNS_HOST, &global_config.host, JAL_CFG_REQUIRED);
	error_seen |= jal_config_lookup_int64(root, JALNS_POLL_TIME, &global_config.poll_time, JAL_CFG_OPTIONAL);

	if (global_config.poll_time <= 0) {
		CONFIG_ERROR(root, JALNS_POLL_TIME, "expected positive integer value");
	}


	error_seen |= jal_config_lookup_string(root, JALNS_PID_FILE, &global_config.pid_file, JAL_CFG_OPTIONAL);

	//Since pid_file is optional, ensure not null before processing
	if (global_config.pid_file != NULL)
	{
		char *expanded_pid_file_path = jal_expand_home_dir(global_config.pid_file, JALNS_PID_FILE);
		if (expanded_pid_file_path != NULL)
		{
			free(global_config.pid_file);
			global_config.pid_file = expanded_pid_file_path;
		}
		else {
			error_seen |= JAL_CFG_FAILURE;
		}
	}

	error_seen |= jal_config_lookup_string(root, JALNS_LOG_DIR, &global_config.log_dir, JAL_CFG_OPTIONAL);

	//Since log_file is optional, ensure not null before processing
	if (global_config.log_dir != NULL)
	{
		char *expanded_log_file_path = jal_expand_path(global_config.log_dir, JALNS_LOG_DIR);
		if (expanded_log_file_path != NULL)
		{
			free(global_config.log_dir);
			global_config.log_dir = expanded_log_file_path;
		}
		else {
			error_seen |= JAL_CFG_FAILURE;
		}
	}


	if(global_args.use_filter){

		if(JAL_CFG_SUCCESS != jal_config_lookup_string(
			root,
			JALNS_FILTER_SOCKET_BASENAME,
			&global_config.filter_socket_basename,
			JAL_CFG_REQUIRED)) {
				// Error printed internally
				return JALD_E_CONFIG_LOAD;
		}
	}

	//Attempts to load optional LMDB_CONFIG file in db_root
	//If present, this will override the lmdb performance level
	//and lmdb map size, otherwise default values will be used.
	jaldb_config *jdb_config = NULL;
	enum jaldb_config_status jcs = get_jaldb_config(global_config.db_root, &jdb_config);
	if (jcs != JALDB_CONFIG_OK && jcs != JALDB_CONFIG_E_NOTFOUND) {
		return JALD_E_CONFIG_LOAD;
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
		free_jaldb_config(&jdb_config);
	}

	error_seen |= jal_config_lookup_string(root, JALNS_DIGEST_ALGORITHMS, &global_config.digest_algorithms, JAL_CFG_OPTIONAL);

	config_setting_t *peers;
	int peer_len;
	error_seen |= jal_config_lookup_list(root, JALNS_PEERS, &peers, &peer_len, JAL_CFG_REQUIRED);

	for (unsigned i = 0; i < (unsigned) peer_len; i++) {
		enum jaln_record_type sub_mask = (enum jaln_record_type) 0;
		enum jaln_record_type pub_mask = (enum jaln_record_type) 0;
		config_setting_t *a_peer = NULL;
		rc = jal_config_get_elem_group(peers, i, &a_peer, JALNS_PEERS);

		if (JAL_CFG_SUCCESS != rc) {
			error_seen |= JAL_CFG_FAILURE;
			break;
		}

		config_setting_t *list = NULL;
		error_seen |= jal_config_get_member(a_peer, JALNS_PUBLISH_ALLOW, &list, JAL_CFG_OPTIONAL);
		if (JALD_E_CONFIG_LOAD == handle_allow_mask(a_peer, list, JALNS_PUBLISH_ALLOW, &pub_mask)) {
			return JALD_E_CONFIG_LOAD;
		}

		list = NULL;
		error_seen |= jal_config_get_member(a_peer, JALNS_SUBSCRIBE_ALLOW, &list, JAL_CFG_OPTIONAL);
		if (JALD_E_CONFIG_LOAD == handle_allow_mask(a_peer, list, JALNS_SUBSCRIBE_ALLOW, &sub_mask)) {
			return JALD_E_CONFIG_LOAD;
		}

		list = NULL;
		int host_len;
		error_seen |= jal_config_lookup_list(a_peer, JALNS_HOSTS, &list, &host_len, JAL_CFG_REQUIRED);

		for (unsigned host_idx = 0; host_idx < (unsigned) host_len; host_idx++) {
			char *key = NULL;
			rc = jal_config_get_elem_string(list, host_idx, &key, JALNS_HOSTS);

			if (JAL_CFG_SUCCESS != rc) {
				error_seen |= JAL_CFG_FAILURE;
				continue;
			}

			std::string check_key = get_ipv4(key);
			if (check_key.empty()){
				printf("Unable to resolve host entry: %s \n", key);
				error_seen |= JAL_CFG_FAILURE;
				continue;
			}
			else{
				key = strcpy(key, check_key.c_str());
			}

			if (!key) {
				rc |= JAL_CFG_FAILURE;
				continue;
			}

			std::string keystr = std::string(key);
			auto it = global_config.peers.find(keystr);

			if (global_config.peers.end() == it) {
				printf("cfg for %s, creating struct\n", key);
				struct peer_config_t peer_cfg;

				peer_cfg.pub_allow = (enum jaln_record_type) (peer_cfg.pub_allow | pub_mask);
				peer_cfg.sub_allow = (enum jaln_record_type) (peer_cfg.sub_allow | sub_mask);

				DEBUG_LOG("cfg for %s, adding %d for pub and %d for sub\n", key, pub_mask, sub_mask);
				DEBUG_LOG("cfg for %s, was %d for pub and %d for sub\n", key, peer_cfg.pub_allow, peer_cfg.sub_allow);

				global_config.peers.insert({keystr, peer_cfg});
				free(key);
			} else {
				error_seen |= JAL_CFG_FAILURE;
				printf("Duplicate host found in peers: %s\n", key);
				free(key);
			}
		}
	}

	if (JAL_CFG_SUCCESS == error_seen) {
		return JALD_OK;
	}

	return JALD_E_CONFIG_LOAD;
}

enum jald_status handle_allow_mask(config_setting_t *parent, config_setting_t *list, const char *cfg_key, enum jaln_record_type *mask) {
	// the allow masks are both optional, so just return OK.
	if (!list) {
		return JALD_OK;
	}
	if (!config_setting_is_list(list)) {
		CONFIG_ERROR(parent, cfg_key, "expected non-empty list");
		return JALD_E_CONFIG_LOAD;
	}
	if (!mask) {
		// this function is internal, so this should never happen.
		return JALD_E_CONFIG_LOAD;
	}

	int rc = JAL_CFG_SUCCESS;
	int len = config_setting_length(list);
	for (unsigned i = 0; i < (unsigned) len; i++) {
		char *type = NULL;
		rc |= jal_config_get_elem_string(list, i, &type, "");
		if (0 == strcmp(type, JALNS_JOURNAL)) {
			*mask = (jaln_record_type) (*mask | JALN_RTYPE_JOURNAL);
		} else if (0 == strcmp(type, JALNS_AUDIT)) {
			*mask = (jaln_record_type) (*mask | JALN_RTYPE_AUDIT);
		} else if (0 == strcmp(type, JALNS_LOG)) {
			*mask = (jaln_record_type) (*mask | JALN_RTYPE_LOG);
		} else {
			CONFIG_ERROR(list, cfg_key, "expected one of {'%s', '%s', '%s'}", JALNS_JOURNAL, JALNS_AUDIT, JALNS_LOG);
			return JALD_E_CONFIG_LOAD;
		}

		free(type);
	}
	return JALD_OK;
}

jaldb_context_t* setup_db_layer(void)
{
	enum jaldb_status jaldb_ret = JALDB_OK;
	jaldb_context_t* db_ctx = jaldb_context_create();

	jaldb_ret = jaldb_context_init(db_ctx, global_config.db_root, global_config.jdb_flags, global_config.map_size);

	if (JALDB_OK != jaldb_ret) {
		jaldb_context_destroy(&db_ctx);
	}
	return db_ctx;
}

static enum jal_status pub_get_bytes(const uint64_t offset, uint8_t * const buffer, uint64_t *size, void *feeder_data)
{
	// TODO: this may need to support reading from buffers stored in RAM,
	// rather than disk.
#define ERRNO_STR_LEN 128
	off64_t err;
	struct session_ctx_t *ctx = (struct session_ctx_t*) feeder_data;
	errno = 0;
	err = lseek64(ctx->rec->payload->fd, offset, SEEK_SET);
	int my_errno = errno;
	if (-1 == err) {
		char buf[ERRNO_STR_LEN];
		DEBUG_LOG("Failed to seek, errno %s\n", strerror_r(my_errno, buf, ERRNO_STR_LEN));
		return JAL_E_INVAL;
	}
	size_t to_read = *size;
	ssize_t bytes_read = read(ctx->rec->payload->fd, buffer, to_read);
	if (bytes_read < 0) {
		return JAL_E_INVAL;
	}
	*size = bytes_read;
	return JAL_OK;
}

static inline SessionMaps select_channel(const enum jaln_record_type type)
{
	// Halt loudly if type isn't a valid record type
	// This should be guaranteed when jaln_network creates the session->ch_info.
	// If this doesn't hold true there is an underlying logic error we don't want to miss
	if(type != JALN_RTYPE_JOURNAL && type != JALN_RTYPE_AUDIT && type != JALN_RTYPE_LOG) {
		std::string msg = "FATAL: Invalid record type passed to select_channel";
		throw std::runtime_error(msg);
	}

	return SessionMaps {
		sessionHostMaps.at(type),
		sessionTokenMaps.at(type),
		mapLocks.at(type)
	};
}
