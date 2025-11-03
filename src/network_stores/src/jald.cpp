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

#include "jal_base64_internal.h"
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
#include "jal_ts_utils.h"
#include "jaldb_record_dbs.h"
#include "jal_socket.hpp"
#include <jalop/jal_seccomp_enforcer.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <thread>

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

struct peer_config_t {
	char *host;
	long long int port;
	char *cert_dir;
	char *dc_config[2];
	enum jaln_record_type record_types;
	enum jaln_publish_mode mode;
	jaln_context *net_ctx;
	struct jaln_connection *conn;
	bool connected;
	long long int retries;
	pthread_mutex_t peer_lock;
};

struct session_ctx_t {
	struct jaldb_record *rec = NULL;
	jaldb_context_t* db_ctx = NULL;

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
	char *private_key;
	char *public_cert;
	char *db_root;
	char *schemas_root;
	long long int poll_time;
	long long int retry_interval;
	char *pub_id;
	long long int network_timeout;
	int num_peers;
	struct peer_config_t *peers;
	char* pid_file;
	char* log_dir;
	char* digest_algorithms;
	char* database_option;
	jaldb_flags jdb_flags;
	int allow_self_signed_certs;
	int http_client_retry_count;
	int http_client_retry_delay;
	int map_size;
	char* filter_socket_basename;
} global_config;

struct global_args_t {
	int daemon;     /* --no-daemon option */
	bool debug_flag;    /* --debug option */
	char *config_path;  /* --config option */
	char *pid_path;     /* --pid option */
	bool enable_tls;    /* --disable_tls option */
	bool use_filter;    /* --use_filter */
	char *digest_algorithms; /* --digest-algorithms option */
} global_args;

enum jald_status {
	JALD_E_CONFIG_LOAD = -1024,
	JALD_E_DB_INIT,
	JALD_E_NOMEM,
	JALD_E_GEN,
	JALD_OK = 0,
};

enum class FilterMessageType: uint16_t {
	StartStream = 0x01,
	StopStream = 0x02,
	RecordSuccess = 0x04,
	RecordError = 0x08,
};

// A counter of threads which need to close before we shut down
static int threads_to_exit = 0;
// A mutex to ensure threads_to_exist remains coherent
static pthread_mutex_t exit_count_lock;

// short hand for long map type names
using SessionHostMap = std::map<std::string, std::shared_ptr<session_ctx_t>>;
using SessionTokenMap = std::map<uint16_t, std::shared_ptr<session_ctx_t>>;

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
static uint16_t next_subscriber_token = 1;
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

static void free_global_config(void);
static void free_peer_config(peer_config_t *peer);
static void free_global_args(void);
static void print_record_types(enum jaln_record_type rtype);
static void print_peer_config(peer_config_t *peer);
static void print_config(void);
static enum jald_status set_global_config(const char* config_path);
static enum jal_status pub_get_bytes(const uint64_t offset, uint8_t * const buffer, uint64_t *size, void *feeder_data);
static jaldb_context_t* setup_db_layer(void);
// Throws if SessionMaps can't be constructed
static inline SessionMaps select_channel(const enum jaln_record_type type);
static bool parse_dc_config(config_setting_t *node, char *dc_config[2]);

int journal_socket_fd;
int audit_socket_fd;
int log_socket_fd;


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

struct StartStreamArgs {
	uint16_t subscriberToken;
	enum jaldb_rec_type type;
	enum jaln_publish_mode mode;
	char* resumeNonce = NULL;
};

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

// Create a specialization of UDSSendMessage for the filter record response message
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
		pthread_mutex_unlock(mapLock.get());

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

void on_channel_close(
		const struct jaln_channel_info *ch_info,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Session is closing");

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(ch_info->type);

	// Close db_handle for this channel
	std::shared_ptr<struct session_ctx_t> ctxPtr = nullptr;
	try {
		pthread_mutex_lock(mapLock.get());
		ctxPtr = sessionHostMap.at(ch_info->hostname);

		// (currently only used by the receive thread)
		// indicate that this session is closing
		ctxPtr->shutting_down = true;

		// Note that erasing the item from our maps doesn't actually destroy the session_ctx_t
		// until all shared_ptrs pointing to it go out of scope, so we can keep using ctxPtr
		sessionHostMap.erase(ctxPtr->hostname);
		sessionTokenMap.erase(ctxPtr->subscriber_token);
		// mapLock is per record type, not per session, so we don't remove that ever

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


	DEBUG_LOG_SUB_SESSION(ch_info, "Closing other sessions");
	struct peer_config_t *peer = (struct peer_config_t *)user_data;
	if (peer) {
		pthread_mutex_lock(&(peer->peer_lock));
		jaln_disconnect(peer->conn); //session->closing=true, for each session.
		DEBUG_LOG_SUB_SESSION(ch_info, "Closed other sessions");
		pthread_mutex_unlock(&(peer->peer_lock));
	}
}

void on_connection_close(
		__attribute__((unused)) const struct jaln_connection *jal_conn,
		__attribute__((unused)) void *user_data)
{
	struct peer_config_t *peer = (struct peer_config_t *)user_data;
	if (!peer) {
		DEBUG_LOG("User data not set for connection_close callback");
		return;
	}
	if (JAL_OK != jaln_shutdown(peer->conn)) {
		DEBUG_LOG("Failed to shutdown connection to %s:%llu", peer->host, peer->port);
	} else {
		DEBUG_LOG("Closed connection to %s:%llu", peer->host, peer->port);
	}
	jaln_disconnect(peer->conn); // marks session->closing = true, for each session.
	peer->connected = false;
}

#define LOG_STR_FIELD(_s, _f) DEBUG_LOG(#_f": %s", _s->_f? _s->_f : "(nil)")
#define LOG_INT_FIELD(_s, _f) DEBUG_LOG(#_f": %d", _s->_f)
#define LOG_PTR_FIELD(_s, _f) DEBUG_LOG(#_f": %p", _s->_f)
void on_connect_ack(
		const struct jaln_connect_ack *ack,
		__attribute__((unused))void *user_data)
{
	DEBUG_LOG("initialize-ack received:");
	DEBUG_LOG("ack: %p", ack);
	LOG_STR_FIELD(ack, hostname);
	LOG_STR_FIELD(ack, addr);
	LOG_INT_FIELD(ack, jaln_version);
	LOG_STR_FIELD(ack, jaln_agent);
	LOG_INT_FIELD(ack, mode);
	LOG_PTR_FIELD(ack, headers);
}

void on_connect_nack(
		const struct jaln_connect_nack *nack,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG("initialize-nack received:");
	DEBUG_LOG("nack: %p", nack);
	DEBUG_LOG("user_data: %p", user_data);
	LOG_STR_FIELD(nack->ch_info, hostname);
	LOG_STR_FIELD(nack->ch_info, addr);
	LOG_STR_FIELD(nack->ch_info, compression);
	LOG_STR_FIELD(nack->ch_info, digest_method);
	LOG_INT_FIELD(nack->ch_info, type);
	LOG_PTR_FIELD(nack, error_list);
	LOG_INT_FIELD(nack, error_cnt);
	for (int i = 0; i < nack->error_cnt; ++i) {
		DEBUG_LOG("error[%d]: %s", i, nack->error_list[i]);
	}
}
#undef LOG_STR_FIELD
#undef LOG_INT_FIELD
#undef LOG_PTR_FIELD

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

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(JALN_RTYPE_JOURNAL);

	pthread_mutex_lock(mapLock.get());

	// A resume should create a new session context, ensure a session with this hostname does not
	// already exist
	if(0 != sessionHostMap.count(std::string(ch_info->hostname))) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Subscriber already exists");
		pthread_mutex_unlock(mapLock.get());
		return JAL_E_INVAL;
	}

	// The session does not alreaady exist. Create it
	// This is a shared pointer to allow both maps to point at the same context safely and ensures
	// the context object can't be destroyed while in use, even if it is removed from the maps
	std::shared_ptr<struct session_ctx_t> ctxPtr = std::make_shared<struct session_ctx_t>(
		std::string(ch_info->hostname),
		next_subscriber_token);

	// Insert this session by hostname and token to our maps
	sessionHostMap.insert({std::string(ch_info->hostname), ctxPtr});
	sessionTokenMap.insert({next_subscriber_token, ctxPtr});
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
			return JALDB_E_NOT_FOUND == db_ret? JAL_E_JOURNAL_MISSING : JAL_E_INVAL;
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
	}
	return JAL_OK;
}

enum jaldb_status pub_get_next_record_on_socket(
			jaln_session *sess,
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
	if(JALDB_OK != ret) {
		jaldb_destroy_record(&ctxPtr->rec);
	}
	return ret;
}

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

	std::shared_ptr<struct session_ctx_t> ctxPtr;
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

	pthread_mutex_lock(mapLock.get());

	// In the case of a journal resume, the session will already exist
	if (0 == sessionHostMap.count(std::string(ch_info->hostname))) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Inserting new session");

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
				return JAL_E_INVAL;
			}
		}

		// Insert this session by hostname and token to our maps
		sessionHostMap.insert({std::string(ch_info->hostname), ctxPtr});
		sessionTokenMap.insert({subscriber_token, ctxPtr});
	} else {
		// We just did a .count() with this value, so we know .at will not throw
		ctxPtr = sessionHostMap.at(ch_info->hostname);
	}
	pthread_mutex_unlock(mapLock.get());

	DEBUG_LOG_SUB_SESSION(ch_info, "Verifying previously sent records.");
	// Only need to clear sent flags for archive mode connection
	// Have to use timestamp since sess->mode is internal to the network library
	if (!*timestamp) {
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
			db_ret = pub_get_next_record_on_socket(
						sess,
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
			db_ret = pub_get_next_record(
						sess,
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

		if (JALDB_OK != db_ret) {
			if (JALDB_E_NOT_FOUND == db_ret) {
				ret = JAL_OK;
				goto out;
			}
			if (JALDB_E_NETWORK_DISCONNECTED == db_ret) {
				// Check if jaln_session is fine.
				if (JAL_OK != jaln_session_is_ok(sess)) {
					DEBUG_LOG_SUB_SESSION(ch_info, "Session issues detected 2");
					DEBUG_LOG_SUB_SESSION(ch_info, "Calling jaln_finish() 2");
					goto out;
				}
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

	DEBUG_LOG_SUB_SESSION(ch_info, "Calling jaln_finish() 3");
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
	ret = jaln_finish(sess);
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

	pthread_mutex_lock(mapLock.get());

	if(0 != sessionHostMap.count(std::string(ch_info->hostname))) {
		// The library should prevent this from happening, but just in case.
		DEBUG_LOG_SUB_SESSION(ch_info, "Subscriber already exists, rejecting subscribe request");
		pthread_mutex_unlock(mapLock.get());
		ret = JAL_E_INVAL;
		return jaln_finish(sess);
	}

	DEBUG_LOG_SUB_SESSION(ch_info, "Inserting new session");

	std::shared_ptr<struct session_ctx_t> ctxPtr = std::make_shared<struct session_ctx_t>(
		std::string(ch_info->hostname),
		subscriber_token);

	fprintf(stderr, "DEBUG: inserting with hostname: %s, token: %d\n", ch_info->hostname, subscriber_token);
	sessionHostMap.insert({std::string(ch_info->hostname), ctxPtr});
	sessionTokenMap.insert({subscriber_token, ctxPtr});

	if (!global_args.use_filter){
		ctxPtr->db_ctx = setup_db_layer();
		if(NULL == ctxPtr->db_ctx) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to setup db");
			pthread_mutex_unlock(mapLock.get());
			return JAL_E_INVAL;
			goto out;
		}
	}

	DEBUG_LOG_SUB_SESSION(ch_info, "Verifying previously sent records.");
	// Only need to clear sent flags for archive mode connection
	// Have to use timestamp since sess->mode is internal to the network library
	if (!*timestamp) {
		if (global_args.use_filter){
		DEBUG_LOG_SUB_SESSION(ch_info, "Using filter.");
		}
		else{
			db_ret = jaldb_mark_unsynced_records_unsent(ctxPtr->db_ctx, db_type);
			if (JALDB_OK != db_ret) {
				DEBUG_LOG_SUB_SESSION(ch_info, "Failed to verify records.");
				ret = JAL_E_INVAL;
				pthread_mutex_unlock(mapLock.get());
				goto out;
			}
		}
	}

	// If we are using the filter, we need to stimulate the filter to start
	// sending us records for this session
	if (global_args.use_filter){
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

	pthread_mutex_unlock(mapLock.get());

	do {
		// nonce will be a new copy that the caller must free
		// The buffers will point to the record stored within the session
		// The record is cleaned up by pub_on_record_complete
		if (global_args.use_filter){
			db_ret = pub_get_next_record_on_socket(
						sess,
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
			db_ret = pub_get_next_record(
						sess,
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
		if (JALDB_OK != db_ret) {
			if (JALDB_E_NOT_FOUND == db_ret) {
				ret = JAL_OK;
				goto out;
			}
			if (JALDB_E_NETWORK_DISCONNECTED == db_ret) {
				// Check if jaln_session is fine.
				if (JAL_OK != jaln_session_is_ok(sess)) {
					DEBUG_LOG_SUB_SESSION(ch_info, "Session issues detected 4");
					DEBUG_LOG_SUB_SESSION(ch_info, "Calling jaln_finish() 4");
					goto out;
				}
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

	DEBUG_LOG_SUB_SESSION(ch_info, "Calling jaln_finish() 5");
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
	}
	ret = jaln_finish(sess);
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
 * Caller is reponsible for freeing this memory
 */
__attribute__((noreturn))
void *pub_send_journal(__attribute__((unused)) void *args)
{
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	const struct jaln_channel_info *ch_info = data->ch_info;

	char *journal_timestamp = NULL;

	if (data->timestamp) {
		journal_timestamp = jal_strdup(data->timestamp);
		free(data->timestamp);
	}


	pub_send_records_feeder(sess, ch_info, &journal_timestamp, &jaln_send_journal, data->subscriber_token);

	free(data);

	free(journal_timestamp);

	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit -= 1;
	pthread_mutex_unlock(&exit_count_lock);

	pthread_exit((void*)NULL);
}

/*
* Called in a thread to handle audit data publishing.  Allocates memory for return status.
* Caller is reponsible for freeing this memory
*/
__attribute__((noreturn))
void *pub_send_audit(void *args)
{
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	const struct jaln_channel_info *ch_info = data->ch_info;

	char *audit_timestamp = NULL;

	if (data->timestamp) {
		audit_timestamp = jal_strdup(data->timestamp);
		free(data->timestamp);
	}

	pub_send_records(sess, ch_info, &audit_timestamp, &jaln_send_audit, data->subscriber_token);

	free(data);

	free(audit_timestamp);

	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit -= 1;
	pthread_mutex_unlock(&exit_count_lock);

	pthread_exit((void*)NULL);
}

/*
 * Called in a thread to handle log data publishing.  Allocates memory for return status.
 * Caller is reponsible for freeing this memory
 */
__attribute__((noreturn))
void *pub_send_log(void *args)
{
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	const struct jaln_channel_info *ch_info = data->ch_info;

	char *log_timestamp = NULL;

	if (data->timestamp) {
		log_timestamp = jal_strdup(data->timestamp);
		free(data->timestamp);
	}

	pub_send_records(sess, ch_info, &log_timestamp, &jaln_send_log, data->subscriber_token);

	free(data);

	free(log_timestamp);

	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit -= 1;
	pthread_mutex_unlock(&exit_count_lock);

	pthread_exit((void*)NULL);
}

// If a resume is requested, pub_on_journal_resume is called prior to (and in addition to)
// pub_on_subscribe. In this case, pub_on_journal_resume creates the session context and inserts
// it to the hash map. pub_on_subscribe detects this by finding ctxPtr != NULL
enum jal_status pub_on_subscribe(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		enum jaln_publish_mode mode,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	pthread_attr_t attr;
	if (0 != pthread_attr_init(&attr)) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR in pthread_attr_init()");
		return JAL_E_INVAL;
	}

	enum jal_status ret = JAL_E_INVAL;
	// Ensure main doesn't try to exit before the thread we're about to create does
	// Note - pub_on_subscribe is called in the chain from jaln_publish, so there isn't actually
	// a risk of main trying to exit during this function
	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit += 1;
	pthread_mutex_unlock(&exit_count_lock);

	pthread_t journal_thread;
	pthread_t audit_thread;
	pthread_t log_thread;

	struct thread_data *data = (struct thread_data *) jal_malloc(sizeof(struct thread_data));
	data->sess = sess;
	data->ch_info = ch_info;
	data->timestamp = NULL;
	// pub_on_subscriber is called directly on the main thread via jaln_publish
	// we can trust that the global value next_subscriber_token will not be concurrently accessed.
	// This is incremented in the main loop, after all corresponding threads have been started
	// Unused when not using the filter
	data->subscriber_token = next_subscriber_token;

	if (0 != pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR in pthread_attr_setdetachstate()");
		ret = JAL_E_INVAL;
		goto err_out;
	}

	if (JALN_LIVE_MODE == mode) {
		data->timestamp = jal_gen_timestamp_usec();
		if (!data->timestamp) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Error: Error generating timestamp");
			ret = JAL_E_INVAL_TIMESTAMP;
			goto err_out;
		}
	} else if (JALN_ARCHIVE_MODE != mode) {
		// Bad mode
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: Bad mode");
		ret = JAL_E_INVAL;
		goto err_out;
	}

	switch (type) {
	case JALN_RTYPE_JOURNAL:
		DEBUG_LOG_SUB_SESSION(ch_info, "Starting journal thread.");
		if(0 != pthread_create(&journal_thread, &attr, pub_send_journal, data)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
			ret = JAL_E_INVAL;
			goto err_out;
		}
		break;

	case JALN_RTYPE_AUDIT:
		DEBUG_LOG_SUB_SESSION(ch_info, "Starting audit thread.");
		if(0 != pthread_create(&audit_thread, &attr, pub_send_audit, data)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
			ret = JAL_E_INVAL;
			goto err_out;
		}
		break;

	case JALN_RTYPE_LOG:
		DEBUG_LOG_SUB_SESSION(ch_info, "Starting log thread.");
		if (0 != pthread_create(&log_thread, &attr, pub_send_log, data)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
			ret = JAL_E_INVAL;
			goto err_out;
		}
		break;

	default:
		DEBUG_LOG_SUB_SESSION(ch_info, "Illegal Record Type");
		ret = JAL_E_INVAL;
		goto err_out;
	}
	pthread_attr_destroy(&attr);

	return JAL_OK;
	// There are a number of cleanup steps that we need to do in error cases
err_out:
	pthread_attr_destroy(&attr);
	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit -= 1;
	pthread_mutex_unlock(&exit_count_lock);
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

	enum jaldb_rec_type db_type = JALDB_RTYPE_UNKNOWN;
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
		DEBUG_LOG_SUB_SESSION(ch_info, "Invalid record type");
		return JAL_E_INVAL;
	}

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);

	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	pthread_mutex_lock(mapLock.get());

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		pthread_mutex_unlock(mapLock.get());
		return JAL_E_INVAL;
	}

	enum jaln_publish_mode mode = jaln_session_get_publish_mode(sess);
	// Only mark the records as sent in archive mode
	if (mode == JALN_ARCHIVE_MODE && !global_args.use_filter) {
		pthread_mutex_lock(mapLock.get());
		enum jaldb_status jaldb_ret = jaldb_mark_sent(ctxPtr->db_ctx, db_type, nonce, 1);
		pthread_mutex_unlock(mapLock.get());
		if (JALDB_OK != jaldb_ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to mark %s as sent: %d", nonce, jaldb_ret);
		} else {
			DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as sent %i", nonce, db_type);
		}
	}
	jaldb_destroy_record(&ctxPtr->rec);
	return JAL_OK;
}

void pub_sync(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) enum jaln_publish_mode mode,
		const char *nonce,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "sync: %s", nonce);

	enum jaldb_status jaldb_ret = JALDB_E_INVAL;
	enum jaldb_rec_type db_type = JALDB_RTYPE_UNKNOWN;

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

	auto [sessionHostMap, sessionTokenMap, mapLock] = select_channel(type);
	//sessionTokenMap is not used
	(void)	sessionTokenMap;

	pthread_mutex_lock(mapLock.get());

	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
		ctxPtr = sessionHostMap.at(std::string(ch_info->hostname));
		pthread_mutex_unlock(mapLock.get());
	} catch (std::out_of_range& e) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		pthread_mutex_unlock(mapLock.get());
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
		if (mode == JALN_ARCHIVE_MODE && ch_info->digest_method) {
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

	pthread_mutex_lock(mapLock.get());
	std::shared_ptr<struct session_ctx_t> ctxPtr;
	try {
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
	// No status returned by callback function
	return;
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

	rc = set_global_config(global_args.config_path);
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
	struct peer_config_t *peer;

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

	// TODO: Try just while(!exiting) here, it prevents us trying to connect once
	// when we're already going down because a ctrl-c happened during startup
	do {
		// set up JALoP contexts for each peer
		for (int i = 0; i < global_config.num_peers; ++i) {
			peer = global_config.peers + i;
			if (peer->connected) {
				// alreay connected
				continue;
			}
			// Since the peer is no longer connected (or has not yet connected
			// the firt time) cleanly shutdown the active connection if it exists
			if(peer->conn) {
				jaln_connection_destroy(&(peer->conn));
				free(peer->conn);
			}

			jctx = peer->net_ctx;
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

			if (JAL_OK != jal_get_digest_algorithm_list(global_config.digest_algorithms, global_args.digest_algorithms, &digest_list, &num_digests)) {
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
			if ((peer->dc_config[0] &&
				JAL_OK != jaln_register_digest_challenge_configuration(jctx, peer->dc_config[0])) ||
				(peer->dc_config[1] &&
				JAL_OK != jaln_register_digest_challenge_configuration(jctx, peer->dc_config[1])))
			{
				DEBUG_LOG("Failed to register digest challenge configuration");
				rc = -1;
				goto out;
			}
			if (JAL_OK != jaln_register_publisher_id(jctx, global_config.pub_id)) {
				DEBUG_LOG("Failed to register publisher ID");
				rc = -1;
				goto out;
			}
			if (global_args.enable_tls) {
				jaln_ret = jaln_register_tls(jctx, global_config.private_key, global_config.public_cert,
					peer->cert_dir);
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
			peer->net_ctx = jctx;

			++peer->retries;
			std::stringstream ss(std::ios_base::out);
			ss << peer->port;
			peer->conn = jaln_publish(peer->net_ctx, peer->host, ss.str().c_str(),
				peer->record_types, peer->mode, peer);
			if (!peer->conn) {
				DEBUG_LOG("Failed connection attempt %lld to %s:%llu", peer->retries, peer->host, peer->port);
			} else {
				peer->retries = 0;
				peer->connected = true;

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
	for (int i = 0; i < global_config.num_peers; ++i) {
		peer = global_config.peers + i;
		if (peer->conn) {
			jal_status status = jaln_disconnect(peer->conn);
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
	for (int i = 0; i < global_config.num_peers; ++i) {
		peer = global_config.peers + i;
		if (peer->conn) {
			jaln_connection_destroy(&(peer->conn));
			free(peer->conn);
		}
		if(peer->net_ctx) {
			jaln_context_destroy(&(peer->net_ctx));
		}
	}
	free_global_config();
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

void free_global_config(void)
{
	free(global_config.private_key);
	free(global_config.public_cert);
	free(global_config.db_root);
	free(global_config.schemas_root);
	free(global_config.pub_id);
	for (int i = 0; i < global_config.num_peers; ++i) {
		free_peer_config(global_config.peers + i);
	}
	free(global_config.peers);
	free(global_config.pid_file);
	free(global_config.log_dir);
	free(global_config.digest_algorithms);
	free(global_config.database_option);
	free(global_config.filter_socket_basename);
}

void free_peer_config(peer_config_t *peer)
{
	if (peer) {
		free(peer->cert_dir);
		free(peer->host);
		free(peer->dc_config[0]);
		free(peer->dc_config[1]);
		pthread_mutex_destroy(&(peer->peer_lock));
		jaln_shutdown(peer->conn);
	}
}

void free_global_args(void)
{
	free((void*) global_args.config_path);
	free((void*) global_args.pid_path);
	free((void*) global_args.digest_algorithms);
}

void print_record_types(enum jaln_record_type rtype)
{
	const size_t j_len = strlen(JALNS_JOURNAL);
	const size_t a_len = strlen(JALNS_AUDIT);
	const size_t l_len = strlen(JALNS_LOG);
	// max size: length of all strings plus 3 spaces and a NUL
	char buffer[sizeof(JALNS_JOURNAL) + sizeof(JALNS_AUDIT) + sizeof(JALNS_LOG) + 1];
	// Fill buffer with space characters
	memset(buffer, ' ', sizeof(buffer));

	char *head = buffer;
	if (rtype & JALN_RTYPE_JOURNAL) {
		memcpy(head, JALNS_JOURNAL, j_len);
		// skip one past the end of this string to leave a space
		head += j_len + 1;
	}
	if (rtype & JALN_RTYPE_AUDIT) {
		memcpy(head, JALNS_AUDIT, a_len);
		// skip one past the end of this string to leave a space
		head += a_len + 1;
	}
	if (rtype & JALN_RTYPE_LOG) {
		memcpy(head, JALNS_LOG, l_len);
		// skip one past the end of this string to leave a space
		head += l_len + 1;
	}
	// terminate with a NULL, potentially but not necessarily in the last byte of the array
	*head = '\0';
	printf("%s", buffer);
}

void print_peer_config(struct peer_config_t *peer_cfg)
{
	printf("\tHOST:\t\t\t%s\n", peer_cfg->host);
	printf("\tPORT:\t\t\t%llu\n", peer_cfg->port);
	printf("\tCERT DIR:\t\t%s\n", peer_cfg->cert_dir);
	printf("\tDIGEST CHALLENGE:\t%s", peer_cfg->dc_config[0]);
	if (peer_cfg->dc_config[1]) {
		printf(", %s\n", peer_cfg->dc_config[1]);
	} else {
		putchar('\n');
	}
	printf("\tMODE:\t\t\t%s\n", peer_cfg->mode == JALN_ARCHIVE_MODE? "archive" : "live");
	printf("\tRECORD TYPES:\t\t");
	print_record_types(peer_cfg->record_types);
	putchar('\n');
}

void print_config(void)
{
	printf("\n===\nBEGIN CONFIG VALUES:\n===\n");
	if (global_args.enable_tls) {
		printf("PRIVATE KEY:\t\t%s\n", global_config.private_key);
		printf("PUBLIC CERT:\t\t%s\n", global_config.public_cert);

		printf("SELF SIGNED CERTS ALLOWED:");
		if (1 == global_config.allow_self_signed_certs)
		{
			printf("\ttrue\n");
		}
		else
		{
			printf("\tfalse\n");
		}

	} else {
		printf("!!!!!!!! TLS DISABLED !!!!!!!!\n");
	}
	printf("POLL TIME:\t\t%lld\n", global_config.poll_time);
	printf("RETRY INTERNVAL:\t%lld\n", global_config.retry_interval);
	printf("NETWORK TIMEOUT:\t%lld\n", global_config.network_timeout);
	printf("HTTP_CLIENT_RETRY_COUNT:\t%d\n", global_config.http_client_retry_count);
	printf("HTTP_CLIENT_RETRY_DELAY:\t%d\n", global_config.http_client_retry_delay);
	printf("DB ROOT:\t\t%s\n", global_config.db_root);
	printf("SCHEMAS ROOT:\t\t%s\n", global_config.schemas_root);
	if(global_config.pid_file) {
		printf("PID FILE:\t\t%s\n", global_config.pid_file);
	}
	if(global_config.log_dir) {
		printf("LOG DIRECTORY:\t\t%s\n", global_config.log_dir);
	}
	printf("PUBLISHER ID:\t\t%s\n", global_config.pub_id);
	if(global_config.digest_algorithms) {
		printf("DIGEST ALGORITHMS:\t%s\n", global_config.digest_algorithms);
	}
	if (global_args.use_filter || global_args.use_filter) {
		printf("FILTER SOCKET:\t\t%s\n", global_config.filter_socket_basename);
	}

	if(global_config.database_option) {
		printf("DATABASE_OPTION:\t%s\n", global_config.database_option);
	}

	printf("LMDB_MAP_SIZE (GB):\t%d\n", global_config.map_size);

	for (int i = 0; i < global_config.num_peers; ++i) {
		printf("PEER[%d]:\n", i);
		print_peer_config(global_config.peers + i);
	}
	printf("===\nEND CONFIG VALUES:\n===\n\n");
	(void)fflush(stdout);
}

static bool validate_dc_config_str(const char* str) {
	if(NULL == str) {
		return false;
	}

	if(0 == strcmp("on", str)
		|| 0 == strcmp("off", str)) {
		return true;
	} else {
		return false;
	}
}

static bool parse_dc_config(config_setting_t *peer, char *dc_config[2])
{
	if (!peer || !dc_config) {
		return false;
	}

	config_setting_t* node = NULL;
	if(JAL_CFG_SUCCESS != jal_config_get_member(
		peer,
		JALNS_DC_CONFIG,
		&node,
		JAL_CFG_REQUIRED)) {
			return false;
	}

	// If a single value is provided instead of an array, handle that here
	if (CONFIG_FALSE == config_setting_is_array(node)
		&& CONFIG_FALSE == config_setting_is_list(node)) {
		// Using the libconfig API directly here since we have already extracted
		// the node and just need to get the string value
		const char* element = config_setting_get_string(node);
		if(NULL == element || !validate_dc_config_str(element)) {
			CONFIG_ERROR(
				node,
				JALNS_DC_CONFIG,
				"Expected \"on\", \"off\", or an array with one or both of these values.");
			return false;
		} else {
			// Note the strdup here - since we used the libconfig API, the returned string
			// is owned by the config_t and tied to its lifetime
			dc_config[0] = strdup(element);
			return true;
		}
	}

	// Otherwise, it's an array/list which we can handle with the same code
	// but we do need the length
	// Again using the libconfig API directly here to get the length so we don't
	// have to re-extract the node
	int node_len = config_setting_length(node);
	// can be on, off, or combination of the two
	if (0 >= node_len || node_len > 2) {
		CONFIG_ERROR(
			node,
			JALNS_DC_CONFIG,
			"Expected \"on\", \"off\", or an array with one or both of these values.");
		return false;
	}

	// Ensure dc_config elements are initialized to NULL
	dc_config[0] = NULL;
	dc_config[1] = NULL;

	for(int i = 0; i < node_len; i++) {
		// Extract the string from the list/array at index i
		char* element = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_elem_string(
			node,
			i,
			&element,
			JALNS_DC_CONFIG)) {
			return false;
		}

		if(!validate_dc_config_str(element)) {
			CONFIG_ERROR(
				node,
				JALNS_DC_CONFIG,
				"Expected \"on\", \"off\", or an array with one or both of these values.");
			return false;
		} else {
			// Note no strdup here because we used the jal_config API, which returns malloc'd
			// memory which must be freed by the caller
			dc_config[i] = element;
		}
	}

	return true;
}

static int rtype_bit_from_str(const char *type)
{
	if (!type) {
		return 0;
	}
	if (!strcasecmp(type, JALNS_JOURNAL)) {
		return JALN_RTYPE_JOURNAL;
	}
	if (!strcasecmp(type, JALNS_AUDIT)) {
		return JALN_RTYPE_AUDIT;
	}
	if (!strcasecmp(type, JALNS_LOG)) {
		return JALN_RTYPE_LOG;
	}
	return 0;
}

static int parse_record_types(config_setting_t *peer)
{
	config_setting_t* node = NULL;
	if(JAL_CFG_SUCCESS != jal_config_get_member(
		peer,
		JALNS_RECORD_TYPES,
		&node,
		JAL_CFG_REQUIRED)) {
			return JALD_E_CONFIG_LOAD;
	}

	if (CONFIG_FALSE == config_setting_is_array(node)
		&& CONFIG_FALSE == config_setting_is_list(node)) {
		// Using the libconfig API directly here since we have already extracted
		// the node and just need to get the string value
		const char* element = config_setting_get_string(node);
		if(NULL == element) {
			CONFIG_ERROR(peer, JALNS_RECORD_TYPES, "Expected a string");
			return false;
		} else {
			int rc = rtype_bit_from_str(element);
			if(!rc) {
				CONFIG_ERROR(
					peer,
					JALNS_RECORD_TYPES,
					"expected string or array of \"" JALNS_JOURNAL \
						"\", \"" JALNS_AUDIT "\", and/or \"" JALNS_LOG "\"");
			}
			return rc;
		}
	}

	// Otherwise, it's an array/list which we can handle with the same code
	// but we do need the length
	// Again using the libconfig API directly here to get the length so we don't
	// have to re-extract the node
	int node_len = config_setting_length(node);

	// can be journal, audit, log or combination of the three
	if (0 >= node_len || node_len > 3) {
		CONFIG_ERROR(
			peer,
			JALNS_RECORD_TYPES,
			"expected string or array of \"" JALNS_JOURNAL \
				"\", \"" JALNS_AUDIT "\", and/or \"" JALNS_LOG "\"");
		return 0;
	}

	// Accumulate bitfield values for all present elements
	int ret = 0;
	for (int i = 0; i < node_len; ++i) {
		// Get the string at index i
		char* element = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_elem_string(
			node,
			i,
			&element,
			JALNS_RECORD_TYPES)) {
				return 0;
		}

		// Get the bit for this string
		int rtype = rtype_bit_from_str(element);
		free(element);
		if (!rtype) {
			CONFIG_ERROR(
				peer,
				JALNS_RECORD_TYPES,
				"expected string or array of \"" JALNS_JOURNAL \
					"\", \"" JALNS_AUDIT "\", and/or \"" JALNS_LOG "\"");
			return 0;
		}

		// OR this bit with our running total
		ret |= rtype;
	}
	return ret;
}

static enum jald_status parse_peer_configs(config_setting_t *root)
{
	config_setting_t *peers = NULL;
	int peer_len = 0;
	// The peers list is required
	if(JAL_CFG_SUCCESS != jal_config_lookup_list(
		root,
		JALNS_PEERS,
		&peers,
		&peer_len,
		JAL_CFG_REQUIRED)) {
		return JALD_E_CONFIG_LOAD;
	}


	// Get length of peer list
	global_config.num_peers = peer_len;
	global_config.peers = (struct peer_config_t *)calloc(peer_len, sizeof(struct peer_config_t));
	if (!global_config.peers) {
		return JALD_E_NOMEM;
	}

	// parse each individual peer configuration
	for (unsigned i = 0; i < (unsigned) peer_len; i++) {
		struct peer_config_t *peer_cfg = global_config.peers + i;
		config_setting_t *a_peer = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_elem_group(
			peers,
			i,
			&a_peer,
			JALNS_PEERS)) {
				return JALD_E_CONFIG_LOAD;
		}

		// Extract peer host
		if(JAL_CFG_SUCCESS != jal_config_lookup_string(
			a_peer,
			JALNS_HOST,
			&peer_cfg->host,
			JAL_CFG_REQUIRED)) {
				// Error printed internally
				return JALD_E_CONFIG_LOAD;
		}

		// Extract peer port
		if(JAL_CFG_SUCCESS != jal_config_lookup_int64(
			a_peer,
			JALNS_PORT,
			&peer_cfg->port,
			JAL_CFG_REQUIRED)) {
				// Error printed internally
				return JALD_E_CONFIG_LOAD;
		}

		// Extract peer digest challenge config

		if (!parse_dc_config(a_peer, peer_cfg->dc_config)) {
			return JALD_E_CONFIG_LOAD;
		}

		// Extract peer record types
		int record_types = parse_record_types(a_peer);
		if(0 == record_types) {
			return JALD_E_CONFIG_LOAD;
		}
		peer_cfg->record_types = (jaln_record_type) record_types;

		// Extract peer mode
		char *mode = NULL;
		if(JAL_CFG_SUCCESS != jal_config_lookup_string(
			a_peer,
			JALNS_MODE,
			&mode,
			JAL_CFG_REQUIRED)) {
				// Error printed internally
				return JALD_E_CONFIG_LOAD;
		}

		// Interpret mode string
		if (!strcasecmp(mode, JALNS_MODE_LIVE)) {
			peer_cfg->mode = JALN_LIVE_MODE;
		} else if (!strcasecmp(mode, JALNS_MODE_ARCHIVE) || (!strcasecmp(mode, JALNS_MODE_ARCHIVE_ALTERNATIVE))) {
			peer_cfg->mode = JALN_ARCHIVE_MODE;
		} else {
			CONFIG_ERROR(
				a_peer,
				JALNS_DC_CONFIG,
				"expected \"" JALNS_MODE_LIVE "\", \"" \
					JALNS_MODE_ARCHIVE "\", or " "\"" JALNS_MODE_ARCHIVE_ALTERNATIVE "\"");
			free(mode);
			return JALD_E_CONFIG_LOAD;
		}
		free(mode);

		// Extract peer cert dir, only if tls is enabled
		if (global_args.enable_tls) {
			char *cert_dir = NULL;
			if(JAL_CFG_SUCCESS != jal_config_lookup_string(
				a_peer,
				JALNS_CERT_DIR,
				&cert_dir,
				JAL_CFG_REQUIRED)) {
				// Error printed internally
				return JALD_E_CONFIG_LOAD;
			}

			char* expanded_cert_dir_path = jal_expand_path(cert_dir, JALNS_CERT_DIR);
			if (expanded_cert_dir_path == NULL)
			{
				//Error already displayed from method call above
				return JALD_E_CONFIG_LOAD;
			}

			peer_cfg->cert_dir = expanded_cert_dir_path;
			if (!peer_cfg->cert_dir) {
				return JALD_E_NOMEM;
			}
			free(cert_dir);
		}

		// Initialize pthread mutex peer_lock
		if (0 != pthread_mutex_init(&(peer_cfg->peer_lock), NULL)) {
			DEBUG_LOG("Failed to initialize peer_lock");
			return JALD_E_GEN;
		}
	}
	return JALD_OK;
}

enum jald_status set_global_config(const char* config_path)
{
	// 0-initialize the global_config struct
	memset(&global_config, 0, sizeof(global_config));

	// Load config file as config_t object
	config_t config;
	if(JAL_CFG_SUCCESS != jal_config_init(&config)) {
		// Error printed internally
		return JALD_E_CONFIG_LOAD;
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
		return JALD_E_CONFIG_LOAD;
	}

	// Extract root configuration setting
	config_setting_t *root = config_root_setting(&config);

	if(global_args.enable_tls) {
		// Extract the private key
		char* private_key = NULL;
		if(JAL_CFG_SUCCESS != jal_config_lookup_string(
			root,
			JALNS_PRIVATE_KEY,
			&private_key,
			JAL_CFG_REQUIRED)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
		}

		global_config.private_key = jal_expand_path(private_key, JALNS_PRIVATE_KEY);
		if (global_config.private_key == NULL)
		{
			//Error already displayed from method call above
			free(private_key);
			return JALD_E_CONFIG_LOAD;
		}
		free(private_key);

		// Extract the public cert
		char* public_cert = NULL;
		if(JAL_CFG_SUCCESS != jal_config_lookup_string(
			root,
			JALNS_PUBLIC_CERT,
			&public_cert,
			JAL_CFG_REQUIRED)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
		}

		global_config.public_cert  = jal_expand_path(public_cert, JALNS_PUBLIC_CERT);
		if (global_config.public_cert == NULL)
		{
			//Error already displayed from method call above
			free(public_cert);
			return JALD_E_CONFIG_LOAD;
		}
		free(public_cert);
	}

	// Extract poll time
	if(JAL_CFG_SUCCESS != jal_config_lookup_int64(
		root,
		JALNS_POLL_TIME,
		&global_config.poll_time,
		JAL_CFG_REQUIRED)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}
	// Additionally require poll time to be a positive integer
	if (global_config.poll_time <= 0) {
		CONFIG_ERROR(root, JALNS_POLL_TIME, "expected positive integer value");
		return JALD_E_CONFIG_LOAD;
	}

	// Extract retry interval
	if(JAL_CFG_SUCCESS != jal_config_lookup_int64(
		root,
		JALNS_RETRY_INTERVAL,
		&global_config.retry_interval,
		JAL_CFG_REQUIRED)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}
	// Additionaly require retry interval to be -1 or greater than 0
	if (0 == global_config.retry_interval || global_config.retry_interval < -1) {
		CONFIG_ERROR(root, JALNS_RETRY_INTERVAL, "expected positive integer value or -1");
		return JALD_E_CONFIG_LOAD;
	}

	// Extract network timeout
	if(JAL_CFG_SUCCESS != jal_config_lookup_int64(
		root,
		JALNS_NETWORK_TIMEOUT,
		&global_config.network_timeout,
		JAL_CFG_REQUIRED)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}
	// Additionally require network timeout to be >= 0
	if (global_config.network_timeout < 0) {
		CONFIG_ERROR(root, JALNS_NETWORK_TIMEOUT, "expected positive integer value or 0");
		return JALD_E_CONFIG_LOAD;
	}

	// Extract publisher ID
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALNS_PUBLISHER_ID,
		&global_config.pub_id,
		JAL_CFG_REQUIRED)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}

	// Extract db_root - optional
	char* db_root = NULL;
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALNS_DB_ROOT,
		&db_root,
		JAL_CFG_OPTIONAL)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}
	if (NULL != db_root) {
		global_config.db_root = jal_expand_path(db_root, JALNS_DB_ROOT);
		if (global_config.db_root  == NULL) {
			//Error already displayed from method call above
			free(db_root);
			return JALD_E_CONFIG_LOAD;
		}
		free(db_root);
	}

	// Extract schemas_root - optional
	char* schemas_root = NULL;
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALNS_SCHEMAS_ROOT,
		&schemas_root,
		JAL_CFG_OPTIONAL)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}
	if (NULL != schemas_root) {
		global_config.schemas_root = jal_expand_path(schemas_root, JALNS_SCHEMAS_ROOT);
		if (global_config.schemas_root == NULL)
		{
			//Error already displayed from method call above
			free(schemas_root);
			return JALD_E_CONFIG_LOAD;
		}
		free(schemas_root);
	}

	// Extract pid_file - optional
	char* pid_file = NULL;
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALNS_PID_FILE,
		&pid_file,
		JAL_CFG_OPTIONAL)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}
	//Since pid_file is optional, ensure not null before processing
	if (pid_file != NULL) {
		global_config.pid_file = jal_expand_home_dir(pid_file, JALNS_PID_FILE);
		if (global_config.pid_file == NULL)
		{
			//Error already displayed from method call above
			free(pid_file);
			return JALD_E_CONFIG_LOAD;
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
			return JALD_E_CONFIG_LOAD;
	}

	//Since log_file is optional, ensure not null before processing
	if (log_dir != NULL)
	{
		global_config.log_dir = jal_expand_path(log_dir, JALNS_LOG_DIR);
		if (global_config.log_dir == NULL) {
			//Error already displayed from method call above
			free(log_dir);
			return JALD_E_CONFIG_LOAD;
		}
		free(log_dir);
	}

	// Extract digest_algorithm - optional
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALNS_DIGEST_ALGORITHMS,
		&global_config.digest_algorithms,
		false)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}

	//Extract allow_self_signed_certs
	global_config.allow_self_signed_certs = 0;
	if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
			root,
			JALNS_ALLOW_SELF_SIGNED_CERTS,
			&global_config.allow_self_signed_certs,
			JAL_CFG_OPTIONAL)
		)
	{
		// Error printed internally
		return JALD_E_CONFIG_LOAD;
	}

	// Extract http_client_retry_count
	global_config.http_client_retry_count = JALN_HTTP_CLIENT_RETRY_COUNT_DEFAULT;
	if(JAL_CFG_SUCCESS != jal_config_lookup_int(
		root,
		JALNS_HTTP_CLIENT_RETRY_COUNT,
		&global_config.http_client_retry_count,
		JAL_CFG_OPTIONAL)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}
	//Check http_client_retry_count is less than zero.
	if (global_config.http_client_retry_count < 0) {
		CONFIG_ERROR(root, JALNS_HTTP_CLIENT_RETRY_COUNT, "invalid value, less than zero.");
		return JALD_E_CONFIG_LOAD;
	}

	// Extract http_client_retry_delay
	global_config.http_client_retry_delay = JALN_HTTP_CLIENT_RETRY_DELAY_DEFAULT;
	if(JAL_CFG_SUCCESS != jal_config_lookup_int(
		root,
		JALNS_HTTP_CLIENT_RETRY_DELAY,
		&global_config.http_client_retry_delay,
		JAL_CFG_OPTIONAL)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}
	//Check http_client_retry_delay is less than zero.
	if (global_config.http_client_retry_delay < 0) {
		CONFIG_ERROR(root, JALNS_HTTP_CLIENT_RETRY_DELAY, "invalid value, less than zero.");
		return JALD_E_CONFIG_LOAD;
	}

	if(global_args.use_filter){

		if(JAL_CFG_SUCCESS != jal_config_lookup_string(
			root,
			JALNS_FILTER_SOCKET_BASENAME,
			&global_config.filter_socket_basename,
			JAL_CFG_OPTIONAL)) {
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

	return parse_peer_configs(root);
}

static jaldb_context_t* setup_db_layer(void)
{
	enum jaldb_status jaldb_ret = JALDB_OK;
	jaldb_context_t* db_ctx = jaldb_context_create();
	if(global_args.use_filter){
		global_config.jdb_flags = JDB_READONLY;
	}
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
		fprintf(stderr, "fd: %d\n", ctx->rec->payload->fd);
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
