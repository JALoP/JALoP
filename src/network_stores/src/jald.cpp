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
#include <string>
#include <unistd.h>
#include <time.h>
#include <pwd.h>

#include <jalop/jal_version.h>

#include "jal_base64_internal.h"
#include "jaldb_context.hpp"
#include "jalns_strings.h"
#include "jalu_daemonize.h"
#include "jal_config.h"
#include "jaldb_segment.h"
#include "jaldb_record.h"
#include "jaldb_utils.h"
#include "jal_alloc.h"
#include "jal_ts_utils.h"
#include <jalop/jal_seccomp_enforcer.h>

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
	struct jaldb_record *rec;
	jaldb_context_t* db_ctx;
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
} global_config;

struct global_args_t {
	int daemon;     /* --no-daemon option */
	bool debug_flag;    /* --debug option */
	char *config_path;  /* --config option */
	char *pid_path;     /* --pid option */
	bool enable_tls;    /* --disable_tls option */
	char *digest_algorithms; /* --digest-algorithms option */
} global_args;

enum jald_status {
	JALD_E_CONFIG_LOAD = -1024,
	JALD_E_DB_INIT,
	JALD_E_NOMEM,
	JALD_E_GEN,
	JALD_OK = 0,
};

static jaln_context *jctx = NULL;
static pthread_mutex_t gs_journal_sub_lock;
static pthread_mutex_t gs_audit_sub_lock;
static pthread_mutex_t gs_log_sub_lock;
static pthread_mutex_t exit_count_lock;
static axlHash *gs_journal_subs = NULL;
static axlHash *gs_audit_subs = NULL;
static axlHash *gs_log_subs = NULL;
static int exiting = 0;
static int threads_to_exit = 0;

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
static enum jal_status select_channel(const struct jaln_channel_info* ch_info, axlHash** hash, pthread_mutex_t** sub_lock);
static bool parse_dc_config(config_setting_t *node, char *dc_config[2]);

void on_channel_close(
		const struct jaln_channel_info *ch_info,
		__attribute__((unused)) void *user_data)
{
	axlHash *hash = NULL;
	pthread_mutex_t *sub_lock = NULL;
	if(JAL_OK != select_channel(ch_info, &hash, &sub_lock))
	{
		return;
	}

	DEBUG_LOG_SUB_SESSION(ch_info, "Session is closing");

	// Close db_handle for this channel
	struct session_ctx_t* ctx = NULL;
	ctx = (struct session_ctx_t*)axl_hash_get(hash, ch_info->hostname);
	if(!ctx || !ctx->db_ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: No context or DB context associated with closing channel");
	}
	else {
		jaldb_context_destroy(&ctx->db_ctx);
		if(ctx->rec) {
			jaldb_destroy_record(&ctx->rec);
		}
	}

	pthread_mutex_lock(sub_lock);
	axl_hash_remove(hash, ch_info->hostname);
	pthread_mutex_unlock(sub_lock);

	DEBUG_LOG_SUB_SESSION(ch_info, "Closing other sessions");
	struct peer_config_t *peer = (struct peer_config_t *)user_data;
	if (peer) {
		pthread_mutex_lock(&(peer->peer_lock));
		jaln_disconnect(peer->conn); //session->closing=axl_true, for each session.
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
	jaln_disconnect(peer->conn); // marks session->closing = axl_true, for each session.
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
	pthread_mutex_lock(&gs_journal_sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*)axl_hash_get(gs_journal_subs, ch_info->hostname);
	if (ctx) {
		// The library should prevent this from happening, but just in case.
		DEBUG_LOG_SUB_SESSION(ch_info, "Subscriber already exists");
		pthread_mutex_unlock(&gs_journal_sub_lock);
		return JAL_E_INVAL;
	}
	ctx = (struct session_ctx_t*) calloc(1, sizeof(*ctx));
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed to create session context");
		pthread_mutex_unlock(&gs_journal_sub_lock);
		return JAL_E_NO_MEM;
	}
	axl_hash_insert_full(gs_journal_subs, strdup(ch_info->hostname), free, ctx, free);
	pthread_mutex_unlock(&gs_journal_sub_lock);
	ctx->rec = NULL;
	ctx->db_ctx = setup_db_layer();
	if(NULL == ctx->db_ctx) {
		return JAL_E_INVAL;
	}

	enum jaldb_status db_ret = JALDB_E_INVAL;

	db_ret = jaldb_get_record(ctx->db_ctx, JALDB_RTYPE_JOURNAL, record_info->nonce, &(ctx->rec));
	if (JALDB_OK != db_ret) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed to retrieve journal from db");
		return JALDB_E_NOT_FOUND == db_ret? JAL_E_JOURNAL_MISSING : JAL_E_INVAL;
	}

	*system_metadata_buffer = ctx->rec->sys_meta->payload;
	if (ctx->rec->app_meta) {
		*application_metadata_buffer = ctx->rec->app_meta->payload;
	} else {
		*application_metadata_buffer = NULL;
	}

	return JAL_OK;
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
			axlHash *hash,
			pthread_mutex_t *sub_lock,
			enum jaldb_rec_type db_type)
{
	enum jaldb_status ret = JALDB_E_NOT_FOUND;
	struct session_ctx_t *ctx = NULL;
	struct jaldb_record *rec = NULL;
	pthread_mutex_lock(sub_lock);
	ctx = (struct session_ctx_t*)axl_hash_get(hash, ch_info->hostname);
	pthread_mutex_unlock(sub_lock);
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session");
		goto out;
	}
	if ((ctx->rec) && (JALDB_RTYPE_JOURNAL == db_type)) {
		/* Journal resume, so we already have a record */
		// Make a copy to match behavior of jaldb_next_*_record functions
		*nonce = jal_strdup(ctx->rec->network_nonce);
		ret = JALDB_OK;
	} else {
		while (JALDB_E_NOT_FOUND == ret) {
			// Have to use timestamp since sess->mode is internal to the network library
			if (!*timestamp) {
				// Archive mode
				DEBUG_LOG_SUB_SESSION(ch_info, "Looking for a record in Archive Mode");
				ret = jaldb_next_unsynced_record(ctx->db_ctx, db_type, nonce, &(ctx->rec));
			} else {
				// Live mode
				DEBUG_LOG_SUB_SESSION(ch_info, "Looking for a record in Live Mode, timestamp: %s",*timestamp);
				ret = jaldb_next_chronological_record(ctx->db_ctx,
									db_type,
									nonce,
									&(ctx->rec),
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

	rec = ctx->rec;

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
			ret = jaldb_open_segment_for_read(ctx->db_ctx, rec->payload);
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
		jaldb_destroy_record(&ctx->rec);
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
			axlHash *hash,
			pthread_mutex_t *sub_lock,
			enum jal_status (*send)(jaln_session *, char *, uint8_t *,
						uint64_t, uint8_t *, uint64_t,
						uint64_t, struct jaln_payload_feeder *))
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
	struct session_ctx_t *ctx = NULL;
	struct jaln_payload_feeder feeder;

	enum jaldb_rec_type db_type;
	switch (type) {
	case JALN_RTYPE_JOURNAL:
		db_type = JALDB_RTYPE_JOURNAL;
		break;
	default:
		ret = JAL_E_INVAL;
		goto out;
	}

	pthread_mutex_lock(sub_lock);

	ctx = (struct session_ctx_t *) axl_hash_get(hash, ch_info->hostname);
	if (!ctx) {
		ctx = (struct session_ctx_t*) calloc(1, sizeof(*ctx));
		if (!ctx) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to allocate context");
			pthread_mutex_unlock(sub_lock);
			ret = JAL_E_NO_MEM;
			goto out;
		}
		DEBUG_LOG_SUB_SESSION(ch_info, "Inserting new session");

		ctx->db_ctx = setup_db_layer();
		if(NULL == ctx->db_ctx) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to setup db");
			pthread_mutex_unlock(sub_lock);
			ret = JAL_E_INVAL;
			goto out;
		}

		axl_hash_insert_full(hash, strdup(ch_info->hostname), free, ctx, free);
	}

	DEBUG_LOG_SUB_SESSION(ch_info, "Verifying previously sent records.");
	// Only need to clear sent flags for archive mode connection
	// Have to use timestamp since sess->mode is internal to the network library
	if (!*timestamp) {
		db_ret = jaldb_mark_unsynced_records_unsent(ctx->db_ctx, db_type);
		if (JALDB_OK != db_ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to verify records.");
			ret = JAL_E_INVAL;
			pthread_mutex_unlock(sub_lock);
			goto out;
		}
	}

	pthread_mutex_unlock(sub_lock);

	feeder.feeder_data = ctx;
	feeder.get_bytes = pub_get_bytes;

	do {
		// nonce will be a new copy that the caller must free
		// The buffers will point to the record stored within the session
		// The record is cleaned up by pub_on_record_complete
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
					hash,
					sub_lock,
					db_type);
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
		if (JAL_OK != ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to send record (%d)", ret);
			goto out;
		}

		free(nonce);
		nonce = NULL;
	} while (JALDB_OK == db_ret);

	DEBUG_LOG_SUB_SESSION(ch_info, "Calling jaln_finish() 3");
out:
	ret = jaln_finish(sess);
	free(nonce);
	return ret;
}


enum jal_status pub_send_records(
			jaln_session *sess,
			const struct jaln_channel_info *ch_info,
			char **timestamp,
			axlHash *hash,
			pthread_mutex_t *sub_lock,
			enum jal_status (*send)(jaln_session *, char *, uint8_t *,
						uint64_t, uint8_t *, uint64_t,
						uint8_t *, uint64_t))
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
	struct session_ctx_t *ctx = NULL;

	enum jaldb_rec_type db_type;
	switch (type) {
	case JALN_RTYPE_AUDIT:
		db_type = JALDB_RTYPE_AUDIT;
		break;
	case JALN_RTYPE_LOG:
		db_type = JALDB_RTYPE_LOG;
		break;
	default:
		ret = JAL_E_INVAL;
		goto out;
	}

	pthread_mutex_lock(sub_lock);

	ctx = (struct session_ctx_t *) axl_hash_get(hash, ch_info->hostname);
	if (ctx) {
		// The library should prevent this from happening, but just in case.
		DEBUG_LOG_SUB_SESSION(ch_info, "Subscribe exists, rejecting subscribe request");
		pthread_mutex_unlock(sub_lock);
		ret = JAL_E_INVAL;
		goto out;
	}

	ctx = (struct session_ctx_t*) calloc(1, sizeof(*ctx));
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed to allocate context");
		pthread_mutex_unlock(sub_lock);
		ret = JAL_E_NO_MEM;
		goto out;
	}

	ctx->db_ctx = setup_db_layer();
	if(NULL == ctx->db_ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed to setup db");
		pthread_mutex_unlock(sub_lock);
		return JAL_E_INVAL;
		goto out;
	}

	DEBUG_LOG_SUB_SESSION(ch_info, "Inserting new session");

	axl_hash_insert_full(hash, strdup(ch_info->hostname), free, ctx, free);

	DEBUG_LOG_SUB_SESSION(ch_info, "Verifying previously sent records.");
	// Only need to clear sent flags for archive mode connection
	// Have to use timestamp since sess->mode is internal to the network library
	if (!*timestamp) {
		db_ret = jaldb_mark_unsynced_records_unsent(ctx->db_ctx, db_type);
		if (JALDB_OK != db_ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to verify records.");
			ret = JAL_E_INVAL;
			pthread_mutex_unlock(sub_lock);
			goto out;
		}
	}

	pthread_mutex_unlock(sub_lock);

	do {
		// nonce will be a new copy that the caller must free
		// The buffers will point to the record stored within the session
		// The record is cleaned up by pub_on_record_complete
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
					hash,
					sub_lock,
					db_type);
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
		if (JAL_OK != ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to send record (%d)", ret);
			goto out;
		}

		free(nonce);
		nonce = NULL;
	} while (JALDB_OK == db_ret);

	DEBUG_LOG_SUB_SESSION(ch_info, "Calling jaln_finish() 5");
out:
	ret = jaln_finish(sess);
	free(nonce);
	return ret;
}

struct thread_data {
	jaln_session *sess;
	const struct jaln_channel_info *ch_info;
	char *timestamp;
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
	axlHash *hash = gs_journal_subs;
	pthread_mutex_t *sub_lock = &gs_journal_sub_lock;

	char *journal_timestamp = NULL;

	if (data->timestamp) {
		journal_timestamp = jal_strdup(data->timestamp);
		free(data->timestamp);
	}

	free(data);

	pub_send_records_feeder(sess, ch_info, &journal_timestamp, hash, sub_lock, &jaln_send_journal);

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
	axlHash *hash = gs_audit_subs;
	pthread_mutex_t *sub_lock = &gs_audit_sub_lock;

	char *audit_timestamp = NULL;

	if (data->timestamp) {
		audit_timestamp = jal_strdup(data->timestamp);
		free(data->timestamp);
	}

	free(data);

	pub_send_records(sess, ch_info, &audit_timestamp, hash, sub_lock, &jaln_send_audit);

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
	axlHash *hash = gs_log_subs;
	pthread_mutex_t *sub_lock = &gs_log_sub_lock;

	char *log_timestamp = NULL;

	if (data->timestamp) {
		log_timestamp = jal_strdup(data->timestamp);
		free(data->timestamp);
	}

	free(data);

	pub_send_records(sess, ch_info, &log_timestamp, hash, sub_lock, &jaln_send_log);

	free(log_timestamp);

	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit -= 1;
	pthread_mutex_unlock(&exit_count_lock);

	pthread_exit((void*)NULL);
}

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
		enum jaln_record_type type,
		char *nonce,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "On record complete: %s", nonce);
	axlHash *hash = NULL;
	pthread_mutex_t *sub_lock = NULL;

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

	if(JAL_OK != select_channel(ch_info, &hash, &sub_lock)) {
		return JAL_E_INVAL;
	}

	pthread_mutex_lock(sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*)axl_hash_get(hash, ch_info->hostname);
	pthread_mutex_unlock(sub_lock);
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		return JAL_E_INVAL;
	}

	enum jaln_publish_mode mode = jaln_session_get_publish_mode(sess);
	// Only mark the records as sent in archive mode
	if (mode == JALN_ARCHIVE_MODE) {
		pthread_mutex_lock(sub_lock);
		enum jaldb_status jaldb_ret = jaldb_mark_sent(ctx->db_ctx, db_type, nonce, 1);
		pthread_mutex_unlock(sub_lock);
		if (JALDB_OK != jaldb_ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to mark %s as sent: %d", nonce, jaldb_ret);
		} else {
			DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as sent", nonce);
		}
	}

	jaldb_destroy_record(&ctx->rec);
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
	pthread_mutex_t *sub_lock = NULL;

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
	axlHash *hash = NULL;

	if(JAL_OK != select_channel(ch_info, &hash, &sub_lock))
	{
		return;
	}

	pthread_mutex_lock(sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*)axl_hash_get(hash, ch_info->hostname);
	pthread_mutex_unlock(sub_lock);
	if(!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		return;
	}

	// Only sync the record in the DB in archive mode with digest challenges
	if (mode == JALN_ARCHIVE_MODE && ch_info->digest_method) {
		pthread_mutex_lock(sub_lock);
		jaldb_ret = jaldb_mark_synced(ctx->db_ctx, db_type, nonce);
		pthread_mutex_unlock(sub_lock);
		if (JALDB_OK != jaldb_ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to mark %s as synced: %d", nonce, jaldb_ret);
		} else {
			DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as synced", nonce);
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

	axlHash *hash = NULL;
	pthread_mutex_t *sub_lock = NULL;

	if(JAL_OK != select_channel(ch_info, &hash, &sub_lock))
	{
		return;
	}

	pthread_mutex_lock(sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*)axl_hash_get(hash, ch_info->hostname);
	pthread_mutex_unlock(sub_lock);
	if(!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		return;
	}

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
	if(ctx)
	{
		db_ret = jaldb_mark_sent(ctx->db_ctx, db_type, nonce, 0);
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
	struct jaln_connection_callbacks *conn_cbs = NULL;
	struct jaln_publisher_callbacks *pub_cbs = NULL;
	struct jal_digest_ctx *dctx = NULL;
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

	if (0 != pthread_mutex_init(&gs_journal_sub_lock, NULL)) {
		DEBUG_LOG("Failed to initialize journal_sub_lock");
		rc = -1;
		goto out;
	}
	if (0 != pthread_mutex_init(&gs_audit_sub_lock, NULL)) {
		DEBUG_LOG("Failed to initialize audit_sub_lock");
		rc = -1;
		goto out;
	}
	if (0 != pthread_mutex_init(&gs_log_sub_lock, NULL)) {
		DEBUG_LOG("Failed to initialize log_sub_lock");
		rc = -1;
		goto out;
	}
	if (0 != pthread_mutex_init(&exit_count_lock, NULL)) {
		DEBUG_LOG("Failed to initialize exit_count_lock");
		rc = -1;
		goto out;
	}
	gs_journal_subs = axl_hash_new(axl_hash_string, axl_hash_equal_string);
	gs_audit_subs = axl_hash_new(axl_hash_string, axl_hash_equal_string);
	gs_log_subs = axl_hash_new(axl_hash_string, axl_hash_equal_string);
	struct peer_config_t *peer;

	if (0 != jal_seccomp_enforcer_apply_final(seccomp_enforcer)){
		goto out;
	}

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

			conn_cbs = jaln_connection_callbacks_create();
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
				dctx = jal_digest_ctx_create(digest_list[j]);

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

			jaln_ret = jaln_register_connection_callbacks(jctx, conn_cbs);
			if (JAL_OK != jaln_ret) {
				DEBUG_LOG("Failed to register connection callbacks");
				rc = -1;
				goto out;
			}
			conn_cbs = NULL;

			jaln_ret = jaln_register_publisher_callbacks(jctx, pub_cbs);
			if (JAL_OK != jaln_ret) {
				DEBUG_LOG("Failed to register publisher callbacks");
				rc = -1;
				goto out;
			}
			pub_cbs = NULL;

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
	pthread_mutex_destroy(&gs_journal_sub_lock);
	pthread_mutex_destroy(&gs_audit_sub_lock);
	pthread_mutex_destroy(&gs_log_sub_lock);
	pthread_mutex_destroy(&exit_count_lock);
	jaln_connection_callbacks_destroy(&conn_cbs);
	jaln_publisher_callbacks_destroy(&pub_cbs);
	axl_hash_free(gs_journal_subs);
	axl_hash_free(gs_log_subs);
	axl_hash_free(gs_audit_subs);

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

	if(global_config.database_option) {
		printf("DATABASE_OPTION:\t%s\n", global_config.database_option);
	}

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

	//database_option config setting
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALNS_DATABASE_OPTION,
		&global_config.database_option,
		JAL_CFG_OPTIONAL)) {
			// Error printed internally
			return JALD_E_CONFIG_LOAD;
	}

	//Ensure valid entry was in the config file and parse the value
	if (JALDB_OK != jaldb_get_db_flags(global_config.database_option, &global_config.jdb_flags))
	{
		CONFIG_ERROR(root, JALNS_DATABASE_OPTION, "invalid value.");
		return JALD_E_CONFIG_LOAD;
	}

	return parse_peer_configs(root);
}

static jaldb_context_t* setup_db_layer(void)
{
	enum jaldb_status jaldb_ret = JALDB_OK;
	jaldb_context_t* db_ctx = jaldb_context_create();

	jaldb_ret = jaldb_context_init(db_ctx, global_config.db_root, global_config.jdb_flags);

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

static enum jal_status select_channel(const struct jaln_channel_info * ch_info, axlHash ** hash, pthread_mutex_t ** sub_lock)
{
	*hash = NULL;
	*sub_lock = NULL;

	switch(ch_info->type) {
		case JALN_RTYPE_JOURNAL:
			*hash = gs_journal_subs;
			*sub_lock = &gs_journal_sub_lock;
			break;
		case JALN_RTYPE_AUDIT:
			*hash = gs_audit_subs;
			*sub_lock = &gs_audit_sub_lock;
			break;
		case JALN_RTYPE_LOG:
			*hash = gs_log_subs;
			*sub_lock = &gs_log_sub_lock;
			break;
		default:
			DEBUG_LOG_SUB_SESSION(ch_info, "Illegal Record Type");
			return JAL_E_INVAL;
	}
	return JAL_OK;
}
