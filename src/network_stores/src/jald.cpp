/**
 * @file jald.cpp This file contains the implementation of a daemon process that
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
#include <pthread.h>
#include <signal.h>
#include <sstream>
#include <string>
#include <unistd.h>
#include <time.h>

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

struct peer_config_t {
	enum jaln_record_type pub_allow;
	enum jaln_record_type sub_allow;
};
struct session_ctx_t {
	struct jaldb_record *rec;
	jaldb_context_t *db_ctx;
};

struct global_config_t {
	axlHash *peers;
	char *private_key;
	char *public_cert;
	char *remote_cert_dir;
	char *db_root;
	char *host;
	char *pid_file;
	char *log_dir;
	long long int port;
	long long int poll_time;
	char *digest_algorithms;
} global_config;

struct global_args_t {
	int daemon;		/* --no_daemon option */
	bool debug_flag;	/* --debug option */
	char *config_path;	/* --config option */
	char *pid_path;		/* --pid option */
	bool enable_tls;	/* --disable_tls option */
	char *digest_algorithms;	/* --digest-algorithms option */
} global_args;

enum jald_status {
	JALD_E_CONFIG_LOAD = -1024,
	JALD_E_DB_INIT,
	JALD_E_NOMEM,
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
	{"disable-tls", 's', 0, 0,
		"Disable attempts at TLS negotiation. This option should not be used in production environment since there will be no privacy over the connection.", 0},
	{"pid", 'p', "pid-path", 0,
		"PID Path", 0},
	{"digest-algorithms", 'a', "algs", 0,
		"Provide a list of supported digest algorithms. These algorithms should be ordered by preference in a single double-quoted string with a space separating the algorithms.", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};
static struct argp argp = {options, parse_opt, args_doc, doc, NULL, NULL, NULL};

static void init_global_config(void);
static void free_global_config(void);
static void free_global_args(void);
static axl_bool print_peer_cfg(axlPointer key, axlPointer data, axlPointer user_data);
static void print_record_types(enum jaln_record_type rtype);
static void print_config(void);
static enum jald_status set_global_config(config_t *config);
static enum jald_status handle_allow_mask(config_setting_t *parent, config_setting_t *list, const char *cfg_key, enum jaln_record_type *mask);
static enum jal_status pub_get_bytes(const uint64_t offset, uint8_t * const buffer, uint64_t *size, void *feeder_data);
static jaldb_context_t* setup_db_layer(void);
static enum jal_status select_channel(const struct jaln_channel_info *ch_info, axlHash** hash, pthread_mutex_t ** sub_lock);

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

	struct peer_config_t *peer_cfg = (struct peer_config_t*) axl_hash_get(global_config.peers, req->hostname);
	if (!peer_cfg) {
		peer_cfg = (struct peer_config_t*) axl_hash_get(global_config.peers, req->addr);
	}
	if (!peer_cfg) {
		return JALN_CE_UNAUTHORIZED_MODE;
	}
	if (req->role == JALN_ROLE_PUBLISHER) {
		// TODO: add support for jald to act as a subscriber.
		return JALN_CE_UNSUPPORTED_MODE;
	}
	enum jaln_record_type mask = (enum jaln_record_type)0;
	switch (req->role) {
	case JALN_ROLE_SUBSCRIBER:
		mask = peer_cfg->sub_allow;
		break;
	case JALN_ROLE_PUBLISHER:
		mask = peer_cfg->pub_allow;
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
	axlHash *hash = NULL;
	pthread_mutex_t *sub_lock = NULL;
	if(JAL_OK != select_channel(ch_info, &hash, &sub_lock))
	{
		return;
	}

	DEBUG_LOG_SUB_SESSION(ch_info, "Session is closing");

	struct session_ctx_t* ctx = NULL;
	ctx = (struct session_ctx_t*)axl_hash_get(hash, ch_info->hostname);
	if(!ctx || !ctx->db_ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: No context or BDB context associated with closing channel");
	}
	else {
		jaldb_context_destroy(&ctx->db_ctx);
	}

	pthread_mutex_lock(sub_lock);
	axl_hash_remove(hash, ch_info->hostname);
	pthread_mutex_unlock(sub_lock);
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
		return JAL_E_INVAL;
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

			if (JALDB_E_NOT_FOUND == ret) {
				sleep(global_config.poll_time);

			}
			if (exiting || (JAL_OK != jaln_session_is_ok(sess))) {
				ret = JALDB_E_NETWORK_DISCONNECTED;
				goto out;
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
		return JAL_E_INVAL;
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
					hash,
					sub_lock,
					db_type);
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
		if (JAL_OK != ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to send record (%d)", ret);
			goto out;
		}
		// Have to use timestamp since sess->mode is internal to the network library
		if (!*timestamp) {
			//Archive mode
			pthread_mutex_lock(sub_lock);
			db_ret = jaldb_mark_sent(ctx->db_ctx, db_type, nonce, 1);
			pthread_mutex_unlock(sub_lock);
			if (JALDB_OK != db_ret) {
				DEBUG_LOG_SUB_SESSION(ch_info, "Failed to mark %s as sent: %d", nonce, db_ret);
				ret = JAL_E_INVAL_NONCE;
				goto out;
			} else {
				DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as sent", nonce);
			}
		}

		free(nonce);
		nonce = NULL;
	} while (JALDB_OK == db_ret);

	ret = jaln_finish(sess);
out:
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
		return JAL_E_INVAL;
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
		ret = JAL_E_INVAL;
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
					hash,
					sub_lock,
					db_type);

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
		if (JAL_OK != ret) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Failed to send record (%d)", ret);
			goto out;
		}
		// Have to use timestamp since sess->mode is internal to the network library
		if (!*timestamp) {
			//Archive mode
			pthread_mutex_lock(sub_lock);
			db_ret = jaldb_mark_sent(ctx->db_ctx, db_type, nonce, 1);
			pthread_mutex_unlock(sub_lock);
			if (JALDB_OK != db_ret) {
				DEBUG_LOG_SUB_SESSION(ch_info, "Failed to mark %s as sent", nonce);
				ret = JAL_E_INVAL_NONCE;
				goto out;
			} else {
				DEBUG_LOG_SUB_SESSION(ch_info, "Marked %s as sent", nonce);
			}
		}

		free(nonce);
		nonce = NULL;

	} while (JALDB_OK == db_ret);

	ret = jaln_finish(sess);
out:
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
	enum jal_status *ret = (enum jal_status *) jal_malloc(sizeof(enum jal_status));
	*ret = JAL_E_INVAL;
	struct thread_data *data = (struct thread_data *) args;
	jaln_session *sess = data->sess;
	const struct jaln_channel_info *ch_info = data->ch_info;
	axlHash *hash = gs_journal_subs;
	pthread_mutex_t *sub_lock = &gs_journal_sub_lock;

	char *journal_timestamp = NULL;

	if (data->timestamp) {
		journal_timestamp = jal_strdup(data->timestamp);
	}

	*ret = pub_send_records_feeder(sess, ch_info, &data->timestamp, hash, sub_lock, &jaln_send_journal);

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
	axlHash *hash = gs_audit_subs;
	pthread_mutex_t *sub_lock = &gs_audit_sub_lock;

	char *audit_timestamp = NULL;

	if (data->timestamp) {
		audit_timestamp = jal_strdup(data->timestamp);
	}

	*ret = pub_send_records(sess, ch_info, &audit_timestamp, hash, sub_lock, &jaln_send_audit);

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
	axlHash *hash = gs_log_subs;
	pthread_mutex_t *sub_lock = &gs_log_sub_lock;

	char *log_timestamp = NULL;

	if (data->timestamp) {
		log_timestamp = jal_strdup(data->timestamp);
	}

	*ret = pub_send_records(sess, ch_info, &log_timestamp, hash, sub_lock, &jaln_send_log);

	free(log_timestamp);

	pthread_exit((void*)ret);
}

enum jal_status pub_on_subscribe(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		enum jaln_publish_mode mode,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	enum jal_status ret = JAL_E_INVAL;
	pthread_t journal_thread;
	pthread_t audit_thread;
	pthread_t log_thread;
	pthread_attr_t attr;
	struct thread_data data;
	void *status = NULL;
	int rc = 0;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit += 1;
	pthread_mutex_unlock(&exit_count_lock);

	data.sess = sess;
	data.ch_info = ch_info;
	data.timestamp = NULL;

	if (JALN_LIVE_MODE == mode) {
		data.timestamp = jaldb_gen_timestamp();
		if (!data.timestamp) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Error: Error generating timestamp");
			return JAL_E_INVAL_TIMESTAMP;
		}
	} else if (JALN_ARCHIVE_MODE != mode) {
		// Bad mode
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: Bad mode");
		return JAL_E_INVAL;
	}

	switch (type) {
	case JALN_RTYPE_JOURNAL:
		if(0 != pthread_create(&journal_thread, &attr, pub_send_journal, &data)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
			return JAL_E_INVAL;
		}

		pthread_attr_destroy(&attr);

		rc = pthread_join(journal_thread, &status);
		if (rc) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR: return code from pthread_create() is %d\n", rc);
			free(status);
			return JAL_E_INVAL;
		}
		break;
	case JALN_RTYPE_AUDIT:
		if(0 != pthread_create(&audit_thread, &attr, pub_send_audit, &data)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
			return JAL_E_INVAL;
		}

		pthread_attr_destroy(&attr);

		rc = pthread_join(audit_thread, &status);
		if (rc) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Error while joining thread (%d)\n", rc);
			free(status);
			return JAL_E_INVAL;
		}
		break;
	case JALN_RTYPE_LOG:
		if (0 != pthread_create(&log_thread, &attr, pub_send_log, &data)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
			return JAL_E_INVAL;
		}

		pthread_attr_destroy(&attr);

		rc = pthread_join(log_thread, &status);
		if (rc) {
			DEBUG_LOG_SUB_SESSION(ch_info, "Error while joining thread (%d)\n", rc);
			free(status);
			return JAL_E_INVAL;
		}
		break;
	default:
		DEBUG_LOG_SUB_SESSION(ch_info, "Illegal Record Type");
		return JAL_E_INVAL;
	}

	ret = *((enum jal_status *) status);
	free(status);
	if (JAL_OK != ret && JAL_E_NOT_CONNECTED != ret) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed while sending records to subscriber");
	}

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
	axlHash *hash = NULL;
	pthread_mutex_t *sub_lock = NULL;

	if(JAL_OK != select_channel(ch_info, &hash, &sub_lock))
	{
		return JAL_E_INVAL;
	}

	pthread_mutex_lock(sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*)axl_hash_get(hash, ch_info->hostname);
	pthread_mutex_unlock(sub_lock);
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		return JAL_E_INVAL;
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

	axlHash *hash = NULL;
	pthread_mutex_t *sub_lock = NULL;

	if(JAL_OK != select_channel(ch_info, &hash, &sub_lock))
	{
		return;
	}

	pthread_mutex_lock(sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*)axl_hash_get(hash, ch_info->hostname);
	pthread_mutex_unlock(sub_lock);
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
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

	if (mode == JALN_ARCHIVE_MODE) {
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
	if (!ctx) {
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

	init_global_config();

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

	ss << global_config.port;
	gs_journal_subs = axl_hash_new(axl_hash_string, axl_hash_equal_string);
	gs_audit_subs = axl_hash_new(axl_hash_string, axl_hash_equal_string);
	gs_log_subs = axl_hash_new(axl_hash_string, axl_hash_equal_string);
	jaln_ret = jaln_listen(jctx, global_config.host, ss.str().c_str(), NULL);
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
	free_global_config();
	free_global_args();
	pthread_mutex_destroy(&gs_journal_sub_lock);
	pthread_mutex_destroy(&gs_audit_sub_lock);
	pthread_mutex_destroy(&gs_log_sub_lock);
	pthread_mutex_destroy(&exit_count_lock);
	jaln_context_destroy(&jctx);
	jaln_publisher_callbacks_destroy(&pub_cbs);
	config_destroy(&config);
	jal_seccomp_enforcer_destroy(&seccomp_enforcer);

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

void init_global_config(void)
{
	memset(&global_config, 0, sizeof(global_config));
	global_config.peers = axl_hash_new(axl_hash_string, axl_hash_equal_string);
}

void free_global_config(void)
{
	// all the other config elements are simply libconfig elements and
	// should not get freed.
	axl_hash_free(global_config.peers);
}

void free_global_args(void)
{
	free((void*) global_args.config_path);
	free((void*) global_args.pid_path);
	free((void*) global_args.digest_algorithms);
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

axl_bool print_peer_cfg(axlPointer key, axlPointer data, __attribute__((unused)) axlPointer user_data)
{
	char *host = (char *)key;
	struct peer_config_t *peer_cfg = (struct peer_config_t*) data;
	printf("\n%15s | ", host);
	print_record_types(peer_cfg->pub_allow);
	printf(" | ");
	print_record_types(peer_cfg->sub_allow);
	return axl_false;
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
	printf("PEERS\n%15s | %18s | %18s\n", "HOST", "PUBLISH_ALLOW", "SUBSCRIBE_ALLOW");
	axl_hash_foreach(global_config.peers, print_peer_cfg, NULL);
	printf("\n===\nEND CONFIG VALUES:\n===\n");
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

			struct peer_config_t *peer_cfg = (struct peer_config_t*) axl_hash_get(global_config.peers, key);

			if (!peer_cfg) {
				printf("cfg for %s, creating struct\n", key);
				peer_cfg = (struct peer_config_t*) calloc(1, sizeof(*peer_cfg));
				if (!peer_cfg) {
					return JALD_E_NOMEM;
				}
				if (!key) {
					rc |= JAL_CFG_FAILURE;
					free(peer_cfg);
					continue;
				}
				axl_hash_insert_full(global_config.peers, key, free, peer_cfg, free);

				DEBUG_LOG("cfg for %s, adding %d for pub and %d for sub\n", key, pub_mask, sub_mask);
				DEBUG_LOG("cfg for %s, was %d for pub and %d for sub\n", key, peer_cfg->pub_allow, peer_cfg->sub_allow);

				peer_cfg->pub_allow = (enum jaln_record_type) (peer_cfg->pub_allow | pub_mask);
				peer_cfg->sub_allow = (enum jaln_record_type) (peer_cfg->sub_allow | sub_mask);
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

	jaldb_ret = jaldb_context_init(db_ctx, global_config.db_root, JDB_NONE);

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

static enum jal_status select_channel(const struct jaln_channel_info *ch_info, axlHash** hash, pthread_mutex_t ** sub_lock)
{
	*hash = NULL;
	*sub_lock = NULL;

	switch (ch_info->type) {
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
