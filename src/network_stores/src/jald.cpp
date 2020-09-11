/**
 * @file jald.cpp This file contains the implementation of a daemon process that
 * listens for subscribe requests from remotes.
 *
 * @section LICENSE
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
#include <getopt.h>
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

#include <jalop/jal_version.h>

#include "jal_base64_internal.h"
#include "jaldb_context.hpp"
#include "jalns_strings.h"
#include "jalu_daemonize.h"
#include "jalu_config.h"
#include "jaldb_segment.h"
#include "jaldb_record.h"
#include "jaldb_utils.h"
#include "jal_alloc.h"

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

#define CONFIG_ERROR(setting, name, ...) \
do { \
	fprintf(stderr, "Config Error: line %d: field \"%s\" ", \
			config_setting_source_line(setting), name); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n"); \
} while (0)

struct peer_config_t {
	const char *host;
	long long int port;
	char *cert_dir;
	const char *dc_config[2];
	enum jaln_record_type record_types;
	enum jaln_publish_mode mode;
	jaln_context *net_ctx;
	struct jaln_connection *conn;
	long long int retries;
	pthread_mutex_t peer_lock;
};

struct session_ctx_t {
	struct jaldb_record *rec;
};

struct global_config_t {
	char *private_key;
	char *public_cert;
	char *db_root;
	char *schemas_root;
	long long int poll_time;
	long long int retry_interval;
	const char *pub_id;
	int num_peers;
	struct peer_config_t *peers;
} global_config;

struct global_args_t {
	int daemon;		/* --no_daemon option */
	bool debug_flag;	/* --debug option */
	char *config_path;	/* --config option */
	bool enable_tls;	/* --disable_tls option */
} global_args;

enum jald_status {
	JALD_E_CONFIG_LOAD = -1024,
	JALD_E_DB_INIT,
	JALD_E_NOMEM,
	JALD_E_GEN,
	JALD_OK = 0,
};

static jaln_context *jctx = NULL;
static jaldb_context_t *db_ctx = NULL;
static pthread_mutex_t gs_journal_sub_lock;
static pthread_mutex_t gs_audit_sub_lock;
static pthread_mutex_t gs_log_sub_lock;
static pthread_mutex_t exit_count_lock;
static axlHash *gs_journal_subs = NULL;
static axlHash *gs_audit_subs = NULL;
static axlHash *gs_log_subs = NULL;
static int exiting = 0;
static int threads_to_exit = 0;

static void usage();
static int process_options(int argc, char **argv);
static enum jald_status config_load(config_t *config, char *config_path);
static void init_global_config(void);
static void free_global_config(void);
static void free_peer_config(peer_config_t *peer);
static void free_global_args(void);
static void print_record_types(enum jaln_record_type rtype);
static void print_peer_config(peer_config_t *peer);
static void print_config(void);
static enum jald_status set_global_config(config_t *config);
static enum jal_status pub_get_bytes(const uint64_t offset, uint8_t * const buffer, uint64_t *size, void *feeder_data);

enum jaln_connect_error on_connect_request(
		__attribute__((unused)) const struct jaln_connect_request *req,
		__attribute__((unused)) int *selected_encoding,
		__attribute__((unused)) int *selected_digest,
		__attribute__((unused)) void *user_data)
{
	// Incoming connections are not supported
	return JALN_CE_UNAUTHORIZED_MODE;
}

void on_channel_close(
		const struct jaln_channel_info *ch_info,
		__attribute__((unused)) void *user_data)
{
	axlHash *hash = NULL;
	pthread_mutex_t *sub_lock = NULL;
	switch (ch_info->type) {
	case JALN_RTYPE_JOURNAL:
		hash = gs_journal_subs;
		sub_lock = &gs_journal_sub_lock;
		break;
	case JALN_RTYPE_AUDIT:
		hash = gs_audit_subs;
		sub_lock = &gs_audit_sub_lock;
		break;
	case JALN_RTYPE_LOG:
		hash = gs_log_subs;
		sub_lock = &gs_log_sub_lock;
		break;
	default:
		DEBUG_LOG_SUB_SESSION(ch_info, "Illegal record type");
		return;
	}
	DEBUG_LOG_SUB_SESSION(ch_info, "Session is closing");
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
        free(peer->conn);
	peer->conn = NULL;
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
        LOG_STR_FIELD(nack->ch_info, encoding);
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
	enum jaldb_status db_ret = JALDB_E_INVAL;
	
	db_ret = jaldb_get_record(db_ctx, JALDB_RTYPE_JOURNAL, record_info->nonce, &(ctx->rec));
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
				ret = jaldb_next_unsynced_record(db_ctx, db_type, nonce, &(ctx->rec));
			} else {
				// Live mode
				DEBUG_LOG_SUB_SESSION(ch_info, "Looking for a record in Live Mode, timestamp: %s",*timestamp);
				ret = jaldb_next_chronological_record(db_ctx,
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
			ret = jaldb_open_segment_for_read(db_ctx, rec->payload);
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

		axl_hash_insert_full(hash, strdup(ch_info->hostname), free, ctx, free);
	}

	DEBUG_LOG_SUB_SESSION(ch_info, "Verifying previously sent records.");
	// Only need to clear sent flags for archive mode connection
	// Have to use timestamp since sess->mode is internal to the network library
	if (!*timestamp) {
		db_ret = jaldb_mark_unsynced_records_unsent(db_ctx, db_type);
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
					ret = jaln_finish(sess);
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
		// Have to use timestamp since sess->mode is internal to the network library
		if (!*timestamp) {
			//Archive mode
			pthread_mutex_lock(sub_lock);
			db_ret = jaldb_mark_sent(db_ctx, db_type, nonce, 1);
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

	DEBUG_LOG_SUB_SESSION(ch_info, "Calling jaln_finish() 3");
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

	DEBUG_LOG_SUB_SESSION(ch_info, "Inserting new session");

	axl_hash_insert_full(hash, strdup(ch_info->hostname), free, ctx, free);

	DEBUG_LOG_SUB_SESSION(ch_info, "Verifying previously sent records.");
	// Only need to clear sent flags for archive mode connection
	// Have to use timestamp since sess->mode is internal to the network library
	if (!*timestamp) {
		db_ret = jaldb_mark_unsynced_records_unsent(db_ctx, db_type);
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
					ret = jaln_finish(sess);
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
		// Have to use timestamp since sess->mode is internal to the network library
		if (!*timestamp) {
			//Archive mode
			pthread_mutex_lock(sub_lock);
			db_ret = jaldb_mark_sent(db_ctx, db_type, nonce, 1);
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

	DEBUG_LOG_SUB_SESSION(ch_info, "Calling jaln_finish() 5");
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

	free(data);

	*ret = pub_send_records_feeder(sess, ch_info, &journal_timestamp, hash, sub_lock, &jaln_send_journal);

	free(journal_timestamp);

	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit -= 1;
	pthread_mutex_unlock(&exit_count_lock);

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

	free(data);

	*ret = pub_send_records(sess, ch_info, &audit_timestamp, hash, sub_lock, &jaln_send_audit);

	free(audit_timestamp);

	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit -= 1;
	pthread_mutex_unlock(&exit_count_lock);

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

	free(data);

	*ret = pub_send_records(sess, ch_info, &log_timestamp, hash, sub_lock, &jaln_send_log);

	free(log_timestamp);

	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit -= 1;
	pthread_mutex_unlock(&exit_count_lock);

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
	pthread_t journal_thread;
	pthread_t audit_thread;
	pthread_t log_thread;
	pthread_attr_t attr;
	struct thread_data *data = (struct thread_data *) jal_malloc(sizeof(struct thread_data));

	if (0 != pthread_attr_init(&attr)) {
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR in pthread_attr_init()");
		return JAL_E_INVAL;
	}

	//pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (0 != pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE)) {
		pthread_attr_destroy(&attr);
		DEBUG_LOG_SUB_SESSION(ch_info, "ERROR in pthread_attr_setdetachstate()");
		return JAL_E_INVAL;
	}

	pthread_mutex_lock(&exit_count_lock);
	threads_to_exit += 1;
	pthread_mutex_unlock(&exit_count_lock);

	data->sess = sess;
	data->ch_info = ch_info;
	data->timestamp = NULL;

	if (JALN_LIVE_MODE == mode) {
		data->timestamp = jaldb_gen_timestamp();
		if (!data->timestamp) {
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
		DEBUG_LOG_SUB_SESSION(ch_info, "Starting journal thread.");
		if(0 != pthread_create(&journal_thread, &attr, pub_send_journal, data)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
			return JAL_E_INVAL;
		}

		pthread_attr_destroy(&attr);

		break;
	case JALN_RTYPE_AUDIT:
		DEBUG_LOG_SUB_SESSION(ch_info, "Starting audit thread.");
		if(0 != pthread_create(&audit_thread, &attr, pub_send_audit, data)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
			return JAL_E_INVAL;
		}

		pthread_attr_destroy(&attr);

		break;
	case JALN_RTYPE_LOG:
		DEBUG_LOG_SUB_SESSION(ch_info, "Starting log thread.");
		if (0 != pthread_create(&log_thread, &attr, pub_send_log, data)) {
			DEBUG_LOG_SUB_SESSION(ch_info, "ERROR creating a thread");
			return JAL_E_INVAL;
		}

		pthread_attr_destroy(&attr);

		break;
	default:
		DEBUG_LOG_SUB_SESSION(ch_info, "Illegal Record Type");
		return JAL_E_INVAL;
	}

	return JAL_OK;
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

	switch (type) {
	case JALN_RTYPE_JOURNAL:
		hash = gs_journal_subs;
		sub_lock = &gs_journal_sub_lock;
		break;
	case JALN_RTYPE_AUDIT:
		hash = gs_audit_subs;
		sub_lock = &gs_audit_sub_lock;
		break;
	case JALN_RTYPE_LOG:
		hash = gs_log_subs;
		sub_lock = &gs_log_sub_lock;
		break;
	default:
		DEBUG_LOG_SUB_SESSION(ch_info, "Illegal Record Type");
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

	pthread_mutex_t *sub_lock = NULL;

	switch(type) {
	case JALN_RTYPE_JOURNAL:
		db_type = JALDB_RTYPE_JOURNAL;
		sub_lock = &gs_journal_sub_lock;
		break;
	case JALN_RTYPE_AUDIT:
		db_type = JALDB_RTYPE_AUDIT;
		sub_lock = &gs_audit_sub_lock;
		break;
	case JALN_RTYPE_LOG:
		db_type = JALDB_RTYPE_LOG;
		sub_lock = &gs_log_sub_lock;
		break;
	default:
		// shouldn't happen.
		return;
	}

	// Only sync the record in the DB in archive mode with digest challenges
	if (mode == JALN_ARCHIVE_MODE && ch_info->digest_method) {
		pthread_mutex_lock(sub_lock);
		jaldb_ret = jaldb_mark_synced(db_ctx, db_type, nonce);
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
	db_ret = jaldb_mark_sent(db_ctx, db_type, nonce, 0);

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

static enum jald_status setup_db_layer(void);
static void teardown_db_layer(void);

int main(int argc, char **argv)
{
	struct jaln_connection_callbacks *conn_cbs = NULL;
	struct jaln_publisher_callbacks *pub_cbs = NULL;
	struct jal_digest_ctx *dctx = NULL;
	enum jal_status jaln_ret;
	int rc = 0;
	config_t config;
	config_init(&config);

	rc = setup_signals();
	if (0 != rc) {
		goto quick_out;
	}

	if (process_options(argc, argv) == VERSION_CALLED) {
		goto quick_out;
	}

	DEBUG_LOG("Config Path: %s\tDebug: %d\n", global_args.config_path, global_args.debug_flag);

	if (!global_args.config_path) {
		rc = JALD_E_CONFIG_LOAD;
		goto quick_out;
	}

	rc = config_load(&config, global_args.config_path);
	if (rc != JALD_OK) {
		goto quick_out;
	}

	init_global_config();

	rc = set_global_config(&config);
	if (rc != JALD_OK) {
		goto out;
	}

	print_config();

	if (global_args.daemon) {
		jalu_daemonize();
	}

	rc = setup_db_layer();
	if (rc != JALD_OK) {
		DEBUG_LOG("Error setting up database");
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

	do {
	    // set up JALoP contexts for each peer
	    for (int i = 0; i < global_config.num_peers; ++i) {
		peer = global_config.peers + i;
		if (peer->conn) {
			// alreay connected
			continue;
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

		jctx = peer->net_ctx;
	    	jaln_context_destroy(&jctx);
		sleep(1);
		jctx = jaln_context_create();

		if (!jctx) {
			DEBUG_LOG("Failed to create the jaln_context");
			rc = -1;
			goto out;
		}
		if (JAL_OK != jaln_register_encoding(jctx, "none")) {
			DEBUG_LOG("Failed to register default encoding");
			rc = -1;
			goto out;
		}
		dctx = jal_sha256_ctx_create();
		if (JAL_OK != jaln_register_digest_algorithm(jctx, dctx)) {
			DEBUG_LOG("Failed to register sha256 algorithm");
			jal_digest_ctx_destroy(&dctx);
			dctx = NULL;
			rc = -1;
			goto out;
		}
		// The jaln_context owns the digest algorithm, so don't keep a
		// reference to it.
		dctx = NULL;
		if ((peer->dc_config[0] && JAL_OK != jaln_register_digest_challenge_configuration(
					jctx, peer->dc_config[0])) ||
				(peer->dc_config[1] && JAL_OK != jaln_register_digest_challenge_configuration(
					jctx, peer->dc_config[1]))) {
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

		peer->net_ctx = jctx;

		++peer->retries;
		std::stringstream ss(std::ios_base::out);
		ss << peer->port;
		peer->conn = jaln_publish(peer->net_ctx, peer->host, ss.str().c_str(), \
				peer->record_types, peer->mode, peer);
		if (!peer->conn) {
			DEBUG_LOG("Failed connection attempt %lld to %s:%llu", peer->retries, peer->host, peer->port);
		} else {
			peer->retries = 0;
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
			jal_status rc = jaln_disconnect(peer->conn);
			if (JAL_OK == rc) {
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
	free_global_config();
	free_global_args();
	teardown_db_layer();
	pthread_mutex_destroy(&gs_journal_sub_lock);
	pthread_mutex_destroy(&gs_audit_sub_lock);
	pthread_mutex_destroy(&gs_log_sub_lock);
	pthread_mutex_destroy(&exit_count_lock);
	jaln_context_destroy(&jctx);
	jaln_connection_callbacks_destroy(&conn_cbs);
	jaln_publisher_callbacks_destroy(&pub_cbs);

quick_out:
	config_destroy(&config);

	return rc;
}

int process_options(int argc, char **argv)
{
	int opt = 0;
	int long_index = 0;

	static const char *opt_string = "c:dvs";
	static const struct option long_options[] = {
		{"config", required_argument, NULL, 'c'}, /* --config or -c */
		{"debug", no_argument, NULL, 'd'}, /* --debug or -d */
		{"no-daemon", no_argument, &global_args.daemon, 0}, /* --no-daemon */
		{"version", no_argument, NULL, 'v'}, /* --version or -v */
		{"disable-tls", no_argument, NULL, 's'}, /* --disable-tls or -s */
		{0, 0, 0, 0} /* terminating -0 item */
	};

	global_args.daemon = true;
	global_args.debug_flag = false;
	global_args.config_path = NULL;
	global_args.enable_tls = true;

	opt = getopt_long(argc, argv, opt_string, long_options, &long_index);

	while(opt != -1) {
		switch (opt) {
			case 'd':
				global_args.debug_flag = true;
				break;
			case 'c':
				if (global_args.config_path) {
					free(global_args.config_path);
				}
				global_args.config_path = strdup(optarg);
				break;
			case 'v':
				printf("%s\n", jal_version_as_string());
				return VERSION_CALLED;
				break;
			case 0:
				// getopt_long returns 0 for long options that
				// have no equivalent 'short' option, i.e.
				// --no-daemon in this case.
				break;
			case 's':
				// disable TLS
				global_args.enable_tls = false;
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
	fprintf(stderr, "Usage: jald -c, --config <config_file> [-d, --debug] [-s, --disable-tls] [-v, --version] [--no-daemon]\n");
	exit(1);
}

enum jald_status config_load(config_t *config, char *config_path)
{
	int rc = 0;

	if (!config) {
		rc = JALD_E_CONFIG_LOAD;
		goto out;
	}

	if (!config_path) {
		rc = JALD_E_CONFIG_LOAD;
		goto out;
	}

	rc = config_read_file(config, config_path);
	if (rc != CONFIG_TRUE) {
		printf("Failed to load config file: %s: (%d) %s!\n", config_path, config_error_line(config), config_error_text(config));
		rc = JALD_E_CONFIG_LOAD;
		goto out;
	}
	rc = JALD_OK;

out:
	return (enum jald_status) rc;
}

void init_global_config(void)
{
	memset(&global_config, 0, sizeof(global_config));
}

void free_global_config(void)
{
	// all the other config elements are simply libconfig elements and
	// should not get freed.
        free(global_config.private_key);
        free(global_config.public_cert);
        free(global_config.db_root);
        free(global_config.schemas_root);
	for (int i = 0; i < global_config.num_peers; ++i) {
		free_peer_config(global_config.peers + i);
	}
	free(global_config.peers);
}

void free_peer_config(peer_config_t *peer)
{
	if (peer) {
		free(peer->cert_dir);
		pthread_mutex_destroy(&(peer->peer_lock));
		jaln_shutdown(peer->conn);
	}
}

void free_global_args(void)
{
	free((void*) global_args.config_path);
}

void print_record_types(enum jaln_record_type rtype)
{
	const size_t j_len = strlen(JALNS_JOURNAL);
	const size_t a_len = strlen(JALNS_AUDIT);
	const size_t l_len = strlen(JALNS_LOG);
	// max size: length of all strings plus 2 spaces and a NUL
	const int size = j_len + a_len + l_len + 3;
	char *buffer = (char *)alloca(size);
	char *head = buffer;
	memset(head, ' ', size);
	if (rtype & JALN_RTYPE_JOURNAL) {
		memcpy(head, JALNS_JOURNAL, j_len);
		head += j_len + 1;
	}
	if (rtype & JALN_RTYPE_AUDIT) {
		memcpy(head, JALNS_AUDIT, a_len);
		head += a_len + 1;
	}
	if (rtype & JALN_RTYPE_LOG) {
		memcpy(head, JALNS_LOG, l_len);
		head += l_len + 1;
	}
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
	} else {
		printf("!!!!!!!! TLS DISABLED !!!!!!!!\n");
	}
	printf("POLL TIME:\t\t%lld\n", global_config.poll_time);
	printf("RETRY INTERNVAL:\t%lld\n", global_config.retry_interval);
	printf("DB ROOT:\t\t%s\n", global_config.db_root);
	printf("SCHEMAS ROOT:\t\t%s\n", global_config.schemas_root);
	printf("PUBLISHER ID:\t\t%s\n", global_config.pub_id);
	for (int i = 0; i < global_config.num_peers; ++i) {
		printf("PEER[%d]:\n", i);
		print_peer_config(global_config.peers + i);
	}
	printf("===\nEND CONFIG VALUES:\n===\n\n");
	(void)fflush(stdout);
}

static bool parse_dc_config(config_setting_t *node, const char *dc_config[2])
{
	if (!node || !dc_config) {
		return false;
	}
	if (!config_setting_is_array(node)) {
		if (!(dc_config[0] = config_setting_get_string(node))) {
			return false;
		}
		dc_config[1] = NULL;
		return true;
	}
	int node_len = config_setting_length(node);
	// can be on, off, or combination of the two
	if (0 >= node_len || node_len > 2) {
		return false;
	}
	if (!(dc_config[0] = config_setting_get_string_elem(node, 0))) {
		return false;
	}
	if (node_len == 2) {
		if (!(dc_config[1] = config_setting_get_string_elem(node, 1))) {
			return false;
		}
	} else {
		dc_config[1] = NULL;
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

static int parse_record_types(config_setting_t *node)
{
	if (!node) {
		return 0;
	}
	if (!config_setting_is_array(node)) {
		return rtype_bit_from_str(config_setting_get_string(node));
	}
	int node_len = config_setting_length(node);
	// can be journal, audit, log or combination of the three
	if (0 >= node_len || node_len > 3) {
		return 0;
	}
	int ret = 0;
	for (int i = 0; i < node_len; ++i) {
		int rtype = rtype_bit_from_str(config_setting_get_string_elem(node, i));
		if (!rtype) {
			return 0;
		}
		ret |= rtype;
	}
	return ret;
}

static enum jald_status parse_peer_configs(config_setting_t *root, config_setting_t *peers)
{
	if (NULL == peers || !config_setting_is_list(peers)) {
		CONFIG_ERROR(root, JALNS_PEERS, "expected non-empty list");
		return JALD_E_CONFIG_LOAD;
	}
	int peer_len = config_setting_length(peers);
	if (!peer_len) {
		CONFIG_ERROR(root, JALNS_PEERS, "expected non-empty list");
		return JALD_E_CONFIG_LOAD;
	}
	global_config.num_peers = peer_len;
	global_config.peers = (struct peer_config_t *)calloc(peer_len, sizeof(struct peer_config_t));
	if (!global_config.peers) {
		return JALD_E_NOMEM;
	}
	// parse each individual peer configuration
	for (unsigned i = 0; i < (unsigned) peer_len; i++) {
		int rc;
		struct peer_config_t *peer_cfg = global_config.peers + i;
		config_setting_t *a_peer = config_setting_get_elem(peers, i);
		if (!config_setting_is_group(a_peer)) {
			CONFIG_ERROR(a_peer, JALNS_PEERS, " expected group for %s[%u]", JALNS_PEERS, i);
			return JALD_E_CONFIG_LOAD;
		}

		rc = config_setting_lookup_string(a_peer, JALNS_HOST, &peer_cfg->host);
		if (CONFIG_FALSE == rc) {
			CONFIG_ERROR(a_peer, JALNS_HOST, "expected string value");
			return JALD_E_CONFIG_LOAD;
		}

		rc = config_setting_lookup_int64(a_peer, JALNS_PORT, &peer_cfg->port);
		if (CONFIG_FALSE == rc) {
			CONFIG_ERROR(a_peer, JALNS_PORT, "expected int64 value");
			return JALD_E_CONFIG_LOAD;
		}

		if (!parse_dc_config(config_setting_get_member(a_peer, JALNS_DC_CONFIG), peer_cfg->dc_config)) {
			CONFIG_ERROR(a_peer, JALNS_DC_CONFIG, "expected string or array of one or two elements");
			return JALD_E_CONFIG_LOAD;
		}

		rc = parse_record_types(config_setting_get_member(a_peer, JALNS_RECORD_TYPES));
		if (!rc) {
			CONFIG_ERROR(a_peer, JALNS_RECORD_TYPES, "expected string or array of \"" JALNS_JOURNAL \
					"\", \"" JALNS_AUDIT "\", and/or \"" JALNS_LOG "\"");
			return JALD_E_CONFIG_LOAD;
		}
		peer_cfg->record_types = (jaln_record_type) rc;

		const char *mode;
		rc = config_setting_lookup_string(a_peer, JALNS_MODE, &mode);
		if (CONFIG_TRUE == rc) {
			if (!strcasecmp(mode, JALNS_MODE_LIVE)) {
				peer_cfg->mode = JALN_LIVE_MODE;
			} else if (!strcasecmp(mode, JALNS_MODE_ARCHIVE)) {
				peer_cfg->mode = JALN_ARCHIVE_MODE;
			} else {
				CONFIG_ERROR(a_peer, JALNS_DC_CONFIG, "expected \"" JALNS_MODE_LIVE "\" or \"" \
						JALNS_MODE_ARCHIVE "\"");
				return JALD_E_CONFIG_LOAD;
			}
		} else {
			CONFIG_ERROR(a_peer, JALNS_MODE, "expected string value");
			return JALD_E_CONFIG_LOAD;
		}
		const char *cert_dir;
		char abs_cert_dir[PATH_MAX];
		if (global_args.enable_tls) {
			rc = config_setting_lookup_string(a_peer, JALNS_CERT_DIR, &cert_dir);
			if (CONFIG_FALSE == rc) {
				CONFIG_ERROR(a_peer, JALNS_CERT_DIR, "expected string value");
				return JALD_E_CONFIG_LOAD;
			}
			if (!realpath(cert_dir, abs_cert_dir)) {
				CONFIG_ERROR(a_peer, JALNS_CERT_DIR, "unable to convert to absolute path");
				return JALD_E_CONFIG_LOAD;
			}
			peer_cfg->cert_dir = strdup(abs_cert_dir);
			if (!peer_cfg->cert_dir) {
				return JALD_E_NOMEM;
			}
		}

		// Initialize pthread mutex peer_lock
		if (0 != pthread_mutex_init(&(peer_cfg->peer_lock), NULL)) {
			DEBUG_LOG("Failed to initialize peer_lock");
			return JALD_E_GEN;
		}
	}
	return JALD_OK;
}

enum jald_status set_global_config(config_t *config)
{
	int rc;
	char *ret = NULL;
	char absolute_private_key[PATH_MAX];
	char absolute_public_cert[PATH_MAX];
	char absolute_db_root[PATH_MAX];
	char absolute_schemas_root[PATH_MAX];

	if (!config) {
		return JALD_E_CONFIG_LOAD;
	}
	config_setting_t *root = config_root_setting(config);
	if (global_args.enable_tls) {
		rc = jalu_config_lookup_string(root, JALNS_PRIVATE_KEY, &global_config.private_key, true);
		if (0 != rc) {
			return JALD_E_CONFIG_LOAD;
		}
		ret = realpath(global_config.private_key, absolute_private_key);
		if (!ret) {
			printf("Failed to convert path \"%s\" for key \"%s\" to absolute path\n", global_config.private_key, JALNS_PRIVATE_KEY);
			return JALD_E_CONFIG_LOAD;
		}
		free(global_config.private_key);
		global_config.private_key = strdup(absolute_private_key);
		rc = jalu_config_lookup_string(root, JALNS_PUBLIC_CERT, &global_config.public_cert, true);
		if (0 != rc) {
			return JALD_E_CONFIG_LOAD;
		}
		ret = realpath(global_config.public_cert, absolute_public_cert);
		if (!ret) {
			printf("Failed to convert path \"%s\" for key \"%s\" to absolute path\n", global_config.public_cert, JALNS_PUBLIC_CERT);
			return JALD_E_CONFIG_LOAD;
		}
		free(global_config.public_cert);
		global_config.public_cert = strdup(absolute_public_cert);
	}

	rc = config_setting_lookup_int64(root, JALNS_POLL_TIME, &global_config.poll_time);
	if (CONFIG_FALSE == rc || global_config.poll_time <= 0) {
		CONFIG_ERROR(root, JALNS_POLL_TIME, "expected positive integer value");
		return JALD_E_CONFIG_LOAD;
	}
	rc = config_setting_lookup_int64(root, JALNS_RETRY_INTERVAL, &global_config.retry_interval);
	if (CONFIG_FALSE == rc || global_config.retry_interval < -1) {
		CONFIG_ERROR(root, JALNS_RETRY_INTERVAL, "expected positive integer value or -1");
		return JALD_E_CONFIG_LOAD;
	}

	rc = config_setting_lookup_string(root, JALNS_PUBLISHER_ID, &global_config.pub_id);
	if (CONFIG_FALSE == rc) {
		CONFIG_ERROR(root, JALNS_PUBLISHER_ID, "expected string value");
		return JALD_E_CONFIG_LOAD;
	}

	// db_root is optional
	rc = jalu_config_lookup_string(root, JALNS_DB_ROOT, &global_config.db_root, false);
	if (0 == rc) {
		ret = realpath(global_config.db_root, absolute_db_root);
		if (!ret) {
			printf("Failed to convert path \"%s\" for key \"%s\" to absolute path\n", global_config.db_root, JALNS_DB_ROOT);
			return JALD_E_CONFIG_LOAD;
		}
		free(global_config.db_root);
		global_config.db_root = strdup(absolute_db_root);
	}

	// schemas_root is optional
	rc = jalu_config_lookup_string(root, JALNS_SCHEMAS_ROOT, &global_config.schemas_root, false);
	if (0 == rc) {
		ret = realpath(global_config.schemas_root, absolute_schemas_root);
		if (!ret) {
			printf("Failed to convert path \"%s\" for key \"%s\" to absolute path\n", global_config.schemas_root, JALNS_SCHEMAS_ROOT);
			return JALD_E_CONFIG_LOAD;
		}
		free(global_config.schemas_root);
		global_config.schemas_root = strdup(absolute_schemas_root);
	}

	config_setting_t *peers =  config_setting_get_member(root, JALNS_PEERS);
	return parse_peer_configs(root, peers);
}

enum jald_status setup_db_layer(void)
{
	enum jald_status rc = JALD_OK;
	enum jaldb_status jaldb_ret = JALDB_OK;
	db_ctx = jaldb_context_create();

	jaldb_ret = jaldb_context_init(db_ctx, global_config.db_root, global_config.schemas_root, 0);

	if (JALDB_OK != jaldb_ret) {
		rc = JALD_E_DB_INIT;
	}

	return rc;
}

void teardown_db_layer(void)
{
	jaldb_context_destroy(&db_ctx);

	return;
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
