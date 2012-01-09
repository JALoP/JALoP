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

#include <jalop/jal_version.h>

#include "jal_base64_internal.h"
#include "jaldb_context.hpp"
#include "jalns_strings.h"
#include "jalu_daemonize.h"
#include "jalu_config.h"

#define ONE_MINUTE 60
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
		fprintf(stderr, "jald %s[%d][%s:sub:%s]", __FUNCTION__, __LINE__, \
				ch_info->hostname, __rec_type); \
		fprintf(stderr, ##args); \
		fprintf(stderr, "\n"); \
	} \
} while (0)

#define DEBUG_LOG(args...) \
do { \
	if (global_args.debug_flag) { \
		fprintf(stderr, "jald %s[%d] ", __FUNCTION__, __LINE__); \
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
	enum jaln_record_type pub_allow;
	enum jaln_record_type sub_allow;
};
struct session_ctx_t {
	int journal_fd;
	uint8_t *payload_buf;
};

struct global_config_t {
	axlHash *peers;
	char *private_key;
	char *public_cert;
	char *remote_cert_dir;
	char *db_root;
	char *schemas_root;
	char *host;
	long long int port;
	long long int pending_digest_max;
	long long int pending_digest_timeout;
} global_config;

struct global_args_t {
	int daemon;		/* --no_daemon option */
	bool debug_flag;	/* --debug option */
	char *config_path;	/* --config option */
} global_args;

enum jald_status {
	JALD_E_CONFIG_LOAD = -1024,
	JALD_E_DB_INIT,
	JALD_E_NOMEM,
	JALD_OK = 0,
};

static jaln_context *jctx = NULL;
static jaldb_context_t *db_ctx = NULL;
static pthread_mutex_t gs_journal_sub_lock;
static pthread_mutex_t gs_audit_sub_lock;
static pthread_mutex_t gs_log_sub_lock;
static axlHash *gs_journal_subs = NULL;
static axlHash *gs_audit_subs = NULL;
static axlHash *gs_log_subs = NULL;
static int exiting = 0;

static void usage();
static int process_options(int argc, char **argv);
static enum jald_status config_load(config_t *config, char *config_path);
static void init_global_config(void);
static void free_global_config(void);
static void free_global_args(void);
static axl_bool print_peer_cfg(axlPointer key, axlPointer data, axlPointer user_data);
static void print_record_types(enum jaln_record_type rtype);
static void print_config(void);
static enum jald_status set_global_config(config_t *config);
static enum jald_status handle_allow_mask(config_setting_t *parent, config_setting_t *list, const char *cfg_key, enum jaln_record_type *mask);
static enum jal_status pub_get_bytes(const uint64_t offset, uint8_t * const buffer, uint64_t *size, void *feeder_data);

enum jaln_connect_error on_connect_request(
		const struct jaln_connect_request *req,
		__attribute__((unused)) int *selected_encoding,
		__attribute__((unused)) int *selected_digest,
		__attribute__((unused)) void *user_data)
{
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
	ctx->journal_fd = -1;
	enum jaldb_status jaldb_ret = JALDB_E_INVAL;
	size_t sys_meta_len = 0;
	size_t app_meta_len = 0;
	size_t payload_len = 0;
	jaldb_ret = jaldb_lookup_journal_record(db_ctx, record_info->serial_id, system_metadata_buffer, &sys_meta_len,
				application_metadata_buffer, &app_meta_len,
				&(ctx->journal_fd), &payload_len);
	if (JALDB_OK != jaldb_ret) {
		return JAL_E_INVAL;
	}
	record_info->app_meta_len = (uint64_t) app_meta_len;
	record_info->sys_meta_len = (uint64_t) sys_meta_len;
	record_info->payload_len = (uint64_t) payload_len;
	return JAL_OK;
}

enum jal_status pub_on_subscribe(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *serial_id,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Subscribe message, serial ID is: %s\n", serial_id);
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
	if (ctx) {
		// The library should prevent this from happening, but just in case.
		DEBUG_LOG_SUB_SESSION(ch_info, "Subscribe exists, rejecting subscribe request");
		pthread_mutex_unlock(sub_lock);
		return JAL_E_INVAL;
	}
	ctx = (struct session_ctx_t*) calloc(1, sizeof(*ctx));
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed to allocate context");
		pthread_mutex_unlock(sub_lock);
		return JAL_E_NO_MEM;
	}
	ctx->journal_fd = -1;
	DEBUG_LOG_SUB_SESSION(ch_info, "Inserting new session");
	axl_hash_insert_full(hash, strdup(ch_info->hostname), free, ctx, free);
	pthread_mutex_unlock(sub_lock);
	return JAL_OK;
}

enum jal_status pub_get_next_record_info_and_metadata(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *last_serial_id,
		struct jaln_record_info *record_info,
		uint8_t **system_metadata_buffer,
		uint8_t **application_metadata_buffer,
		__attribute__((unused)) void *user_data)
{

	char *next_sid = NULL;
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
		DEBUG_LOG_SUB_SESSION(ch_info, "Illegal record type");
		return JAL_E_INVAL;
	}
	DEBUG_LOG_SUB_SESSION(ch_info, "Retrieving next record, last serial ID was %s\n", last_serial_id);
	pthread_mutex_lock(sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*)axl_hash_get(hash, ch_info->hostname);
	pthread_mutex_unlock(sub_lock);
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session");
		return JAL_E_INVAL;
	}
	enum jaldb_status jaldb_ret = JALDB_E_INVAL;
	int db_err = 0;
	size_t sys_meta_len = 0;
	size_t app_meta_len = 0;
	size_t payload_len = 0;
	jaldb_ret = JALDB_E_NOT_FOUND;
	while(JALDB_E_NOT_FOUND == jaldb_ret) {
		switch(type) {
		case JALN_RTYPE_JOURNAL:
			jaldb_ret = jaldb_next_journal_record(db_ctx, last_serial_id, &next_sid, system_metadata_buffer, &sys_meta_len,
					application_metadata_buffer, &app_meta_len,
					&(ctx->journal_fd), &payload_len);
			break;
		case JALN_RTYPE_AUDIT:
			jaldb_ret = jaldb_next_audit_record(db_ctx, last_serial_id, &next_sid, system_metadata_buffer, &sys_meta_len,
					application_metadata_buffer, &app_meta_len,
					&(ctx->payload_buf), &payload_len);
			break;
		case JALN_RTYPE_LOG:
			jaldb_ret = jaldb_next_log_record(db_ctx, last_serial_id, &next_sid, system_metadata_buffer, &sys_meta_len,
					application_metadata_buffer, &app_meta_len,
					&(ctx->payload_buf), &payload_len, &db_err);
			break;
		}
		if (JALDB_E_NOT_FOUND == jaldb_ret) {
			if (JAL_OK != jaln_session_is_ok(sess)) {
				return JAL_E_INVAL;
			}
			sleep(ONE_MINUTE);
		}
	}
	if (JALDB_OK != jaldb_ret) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed to get next record");
		return JAL_E_INVAL;
	}

	DEBUG_LOG_SUB_SESSION(ch_info, "Next record %s", next_sid);
	record_info->serial_id = next_sid;
	record_info->app_meta_len = (uint64_t) app_meta_len;
	record_info->sys_meta_len = (uint64_t) sys_meta_len;
	record_info->payload_len = (uint64_t) payload_len;

	return JAL_OK;
}

enum jal_status pub_release_metadata_buffers(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		uint8_t *system_metadata_buffer,
		uint8_t *application_metadata_buffer,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Release metadata buffers for %s", serial_id);
	free(system_metadata_buffer);
	free(application_metadata_buffer);
	return JAL_OK;
}

enum jal_status pub_acquire_log_data(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		uint8_t **buffer,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Getting log data for %s", serial_id);
	pthread_mutex_lock(&gs_log_sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*) axl_hash_get(gs_log_subs, ch_info->hostname);
	pthread_mutex_unlock(&gs_log_sub_lock);
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		return JAL_E_INVAL;
	}
	*buffer = ctx->payload_buf;
	return JAL_OK;
}

enum jal_status pub_release_log_data(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		uint8_t *buffer,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Release log data for %s", serial_id);
	free(buffer);
	pthread_mutex_lock(&gs_log_sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*) axl_hash_get(gs_log_subs, ch_info->hostname);
	pthread_mutex_unlock(&gs_log_sub_lock);
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		return JAL_E_INVAL;
	}
	ctx->payload_buf = NULL;
	return JAL_OK;
}

enum jal_status pub_acquire_audit_data(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		uint8_t **buffer,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Acquiring audit data for %s\n", serial_id);
	pthread_mutex_lock(&gs_audit_sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*) axl_hash_get(gs_audit_subs, ch_info->hostname);
	pthread_mutex_unlock(&gs_audit_sub_lock);
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		return JAL_E_INVAL;
	}
	*buffer = ctx->payload_buf;
	return JAL_OK;
}

enum jal_status pub_release_audit_data(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		uint8_t *buffer,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Release audit data for %s\n", serial_id);
	free(buffer);
	pthread_mutex_lock(&gs_audit_sub_lock);
	struct session_ctx_t *ctx = (struct session_ctx_t*) axl_hash_get(gs_audit_subs, ch_info->hostname);
	pthread_mutex_unlock(&gs_audit_sub_lock);
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		return JAL_E_INVAL;
	}
	ctx->payload_buf = NULL;
	return JAL_OK;
}

enum jal_status pub_acquire_journal_feeder(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Acquire journal feeder for %s\n", serial_id);
	pthread_mutex_lock(&gs_journal_sub_lock);
	struct session_ctx_t*ctx = (struct session_ctx_t*) axl_hash_get(gs_journal_subs, ch_info->hostname);
	pthread_mutex_unlock(&gs_journal_sub_lock);
	if (!ctx) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Couldn't find session context");
		return JAL_E_INVAL;
	}
	feeder->feeder_data = ctx;
	feeder->get_bytes = pub_get_bytes;
	return JAL_OK;
}

enum jal_status pub_release_journal_feeder(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		const char *serial_id,
		struct jaln_payload_feeder *feeder,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "Release journal feeder for %s\n", serial_id);
	struct session_ctx_t *ctx = (struct session_ctx_t*) feeder->feeder_data;
	close(ctx->journal_fd);
	ctx->journal_fd = -1;
	return JAL_OK;
}

enum jal_status pub_on_record_complete(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		char *serial_id,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "On record complete: %s", serial_id);
	// callback is informational, do nothing.
	return JAL_OK;
}

void pub_sync(
		__attribute__((unused)) jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *serial_id,
		__attribute__((unused)) struct jaln_mime_header *headers,
		__attribute__((unused)) void *user_data)
{
	DEBUG_LOG_SUB_SESSION(ch_info, "sync: %s", serial_id);
	switch (type) {
	case JALN_RTYPE_JOURNAL:
		jaldb_mark_journal_synced(db_ctx, ch_info->hostname, serial_id);
		break;
	case JALN_RTYPE_AUDIT:
		jaldb_mark_audit_synced(db_ctx, ch_info->hostname, serial_id);
		break;
	case JALN_RTYPE_LOG:
		jaldb_mark_log_synced(db_ctx, ch_info->hostname, serial_id);
		break;
	}
}

void pub_notify_digest(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		__attribute__((unused)) enum jaln_record_type type,
		__attribute__((unused)) const char *serial_id,
		__attribute__((unused)) const uint8_t *digest,
		__attribute__((unused)) const uint32_t size,
		__attribute__((unused)) void *user_data)
{
	char *b64 = jal_base64_enc(digest, size);
	DEBUG_LOG_SUB_SESSION(ch_info, "Digest for %s: %s", serial_id, b64);
	free(b64);
}

void pub_peer_digest(
		__attribute__((unused)) jaln_session *sess,
		__attribute__((unused)) const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *serial_id,
		const uint8_t *local_digest,
		const uint32_t local_size,
		const uint8_t *peer_digest,
		const uint32_t peer_size,
		__attribute__((unused)) void *user_data)
{
	if (!local_digest || !peer_digest) {
		DEBUG_LOG_SUB_SESSION(ch_info, "missing peer or local digset");
	}
	if ((0 == local_size) || (0 == peer_size) || (local_size != peer_size)) {
		DEBUG_LOG_SUB_SESSION(ch_info, "local digest and peer digest have different lengths");
		return;
	}
	if (0 != memcmp(local_digest, peer_digest, local_size)) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Local digest and peer digest do not match");
		return;
	}
	enum jaldb_status jaldb_ret = JALDB_E_INVAL;
	switch(type) {
	case JALN_RTYPE_JOURNAL:
		jaldb_ret = jaldb_mark_journal_sent_ok(db_ctx, serial_id, ch_info->hostname);
		break;
	case JALN_RTYPE_AUDIT:
		jaldb_ret = jaldb_mark_audit_sent_ok(db_ctx, serial_id, ch_info->hostname);
		break;
	case JALN_RTYPE_LOG:
		jaldb_ret = jaldb_mark_log_sent_ok(db_ctx, serial_id, ch_info->hostname);
		break;
	default:
		return;
	}
	if (JALDB_OK != jaldb_ret) {
		DEBUG_LOG_SUB_SESSION(ch_info, "Failed to mark %s as sent", serial_id);
	} else {
		DEBUG_LOG_SUB_SESSION(ch_info, "Mark %s as sent", serial_id);
	}
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
	std::stringstream ss(std::ios_base::out);

	rc = setup_signals();
	if (0 != rc) {
		goto out;
	}

	if (process_options(argc, argv) == VERSION_CALLED) {
		goto version_out;
	}

	DEBUG_LOG("Config Path: %s\tDebug: %d\n", global_args.config_path, global_args.debug_flag);

	if (!global_args.config_path) {
		rc = JALD_E_CONFIG_LOAD;
		goto out;
	}

	rc = config_load(&config, global_args.config_path);
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
		jalu_daemonize();
	}

	rc = setup_db_layer();
	if (rc != JALD_OK) {
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
	pub_cbs->get_next_record_info_and_metadata = pub_get_next_record_info_and_metadata;
	pub_cbs->release_metadata_buffers = pub_release_metadata_buffers;
	pub_cbs->acquire_log_data = pub_acquire_log_data;
	pub_cbs->release_log_data = pub_release_log_data;
	pub_cbs->acquire_audit_data = pub_acquire_audit_data;
	pub_cbs->release_audit_data = pub_release_audit_data;
	pub_cbs->acquire_journal_feeder = pub_acquire_journal_feeder;
	pub_cbs->release_journal_feeder = pub_release_journal_feeder;
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
	if (JAL_OK != jaln_register_encoding(jctx, "xml")) {
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
	jaln_ret = jaln_register_tls(jctx, global_config.private_key, global_config.public_cert,
			global_config.remote_cert_dir);
	if (JAL_OK != jaln_ret) {
		DEBUG_LOG("Failed to register TLS");
		rc = -1;
		goto out;
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

	while (!exiting) {
		sleep(60);
	}

out:
	free_global_config();
	free_global_args();
	teardown_db_layer();
	pthread_mutex_destroy(&gs_journal_sub_lock);
	pthread_mutex_destroy(&gs_audit_sub_lock);
	pthread_mutex_destroy(&gs_log_sub_lock);
	jaln_context_destroy(&jctx);
	config_destroy(&config);

	return rc;

version_out:
	config_destroy(&config);
	return 0;
}

int process_options(int argc, char **argv)
{
	int opt = 0;
	int long_index = 0;

	static const char *opt_string = "c:d:v";
	static const struct option long_options[] = {
		{"config", required_argument, NULL, 'c'}, /* --config or -c */
		{"debug", no_argument, NULL, 'd'}, /* --debug or -d */
		{"no-daemon", no_argument, &global_args.daemon, 0}, /* --no-daemon */
		{"version", no_argument, NULL, 'v'}, /* --version or -v */
		{0, 0, 0, 0} /* terminating -0 item */
	};

	global_args.daemon = true;
	global_args.debug_flag = false;
	global_args.config_path = NULL;

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
	fprintf(stderr, "Usage: jald -c, --config <config_file> [-d, --debug] [-v, --version] [--no-daemon]\n");
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
		printf("Failed to load config file: %s!\n", config_path);
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
	printf("PRIVATE KEY:\t\t%s\n", global_config.private_key);
	printf("PUBLIC CERT:\t\t%s\n", global_config.public_cert);
	printf("REMOTE CERT DIR:\t\t%s\n", global_config.remote_cert_dir);
	printf("PORT:\t\t\t%lld\n", global_config.port);
	printf("HOST:\t\t\t%s\n", global_config.host);
	printf("PENDING DIGEST MAX:\t%lld\n", global_config.pending_digest_max);
	printf("PENDING DIGEST TIMEOUT:\t%lld\n", global_config.pending_digest_timeout);
	printf("DB ROOT:\t\t%s\n", global_config.db_root);
	printf("SCHEMAS ROOT:\t\t%s\n", global_config.schemas_root);
	printf("PEERS\n%15s | %18s | %18s", "HOST", "PUBLISH_ALLOW", "SUBSCRIBE_ALLOW");
	axl_hash_foreach(global_config.peers, print_peer_cfg, NULL);
	printf("\n===\nEND CONFIG VALUES:\n===\n");
}

enum jald_status set_global_config(config_t *config)
{
	int rc;
	char *ret = NULL;
	char absolute_private_key[PATH_MAX];
	char absolute_public_cert[PATH_MAX];
	char absolute_remote_cert_dir[PATH_MAX];
	char absolute_db_root[PATH_MAX];
	char absolute_schemas_root[PATH_MAX];

	if (!config) {
		return JALD_E_CONFIG_LOAD;
	}
	config_setting_t *root = config_root_setting(config);
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
	rc = jalu_config_lookup_string(root, JALNS_REMOTE_CERT_DIR, &global_config.remote_cert_dir, true);
	if (0 != rc) {
		return JALD_E_CONFIG_LOAD;
	}
	ret = realpath(global_config.remote_cert_dir, absolute_remote_cert_dir);
	if (!ret) {
		printf("Failed to convert path \"%s\" for key \"%s\" to absolute path\n", global_config.remote_cert_dir, JALNS_REMOTE_CERT_DIR);
		return JALD_E_CONFIG_LOAD;
	}
	free(global_config.remote_cert_dir);
	global_config.remote_cert_dir = strdup(absolute_remote_cert_dir);
	rc = config_setting_lookup_int64(root, JALNS_PORT, &global_config.port);
	if (CONFIG_FALSE == rc) {
		CONFIG_ERROR(root, JALNS_PORT, "expected int64 value");
		return JALD_E_CONFIG_LOAD;
	}
	rc = jalu_config_lookup_string(root, JALNS_HOST, &global_config.host, true);
	if (0 != rc) {
		CONFIG_ERROR(root, JALNS_HOST, "expected string value");
		return JALD_E_CONFIG_LOAD;
	}
	rc = config_setting_lookup_int64(root, JALNS_PENDING_DIGEST_MAX, &global_config.pending_digest_max);
	if (CONFIG_FALSE == rc) {
		CONFIG_ERROR(root, JALNS_PENDING_DIGEST_MAX, "expected integer value");
		return JALD_E_CONFIG_LOAD;
	}
	rc = config_setting_lookup_int64(root, JALNS_PENDING_DIGEST_TIMEOUT, &global_config.pending_digest_timeout);
	if (CONFIG_FALSE == rc) {
		CONFIG_ERROR(root, JALNS_PENDING_DIGEST_TIMEOUT, "expected integer value");
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
	if (NULL == peers) {
		CONFIG_ERROR(root, JALNS_PEERS, "expected non-empty list");
		return JALD_E_CONFIG_LOAD;
	}
	if (!config_setting_is_list(peers)) {
		CONFIG_ERROR(peers, JALNS_PEERS, "expected non-empty list");
		return JALD_E_CONFIG_LOAD;
	}
	int peer_len = config_setting_length(peers);
	if (0 >= peer_len) {
		CONFIG_ERROR(peers, JALNS_PEERS, "expected non-empty list");
		return JALD_E_CONFIG_LOAD;
	}
	for (unsigned i = 0; i < (unsigned) peer_len; i++) {
		enum jaln_record_type sub_mask = (enum jaln_record_type) 0;
		enum jaln_record_type pub_mask = (enum jaln_record_type) 0;
		config_setting_t *a_peer = config_setting_get_elem(peers, i);
		if (!config_setting_is_group(a_peer)) {
			CONFIG_ERROR(a_peer, JALNS_PEERS, " expected group for %s[%u]", JALNS_PEERS, i);
			return JALD_E_CONFIG_LOAD;
		}

		config_setting_t *list = config_setting_get_member(a_peer, JALNS_PUBLISH_ALLOW);
		if (JALD_E_CONFIG_LOAD == handle_allow_mask(a_peer, list, JALNS_PUBLISH_ALLOW, &pub_mask)) {
			return JALD_E_CONFIG_LOAD;
		}

		list = config_setting_get_member(a_peer, JALNS_SUBSCRIBE_ALLOW);
		if (JALD_E_CONFIG_LOAD == handle_allow_mask(a_peer, list, JALNS_SUBSCRIBE_ALLOW, &sub_mask)) {
			return JALD_E_CONFIG_LOAD;
		}

		list = config_setting_get_member(a_peer, JALNS_HOSTS);
		if (!list) {
			CONFIG_ERROR(a_peer, JALNS_HOSTS, "expected non-empty list");
			return JALD_E_CONFIG_LOAD;
		}
		if (!config_setting_is_list(list)) {
			CONFIG_ERROR(list, JALNS_HOSTS, "expected non-empty list");
			return JALD_E_CONFIG_LOAD;
		}
		int host_len = config_setting_length(list);
		if (0 >= host_len) {
			CONFIG_ERROR(list, JALNS_HOSTS, "expected non-empty list");
			return JALD_E_CONFIG_LOAD;
		}
		for (unsigned host_idx = 0; host_idx < (unsigned) host_len; host_idx++) {
			config_setting_t *cfg_host = config_setting_get_elem(list, host_idx);
			if (CONFIG_TYPE_STRING != config_setting_type(cfg_host)) {
				CONFIG_ERROR(list, JALNS_HOSTS, "Expected non-empty string for %s[%u]", JALNS_HOSTS, host_idx);
				return JALD_E_CONFIG_LOAD;
			}
			const char *host_str = config_setting_get_string(cfg_host);
			if (!host_str) {
				CONFIG_ERROR(list, JALNS_HOSTS, "Expected non-empty string for %s[%u]", JALNS_HOSTS, host_idx);
				return JALD_E_CONFIG_LOAD;
			}
			char *key = strdup(host_str);
			struct peer_config_t *peer_cfg = (struct peer_config_t*) axl_hash_get(global_config.peers, key);
			if (!peer_cfg) {
				printf("cfg for %s, creating struct\n", host_str);
				peer_cfg = (struct peer_config_t*) calloc(1, sizeof(*peer_cfg));
				if (!peer_cfg) {
					return JALD_E_NOMEM;
				}
				if (!key) {
					return JALD_E_CONFIG_LOAD;
				}
				axl_hash_insert_full(global_config.peers, key, free, peer_cfg, free);
			} else {
				free(key);
			}
			DEBUG_LOG("cfg for %s, adding %d for pub and %d for sub\n", host_str, pub_mask, sub_mask);
			DEBUG_LOG("cfg for %s, was %d for pub and %d for sub\n", host_str, peer_cfg->pub_allow, peer_cfg->sub_allow);
			peer_cfg->pub_allow = (enum jaln_record_type) (peer_cfg->pub_allow | pub_mask);
			peer_cfg->sub_allow = (enum jaln_record_type) (peer_cfg->sub_allow | sub_mask);
		}
	}
	return JALD_OK;
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

	int len = config_setting_length(list);
	for (unsigned i = 0; i < (unsigned) len; i++) {
		config_setting_t *item = config_setting_get_elem(list, i);
		if (CONFIG_TYPE_STRING != config_setting_type(item)) {
			CONFIG_ERROR(list, cfg_key, "Expected non-empty string for %s[%u]", cfg_key, i);
			return JALD_E_CONFIG_LOAD;
		}
		const char *type = config_setting_get_string(item);
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
	}
	return JALD_OK;
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
#define ERRNO_STR_LEN 128
	off64_t err;
	struct session_ctx_t *ctx = (struct session_ctx_t*) feeder_data;
	errno = 0;
	err = lseek64(ctx->journal_fd, offset, SEEK_SET);
	int my_errno = errno;
	if (-1 == err) {
		char buf[ERRNO_STR_LEN];
		strerror_r(my_errno, buf, ERRNO_STR_LEN);
		DEBUG_LOG("Failed to seek, errno %s\n", buf);
		return JAL_E_INVAL;
	}
	size_t to_read = *size;
	ssize_t bytes_read = read(ctx->journal_fd, buffer, to_read);
	if (bytes_read < 0) {
		return JAL_E_INVAL;
	}
	*size = bytes_read;
	return JAL_OK;
}
