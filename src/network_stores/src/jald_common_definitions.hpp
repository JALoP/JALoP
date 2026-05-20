/**
 * @file
 *
 * @brief This file contains the definitions for jald-specific types used in multiple
 * of the jald files.
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
#pragma once

#include <string>
#include <pthread.h>

#include "jaldb_context.hpp"

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


struct global_args_t {
	int daemon;     /* --no-daemon option */
	bool debug_flag;    /* --debug option */
	char *config_path;  /* --config option */
	char *pid_path;     /* --pid option */
	bool enable_tls;    /* --disable_tls option */
	bool use_filter;    /* --use_filter */
	char *digest_algorithms; /* --digest-algorithms option */
};

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

	session_ctx_t(std::string hostname_param, uint16_t subscriber_token_param);

	~session_ctx_t();
};

// Convenience struct for select_channel return value
// Note: we're not shortening the type to SessionHostMap or SessionTokenMap
// using "using" because it's dangerous to put type alias's in header files, although
// in this case it probably wouldn't hurt anyone so long as only jald includes this file.
struct SessionMaps {
	// a.k.a. SessionHostMap
	std::map<std::string, std::shared_ptr<session_ctx_t>>& sessionHostMap;
	// a.k.a. SessionToken Map
	std::map<uint16_t, std::shared_ptr<session_ctx_t>>& sessionTokenMap;
	std::shared_ptr<pthread_mutex_t> mapLock;
};

SessionMaps select_channel(const enum jaln_record_type type);

jaldb_context_t* setup_db_layer(void);

__attribute__((noreturn))
void *pub_send(__attribute__((unused)) void *args);

std::string stringify_type(enum jaln_record_type type);
