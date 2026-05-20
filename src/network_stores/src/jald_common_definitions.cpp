/**
 * @file
 *
 * @brief This file contains the implementations for jald-specific utilities used in multiple
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
#include <pthread.h>
#include <string>

#include <jalop/jaln_network_types.h>
#include "jald_common_definitions.hpp"
#include "jald_config.hpp"

// short hand for long map type names
using SessionHostMap = std::map<std::string, std::shared_ptr<session_ctx_t>>;
using SessionTokenMap = std::map<uint16_t, std::shared_ptr<session_ctx_t>>;

// lifetime globals from jald.cpp
extern std::map<enum jaln_record_type, SessionHostMap> sessionHostMaps;
extern std::map<enum jaln_record_type, std::shared_ptr<pthread_mutex_t>> mapLocks;
extern std::map<enum jaln_record_type, SessionTokenMap> sessionTokenMaps;
extern global_args_t global_args;
extern JaldConfig global_config;

session_ctx_t::session_ctx_t(std::string hostname_param, uint16_t subscriber_token_param) {
	this->hostname = hostname_param;
	this->subscriber_token = subscriber_token_param;
	pthread_mutex_init(&staging_data_lock, NULL);
}

session_ctx_t::~session_ctx_t() {
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

SessionMaps select_channel(const enum jaln_record_type type)
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

jaldb_context_t* setup_db_layer(void)
{
	enum jaldb_status jaldb_ret = JALDB_OK;
	jaldb_context_t* db_ctx = jaldb_context_create();
	if(global_args.use_filter){
		global_config.jdb_flags = JDB_READONLY;
	}
	jaldb_ret = jaldb_context_init(db_ctx, global_config.db_root.c_str(), global_config.jdb_flags, global_config.map_size);

	if (JALDB_OK != jaldb_ret) {
		jaldb_context_destroy(&db_ctx);
	}

	return db_ctx;
}

std::string stringify_type(enum jaln_record_type type) {
	switch(type) {
		case JALN_RTYPE_JOURNAL:
			return std::string("journal");
		case JALN_RTYPE_AUDIT:
			return std::string("audit");
		case JALN_RTYPE_LOG:
			return std::string("log");
	}
	return std::string("unknown type");
}
