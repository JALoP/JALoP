/**
 * @file
 *
 * @brief This file contains the definitions for jald-specific configuration
 * file parsing and representation.
 *
 * ### LICENSE
 *
 * Copyright (C) 2025 Concurrent Technologies Corporation.
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
#include <array>
#include <vector>
#include <mutex>
#include <libconfig.h>
#include <jalop/jaln_network.h>
#include "jaldb_config.h"

struct PeerConfig {
	std::string host;
	long long int port = 0;
	std::string cert_dir;
	std::array<std::string, 2> dc_config;
	enum jaln_record_type record_types = (enum jaln_record_type)JALN_RTYPE_ALL;
	enum jaln_publish_mode mode = JALN_UNKNOWN_MODE;
	jaln_context *net_ctx = NULL;
	struct jaln_connection *conn = NULL;
	bool connected = false;
	long long int retries = 0;
	std::mutex peer_lock;

	// PeerConfig contains a mutex, so copying is dangerous
	// disallow copy constructor
	PeerConfig(const PeerConfig&) = delete;
	// disallow copy assignment
	PeerConfig& operator=(const PeerConfig&) = delete;
	// Constructor
	PeerConfig(config_setting_t* peer_element);
	// Destructor
	~PeerConfig();
	// Move assignment
	PeerConfig& operator=(PeerConfig&& s);
	// Move construction
	PeerConfig(PeerConfig&& s);
};

struct JaldConfig {
	std::string private_key;
	std::string public_cert;
	std::string db_root = "/var/log/jalop";
	std::string schemas_root;
	long long int poll_time = 0;
	long long int retry_interval = -1;
	std::string pub_id;
	long long int network_timeout = 0;
	int num_peers = 0;
	std::vector<PeerConfig> peers;
	std::string pid_file;
	std::string log_dir;
	std::string digest_algorithms;
	std::string database_option = std::string(JDB_LMDB_PERFORMANCE_LEVEL2_STR);
	jaldb_flags jdb_flags = JDB_LMDB_PERFORMANCE_LEVEL2;
	bool allow_self_signed_certs = false;
	int http_client_retry_count = 0;
	int http_client_retry_delay = 0;
	int map_size = DEFAULT_LMDB_MAP_SIZE;
	std::string filter_socket_basename;

	JaldConfig();
	JaldConfig(const char* config_path);
	void print_config();
};
