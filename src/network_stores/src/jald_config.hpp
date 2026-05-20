/**
 * @file
 *
 * @brief This file contains the definitions for jald-specific configuration
 * file parsing and representation.
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
#include <map>

#include "jaldb_config.h"

struct PeerConfig {
	enum jaln_record_type pub_allow;
	enum jaln_record_type sub_allow;
};

struct JaldConfig {
	// Jald Settings
	std::string private_key;
	std::string public_cert;
	std::string remote_cert_dir;
	std::string db_root = "/var/log/jalop";
	long long port;
	std::string host;
	long long int poll_time = 0;
	std::string pid_file;
	std::string log_dir;
	std::string filter_socket_basename;
	std::string digest_algorithms;

	// LMDB settings
	int map_size = DEFAULT_LMDB_MAP_SIZE;
	jaldb_flags jdb_flags = JDB_LMDB_PERFORMANCE_LEVEL2;
	std::string database_option = std::string(JDB_LMDB_PERFORMANCE_LEVEL2_STR);

	// Peer settings
	int num_peers = 0;
	std::map<std::string, PeerConfig> peers;

	JaldConfig();
	JaldConfig(const char* config_path);
	void print_config();
};
