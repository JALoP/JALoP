/**
 * @file
 *
 * @brief This file contains the implementation for jald-specific configuration
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

#include <pthread.h>
#include <libconfig.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <jalop/jaln_network.h>
#include <jaldb_config.h>
#include "jald_config.hpp"
#include "jal_config.h"
#include "jal_config_cpp.hpp"
#include "jald_common_definitions.hpp"
#include "jalns_strings.h"

extern global_args_t global_args;

// Forward declaration of file-static funcitons
static void print_peer_cfg(const std::string host, const PeerConfig& peer_cfg);
static std::map<std::string, PeerConfig> parse_peer_configs(config_setting_t *root);
static enum jaln_record_type handle_allow_mask(
	config_setting_t *parent,
	config_setting_t *list,
	const char *cfg_key);
static std::string get_ipv4(std::string hostname);
static void print_record_types(enum jaln_record_type rtype);

// Empty Constructor to allow allocation of global default value
JaldConfig::JaldConfig(){}

JaldConfig::JaldConfig(const char* config_path) {
	// Load config file as config_t object
	config_t config;
	if(JAL_CFG_SUCCESS != jal_config_init(&config)) {
		// Error printed to stderr internally
		throw std::runtime_error("Failed to initialize config object.");
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
		// Error printed to stderr internally
		std::string msg = std::string("Failed to read config file: ") + std::string(config_path);
		throw std::runtime_error(msg);
	}

	// Extract root configuration setting
	config_setting_t *root = config_root_setting(&config);

	if(global_args.enable_tls) {
		// Extract the private key
		private_key = jal_config_lookup_cpp_path(root, JALNS_PRIVATE_KEY, JAL_CFG_REQUIRED, "");
		// Extract the public cert
		public_cert = jal_config_lookup_cpp_path(root, JALNS_PUBLIC_CERT, JAL_CFG_REQUIRED, "");
		// Extract the remote cert dir
		remote_cert_dir = jal_config_lookup_cpp_path(root, JALNS_REMOTE_CERT_DIR, JAL_CFG_REQUIRED, "");
	}

	// Extract db_root - optional
	db_root = jal_config_lookup_cpp_path(root, JALNS_DB_ROOT, JAL_CFG_OPTIONAL, "/var/log/jalop");

	// Extract port
	port = jal_config_lookup_cpp_int64(root, JALNS_PORT, JAL_CFG_REQUIRED, 0);

	// Extract host
	host = jal_config_lookup_cpp_string(root, JALNS_HOST, JAL_CFG_REQUIRED, {});

	// Extract poll time
	poll_time = jal_config_lookup_cpp_int64(root, JALNS_POLL_TIME, JAL_CFG_REQUIRED, 0);

	// Additionally require poll time to be a positive integer
	if (poll_time <= 0) {
		std::string msg = config_error_context(root, JALNS_POLL_TIME)
			+ std::string(" expected positive integer value");
		throw std::runtime_error(msg);
	}

	// Extract pid_file - optional, file not expected to exist yet
	pid_file = jal_config_lookup_cpp_file_path(root, JALNS_PID_FILE, JAL_CFG_OPTIONAL, {}, false);

	// Extract log_dir path - optional
	log_dir = jal_config_lookup_cpp_path(root, JALNS_LOG_DIR, JAL_CFG_OPTIONAL, {});

	// Extract filter_socket_basename if the filter is in use
	if(global_args.use_filter){
		filter_socket_basename = jal_config_lookup_cpp_file_path(root, JALNS_FILTER_SOCKET_BASENAME, JAL_CFG_REQUIRED, {}, false);
	}

	// Extract digest_algorithm - optional
	digest_algorithms = jal_config_lookup_cpp_string(root, JALNS_DIGEST_ALGORITHMS, JAL_CFG_OPTIONAL, {});

	//Attempts to load optional LMDB_CONFIG file in db_root
	//If present, this will override the lmdb performance level
	//and lmdb map size, otherwise default values will be used.
	jaldb_config *jdb_config = NULL;
	enum jaldb_config_status jcs = get_jaldb_config(db_root.c_str(), &jdb_config);
	if (jcs != JALDB_CONFIG_OK && jcs != JALDB_CONFIG_E_NOTFOUND) {
		std::string msg = std::string("Failued to load db config file from directory: ") + db_root;
		throw std::runtime_error(msg);
	}

	if (jcs != JALDB_CONFIG_E_NOTFOUND)
	{
		//Only override map size if present in config
		if (jdb_config->map_size != 0)
		{
			map_size = jdb_config->map_size;
		}

		//Only override database option if present in config
		if (NULL != jdb_config->database_option)
		{
			jdb_flags = jdb_config->jdb_flags;
			database_option = std::string(jdb_config->database_option);
		}
		free_jaldb_config(&jdb_config);
	}

	peers = parse_peer_configs(root);
}



void JaldConfig::print_config() {
	printf("\n===\nBEGIN CONFIG VALUES:\n===\n");
	if(global_args.debug_flag) {
		printf("DEBUG:\t\tenabled\n");
	} else {
		printf("DEBUG:\t\tdisabled\n");
	}
	if (global_args.enable_tls) {
		printf("PRIVATE KEY:\t\t%s\n", private_key.c_str());
		printf("PUBLIC CERT:\t\t%s\n", public_cert.c_str());
		printf("REMOTE CERT DIR:\t\t%s\n", remote_cert_dir.c_str());
	} else {
		printf("!!!!!!!! TLS DISABLED !!!!!!!!\n");
	}
	printf("PORT:\t\t\t%lld\n", port);
	printf("HOST:\t\t\t%s\n", host.c_str());
	printf("POLL TIME:\t%lld\n", poll_time);
	printf("DB ROOT:\t\t%s\n", db_root.c_str());
	if (!pid_file.empty()) {
		printf("PID FILE:\t\t%s\n", pid_file.c_str());
	}
	if (!log_dir.empty()) {
		printf("LOG DIRECTORY:\t\t%s\n", log_dir.c_str());
	}
	if (!digest_algorithms.empty()) {
		printf("DIGEST ALGORITHMS:\t%s\n", digest_algorithms.c_str());
	}

	if (global_args.use_filter || global_args.use_filter) {
		printf("FILTER SOCKET:\t\t%s\n", filter_socket_basename.c_str());
	}

	if(!database_option.empty()) {
		printf("DATABASE_OPTION:\t%s\n", database_option.c_str());
	}
	printf("LMDB_MAP_SIZE (GB):\t%d\n", map_size);
	printf("PEERS\n%15s | %18s | %18s\n", "HOST", "PUBLISH_ALLOW", "SUBSCRIBE_ALLOW");
	for(const auto& [host_key, cfg] : peers) {
		print_peer_cfg(host_key, cfg);
	}
	printf("\n===\nEND CONFIG VALUES:\n===\n");
}

static void print_record_types(enum jaln_record_type rtype)
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

static void print_peer_cfg(const std::string host, const PeerConfig& peer_cfg)
{
	printf("\n%15s | ", host.c_str());
	print_record_types(peer_cfg.pub_allow);
	printf(" | ");
	print_record_types(peer_cfg.sub_allow);
}

static std::map<std::string, PeerConfig> parse_peer_configs(config_setting_t *root)
{
	// Extract the "peers" element
	std::map<std::string, PeerConfig> peer_configs;
	config_setting_t *peers;
	int peer_len;
	if(JAL_CFG_SUCCESS != jal_config_lookup_list(root, JALNS_PEERS, &peers, &peer_len, JAL_CFG_REQUIRED)) {
		throw std::runtime_error("Failed to extract peers list");
	}

	// For each item in the peers list...
	for (unsigned i = 0; i < (unsigned) peer_len; i++) {
		// Extract the peer sub-element
		config_setting_t *a_peer = NULL;

		if (JAL_CFG_SUCCESS != jal_config_get_elem_group(peers, i, &a_peer, JALNS_PEERS)) {
			throw std::runtime_error("Failed to extract item from peer list");
		}

		// Extract each item from the list of "allow" values
		config_setting_t *list = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_member(a_peer, JALNS_PUBLISH_ALLOW, &list, JAL_CFG_OPTIONAL)) {
			throw std::runtime_error("Failed to extract publish allow list from peer");
		}
		enum jaln_record_type pub_mask = handle_allow_mask(a_peer, list, JALNS_PUBLISH_ALLOW);

		list = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_member(a_peer, JALNS_SUBSCRIBE_ALLOW, &list, JAL_CFG_OPTIONAL)) {
			throw std::runtime_error("Failed to extract subscribe allow list from peer");
		}
		// sub_mask is typically not used anymore
		enum jaln_record_type sub_mask = handle_allow_mask(a_peer, list, JALNS_SUBSCRIBE_ALLOW);

		list = NULL;
		int host_len;
		if(JAL_CFG_SUCCESS != jal_config_lookup_list(a_peer, JALNS_HOSTS, &list, &host_len, JAL_CFG_REQUIRED)) {
			throw std::runtime_error("Failed to extract hosts list from peer");
		}

		// Extract each host from the host list for this peer
		for (unsigned host_idx = 0; host_idx < (unsigned) host_len; host_idx++) {
			char *c_key = NULL;
			if(JAL_CFG_SUCCESS != jal_config_get_elem_string(list, host_idx, &c_key, JALNS_HOSTS)) {
				free(c_key);
				throw std::runtime_error("Failed to extract host from hosts list");
			}
			std::string key = std::string(c_key);
			free(c_key);

			std::string keystr = get_ipv4(key.c_str());
			if (keystr.empty()){
				std::string errMsg = std::string("Unable to resolve host entry: ") + key;
				throw std::runtime_error(errMsg);
			}

			auto it = peer_configs.find(keystr);

			if (peer_configs.end() == it) {
				printf("cfg for %s, creating struct\n", key.c_str());
				PeerConfig peer_cfg;

				peer_cfg.pub_allow = (enum jaln_record_type) pub_mask;
				peer_cfg.sub_allow = (enum jaln_record_type) sub_mask;

				DEBUG_LOG("cfg for %s, adding %d for pub and %d for sub\n", key.c_str(), pub_mask, sub_mask);
				DEBUG_LOG("cfg for %s, was %d for pub and %d for sub\n", key.c_str(), peer_cfg.pub_allow, peer_cfg.sub_allow);

				peer_configs.insert({keystr, peer_cfg});
			} else {
				std::string errMsg = std::string("Duplicate host found in peers: ") + keystr;
				printf("%s\n", errMsg.c_str());
				throw std::runtime_error(errMsg);
			}
		}
	}
	return peer_configs;
}

static enum jaln_record_type handle_allow_mask(config_setting_t *parent, config_setting_t *list, const char *cfg_key) {
	// the allow masks are both optional, so just return none.
	if (!list) {
		return (enum jaln_record_type)0;
	}

	if (!config_setting_is_list(list)) {
		CONFIG_ERROR(parent, cfg_key, "expected non-empty list");
		throw std::runtime_error("handle_allow_mask invoked with non-list config item.");
	}

	int len = config_setting_length(list);
	enum jaln_record_type mask = (enum jaln_record_type)0;
	for (unsigned i = 0; i < (unsigned) len; i++) {
		char *type = NULL;
		jal_config_get_elem_string(list, i, &type, "");
		if(NULL == type) {
			throw std::runtime_error("handle_allow_mask failed to extract type value from list.");
		}
		if (0 == strcmp(type, JALNS_JOURNAL)) {
			mask = (jaln_record_type) (mask | JALN_RTYPE_JOURNAL);
		} else if (0 == strcmp(type, JALNS_AUDIT)) {
			mask = (jaln_record_type) (mask | JALN_RTYPE_AUDIT);
		} else if (0 == strcmp(type, JALNS_LOG)) {
			mask = (jaln_record_type) (mask | JALN_RTYPE_LOG);
		} else {
			CONFIG_ERROR(list, cfg_key, "'%s' not one of {'%s', '%s', '%s'}", type, JALNS_JOURNAL, JALNS_AUDIT, JALNS_LOG);
			throw std::runtime_error("handle_allow_mask failed to interpret mask value.");
		}

		free(type);
	}
	return mask;
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
