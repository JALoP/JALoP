/**
 * @file
 *
 * @brief This file contains the implementation for jald-specific configuration
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

#include <pthread.h>
#include <libconfig.h>

#include <jalop/jaln_network.h>
#include <jaldb_config.h>
#include "jald_config.hpp"
#include "jal_config.h"
#include "jal_config_cpp.hpp"
#include "jald_common_definitions.hpp"
#include "jalns_strings.h"

extern global_args_t global_args;

// Forward declaration of file-static funcitons
static int parse_record_types(config_setting_t *peer);
static void print_peer_config(const PeerConfig& peer);
static int rtype_bit_from_str(const char *type);
static bool validate_dc_config_str(const char* str);
static std::array<std::string, 2> parse_dc_config(config_setting_t *peer);
static std::vector<PeerConfig> parse_peer_configs(config_setting_t *root);

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
	}

	// Extract poll time
	poll_time = jal_config_lookup_cpp_int64(root, JALNS_POLL_TIME, JAL_CFG_REQUIRED, 0);
	// Additionally require poll time to be a positive integer
	if (poll_time <= 0) {
		std::string msg = config_error_context(root, JALNS_POLL_TIME)
			+ std::string(" expected positive integer value");
		throw std::runtime_error(msg);
	}

	// Extract retry interval
	retry_interval = jal_config_lookup_cpp_int64(root, JALNS_RETRY_INTERVAL, JAL_CFG_REQUIRED, -1);
	// Additionaly require retry interval to be -1 or greater than 0
	if (0 == retry_interval || retry_interval < -1) {
		std::string msg = config_error_context(root, JALNS_RETRY_INTERVAL)
			+ std::string(" expected positive integer value or -1");
		throw std::runtime_error(msg);
	}

	// Extract network timeout
	network_timeout = jal_config_lookup_cpp_int64(root, JALNS_NETWORK_TIMEOUT, JAL_CFG_REQUIRED, 0);
	// Additionally require network timeout to be >= 0
	if (network_timeout < 0) {
		std::string msg = config_error_context(root, JALNS_NETWORK_TIMEOUT)
			+ std::string("expected positive integer value or 0");
		throw std::runtime_error(msg);
	}

	// Extract publisher ID
	pub_id = jal_config_lookup_cpp_string(root, JALNS_PUBLISHER_ID, JAL_CFG_REQUIRED, {});

	// Extract db_root - optional
	db_root = jal_config_lookup_cpp_path(root, JALNS_DB_ROOT, JAL_CFG_OPTIONAL, {});

	// Extract schemas_root - optional
	schemas_root = jal_config_lookup_cpp_path(root, JALNS_SCHEMAS_ROOT, JAL_CFG_OPTIONAL, {});

	// Extract pid_file - optional, file not expected to exist yet
	pid_file = jal_config_lookup_cpp_file_path(root, JALNS_PID_FILE, JAL_CFG_OPTIONAL, {}, false);

	// Extract log_dir path - optional
	log_dir = jal_config_lookup_cpp_path(root, JALNS_LOG_DIR, JAL_CFG_OPTIONAL, {});

	// Extract digest_algorithm - optional
	digest_algorithms = jal_config_lookup_cpp_string(root, JALNS_DIGEST_ALGORITHMS, JAL_CFG_OPTIONAL, {});

	// Extract allow_self_signed_certs - optional
	allow_self_signed_certs = jal_config_lookup_cpp_bool(root, JALNS_ALLOW_SELF_SIGNED_CERTS, JAL_CFG_OPTIONAL, false);

	// Extract http_client_retry_count - optional
	http_client_retry_count = jal_config_lookup_cpp_int(
		root,
		JALNS_HTTP_CLIENT_RETRY_COUNT,
		JAL_CFG_OPTIONAL,
		JALN_HTTP_CLIENT_RETRY_COUNT_DEFAULT);

	// Check http_client_retry_count is less than zero.
	if (http_client_retry_count < 0) {
		std::string msg = config_error_context(root, JALNS_HTTP_CLIENT_RETRY_COUNT)
			+ std::string("invalid value, less than zero.");
		throw std::runtime_error(msg);
	}

	// Extract filter_socket_basename if the filter is in use
	if(global_args.use_filter){
		filter_socket_basename = jal_config_lookup_cpp_file_path(root, JALNS_FILTER_SOCKET_BASENAME, JAL_CFG_REQUIRED, {}, false);
	}

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

	peers = std::move(parse_peer_configs(root));
}

void JaldConfig::print_config() {
	printf("\n===\nBEGIN CONFIG VALUES:\n===\n");
	if (global_args.enable_tls) {
		printf("PRIVATE KEY:\t\t%s\n", private_key.c_str());
		printf("PUBLIC CERT:\t\t%s\n", public_cert.c_str());

		printf("SELF SIGNED CERTS ALLOWED:");
		if (allow_self_signed_certs)
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
	printf("POLL TIME:\t\t%lld\n", poll_time);
	printf("RETRY INTERNVAL:\t%lld\n", retry_interval);
	printf("NETWORK TIMEOUT:\t%lld\n", network_timeout);
	printf("HTTP_CLIENT_RETRY_COUNT:\t%d\n", http_client_retry_count);
	printf("HTTP_CLIENT_RETRY_DELAY:\t%d\n", http_client_retry_delay);
	printf("DB ROOT:\t\t%s\n", db_root.c_str());
	printf("SCHEMAS ROOT:\t\t%s\n", schemas_root.c_str());
	if(!pid_file.empty()) {
		printf("PID FILE:\t\t%s\n", pid_file.c_str());
	}
	if(!log_dir.empty()) {
		printf("LOG DIRECTORY:\t\t%s\n", log_dir.c_str());
	}
	printf("PUBLISHER ID:\t\t%s\n", pub_id.c_str());
	if(!digest_algorithms.empty()) {
		printf("DIGEST ALGORITHMS:\t%s\n", digest_algorithms.c_str());
	} if (global_args.use_filter || global_args.use_filter) {
		printf("FILTER SOCKET:\t\t%s\n", filter_socket_basename.c_str());
	}

	if(!database_option.empty()) {
		printf("DATABASE_OPTION:\t%s\n", database_option.c_str());
	}

	printf("LMDB_MAP_SIZE (GB):\t%d\n", map_size);

	int i = 0;
	for (const PeerConfig& peer : peers) {
		printf("PEER[%d]:\n", i++);
		print_peer_config(peer);
	}
	printf("===\nEND CONFIG VALUES:\n===\n\n");
	(void)fflush(stdout);
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


static void print_peer_config(const PeerConfig& peer)
{
	printf("\tHOST:\t\t\t%s\n", peer.host.c_str());
	printf("\tPORT:\t\t\t%llu\n", peer.port);
	printf("\tCERT DIR:\t\t%s\n", peer.cert_dir.c_str());
	printf("\tDIGEST CHALLENGE:\t%s", peer.dc_config[0].c_str());
	if (!peer.dc_config[1].empty()) {
		printf(", %s\n", peer.dc_config[1].c_str());
	} else {
		putchar('\n');
	}
	printf("\tMODE:\t\t\t%s\n", peer.mode == JALN_ARCHIVE_MODE? "archive" : "live");
	printf("\tRECORD TYPES:\t\t");
	print_record_types(peer.record_types);
	putchar('\n');
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
			std::string msg = config_error_context(peer, JALNS_RECORD_TYPES)
				+ std::string("Failed to get record types list.");
			throw std::runtime_error(msg);
	}

	if (CONFIG_FALSE == config_setting_is_array(node)
		&& CONFIG_FALSE == config_setting_is_list(node)) {
		// Using the libconfig API directly here since we have already extracted
		// the node and just need to get the string value
		const char* element = config_setting_get_string(node);
		if(NULL == element) {
			std::string msg = config_error_context(peer, JALNS_RECORD_TYPES)
				+ std::string("Expected a string");
			throw std::runtime_error(msg);
		} else {
			int rc = rtype_bit_from_str(element);
			if(!rc) {
				std::string msg = config_error_context(peer, JALNS_RECORD_TYPES)
				+ std::string("expected string or array of \"" JALNS_JOURNAL \
						"\", \"" JALNS_AUDIT "\", and/or \"" JALNS_LOG "\"");
				throw std::runtime_error(msg);
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
		std::string msg = config_error_context(peer, JALNS_RECORD_TYPES)
		+ std::string("expected string or array of \"" JALNS_JOURNAL \
				"\", \"" JALNS_AUDIT "\", and/or \"" JALNS_LOG "\"");
		throw std::runtime_error(msg);
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
			std::string msg = config_error_context(peer, JALNS_RECORD_TYPES)
			+ std::string("expected string or array of \"" JALNS_JOURNAL \
					"\", \"" JALNS_AUDIT "\", and/or \"" JALNS_LOG "\"");
			throw std::runtime_error(msg);
		}

		// OR this bit with our running total
		ret |= rtype;
	}
	return ret;
}


PeerConfig::~PeerConfig() {
	// Should already be done by jaln_connection_destroy in jald main
	// when the connection is closed
	free(conn);
	conn = NULL;
}

PeerConfig::PeerConfig(config_setting_t* peer_element) {
	// Extract peer host
	host = jal_config_lookup_cpp_string(peer_element, JALNS_HOST, JAL_CFG_REQUIRED, {});

	// Extract peer port
	port = jal_config_lookup_cpp_int64(peer_element, JALNS_PORT, JAL_CFG_REQUIRED, 0);

	// Extract peer digest challenge config
	dc_config = parse_dc_config(peer_element);

	// Extract peer record types
	record_types = (jaln_record_type) parse_record_types(peer_element);

	// Extract peer mode
	std::string mode_str = jal_config_lookup_cpp_string(
		peer_element,
		JALNS_MODE,
		JAL_CFG_REQUIRED,
		{});

	// Interpret mode string
	if (!strcasecmp(mode_str.c_str(), JALNS_MODE_LIVE)) {
		mode = JALN_LIVE_MODE;
	} else if (!strcasecmp(mode_str.c_str(), JALNS_MODE_ARCHIVE)
		|| (!strcasecmp(mode_str.c_str(), JALNS_MODE_ARCHIVE_ALTERNATIVE))) {
		mode = JALN_ARCHIVE_MODE;
	} else {
		std::string msg = config_error_context(peer_element, JALNS_MODE)
		+ std::string("expected \"" JALNS_MODE_LIVE "\", \"" \
			JALNS_MODE_ARCHIVE "\", or " "\"" JALNS_MODE_ARCHIVE_ALTERNATIVE "\"");
		throw std::runtime_error(msg);
	}

	// Extract peer cert dir, only if tls is enabled
	if (global_args.enable_tls) {
		cert_dir = jal_config_lookup_cpp_path(
			peer_element,
			JALNS_CERT_DIR,
			JAL_CFG_REQUIRED,
			{});
	}
}

PeerConfig& PeerConfig::operator=(PeerConfig&& old) {
	if(&old == this) {
		return *this;
	}
	host = std::move(old.host);
	port = old.port;
	cert_dir = std::move(old.cert_dir);
	dc_config = std::move(old.dc_config);
	record_types = old.record_types;
	mode = old.mode;
	net_ctx = old.net_ctx;
	old.net_ctx = NULL;
	conn = old.conn;
	old.conn = NULL;
	connected = old.connected;
	retries = old.retries;
	// allow the peer_lock to be default constructed
	// copy/move semantics on std::mutex are weird, and 
	// we know we aren't adding/removing peers during runtime
	// so we can just ignore concurrency issues during move/copy
	return *this;
}

PeerConfig::PeerConfig(PeerConfig&& old) {
	host = std::move(old.host);
	port = old.port;
	cert_dir = std::move(old.cert_dir);
	dc_config = std::move(old.dc_config);
	record_types = old.record_types;
	mode = old.mode;
	net_ctx = old.net_ctx;
	old.net_ctx = NULL;
	conn = old.conn;
	old.conn = NULL;
	connected = old.connected;
	retries = old.retries;
	// allow the peer_lock to be default constructed
	// copy/move semantics on std::mutex are weird, and 
	// we know we aren't adding/removing peers during runtime
	// so we can just ignore concurrency issues during move/copy
}

static std::vector<PeerConfig> parse_peer_configs(config_setting_t *root)
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
		throw std::runtime_error("Unable to read peer list");
	}

	std::vector<PeerConfig> peer_list;

	// parse each individual peer configuration
	for (unsigned i = 0; i < (unsigned) peer_len; i++) {
		config_setting_t *a_peer = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_elem_group(
			peers,
			i,
			&a_peer,
			JALNS_PEERS)) {
				throw std::runtime_error("Failed to get peer from peer element group");
		}

		peer_list.emplace_back(PeerConfig(a_peer));
	}
	return peer_list;
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

static std::array<std::string, 2> parse_dc_config(config_setting_t *peer)
{
	if (!peer) {
		throw std::runtime_error("Failed to get dc_config group");
	}

	config_setting_t* node = NULL;
	if(JAL_CFG_SUCCESS != jal_config_get_member(
		peer,
		JALNS_DC_CONFIG,
		&node,
		JAL_CFG_REQUIRED)) {
			throw std::runtime_error("Failed to get dc_config");
	}

	// If a single value is provided instead of an array, handle that here
	if (CONFIG_FALSE == config_setting_is_array(node)
		&& CONFIG_FALSE == config_setting_is_list(node)) {
		// Using the libconfig API directly here since we have already extracted
		// the node and just need to get the string value
		const char* element = config_setting_get_string(node);
		if(NULL == element || !validate_dc_config_str(element)) {
			std::string msg = config_error_context(node, JALNS_DC_CONFIG)
				+ std::string("Expected \"on\", \"off\", or an array with one or both of these values.");
			throw std::runtime_error(msg);
		} else {
			// Note the strdup here - since we used the libconfig API, the returned string
			// is owned by the config_t and tied to its lifetime
			std::array<std::string, 2> dc_config;
			dc_config[0] = std::string(element);
			return dc_config;
		}
	}

	// Otherwise, it's an array/list which we can handle with the same code
	// but we do need the length
	// Again using the libconfig API directly here to get the length so we don't
	// have to re-extract the node
	int node_len = config_setting_length(node);
	// can be on, off, or combination of the two
	if (0 >= node_len || 2 < node_len) {
		std::string msg = config_error_context(node, JALNS_DC_CONFIG)
			+ std::string("Expected \"on\", \"off\", or an array with one or both of these values.");
		throw std::runtime_error(msg);
	}

	std::array<std::string, 2> dc_config;
	for(int i = 0; i < node_len; i++) {
		// Extract the string from the list/array at index i
		char* element = NULL;
		if(JAL_CFG_SUCCESS != jal_config_get_elem_string(
			node,
			i,
			&element,
			JALNS_DC_CONFIG)) {
			std::string msg = config_error_context(node, JALNS_DC_CONFIG)
				+ std::string("Failed to extract dc_config element.");
			throw std::runtime_error(msg);
		}

		if(NULL == element) {
			std::string msg = config_error_context(node, JALNS_DC_CONFIG)
				+ std::string("Failed to extract dc_config element.");
			throw std::runtime_error(msg);
		}

		std::string config_str = std::string(element);
		free(element);

		if(!validate_dc_config_str(config_str.c_str())) {
			std::string msg = config_error_context(node, JALNS_DC_CONFIG)
				+ std::string("Expected \"on\", \"off\", or an array with one or both of these values.");
			throw std::runtime_error(msg);
		} else {
			// Note no strdup here because we used the jal_config API, which returns malloc'd
			// memory which must be freed by the caller
			dc_config[i] = config_str;
		}
	}

	return dc_config;
}
