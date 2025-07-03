/**
 * @file
 *
 * @brief This file contains functions for parsing the
 * local store config file.
 *
 * ### LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "jal_alloc.h"
#include "jal_config.h"
#include "jalls_config.h"
#include "jalls_context.h"
#include "jaldb_context.h"

int jalls_parse_config(const char *config_file_path, struct jalls_context **jalls_ctx) {

	if (!config_file_path || !jalls_ctx || *jalls_ctx) {
		return JAL_CFG_FAILURE;
	}

	config_t jalls_config;
	int ret = jal_config_init(&jalls_config);

	if (JAL_CFG_SUCCESS != ret) {
		fprintf(stderr, "Error initializing config file");
		return -1;
	}

	ret = jal_config_read_file(&jalls_config, config_file_path);

	if (JAL_CFG_SUCCESS != ret) {
		fprintf(stderr, "parse error: \"%s\" line %d\n",
			config_error_text(&jalls_config), config_error_line(&jalls_config));
		config_destroy(&jalls_config);
		return JAL_CFG_FAILURE;
	}

	*jalls_ctx = calloc(1, sizeof(**jalls_ctx));
	if (*jalls_ctx == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		return JAL_CFG_FAILURE;
	}

	char *system_uuid_str = NULL;
	char *dgst_alg_str = NULL;
	char **private_key_file = &((*jalls_ctx)->private_key_file);
	char **public_cert_file = &((*jalls_ctx)->public_cert_file);
	uuid_t *system_uuid = &(*jalls_ctx)->system_uuid;
	char **hostname = &((*jalls_ctx)->hostname);
	char **pid_file = &((*jalls_ctx)->pid_file);
	char **log_dir = &((*jalls_ctx)->log_dir);
	char **db_root = &((*jalls_ctx)->db_root);
	char **socket = &((*jalls_ctx)->socket);
	char **socket_owner = &((*jalls_ctx)->socket_owner);
	char **socket_group = &((*jalls_ctx)->socket_group);
	char **socket_mode = &((*jalls_ctx)->socket_mode);
	int *daemon = &((*jalls_ctx)->daemon);
	int *sign_sys_meta = &((*jalls_ctx)->sign_sys_meta);
	int *manifest_sys_meta = &((*jalls_ctx)->manifest_sys_meta);
	int *accept_delay_thread_count = &((*jalls_ctx)->accept_delay_thread_count);
	int *accept_delay_increment = &((*jalls_ctx)->accept_delay_increment);
	int *accept_delay_max = &((*jalls_ctx)->accept_delay_max);
	enum jal_digest_algorithm *sys_meta_dgst_alg = &((*jalls_ctx)->sys_meta_dgst_alg);
	long long *journal_record_size_limit = &((*jalls_ctx)->journal_record_size_limit);
	long long *audit_record_size_limit = &((*jalls_ctx)->audit_record_size_limit);
	long long *log_record_size_limit = &((*jalls_ctx)->log_record_size_limit);
	enum jaldb_flags *jdb_flags=&((*jalls_ctx)->jdb_flags);
	char **database_option = &((*jalls_ctx)->database_option);

	config_setting_t *root = config_root_setting(&jalls_config);
	int error_seen = JAL_CFG_SUCCESS;

	error_seen |= jal_config_lookup_string(root, JALLS_CFG_PRIVATE_KEY_FILE, private_key_file, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_string(root, JALLS_CFG_PUBLIC_CERT_FILE, public_cert_file, JAL_CFG_OPTIONAL);

	if (NULL != *public_cert_file && NULL == *private_key_file) {
		error_seen |= JAL_CFG_FAILURE;
		fprintf(stderr, "Error: public certificate given and no private key specified\n");
	}

	error_seen |= jal_config_lookup_string(root, JALLS_CFG_SYSTEM_UUID, &system_uuid_str, JAL_CFG_REQUIRED);
	//validate the uuid:
	if (system_uuid_str) {
		ret = uuid_parse(system_uuid_str, *system_uuid);
		if (-1 == ret) {
			error_seen |= JAL_CFG_FAILURE;
			fprintf(stderr, "Error: failed to validate uuid\n");
		}
	}

	// Database option setting
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_DATABASE_OPTION,
		database_option,
		JAL_CFG_OPTIONAL))
	{
		error_seen |= JAL_CFG_FAILURE;
	}

	//Ensure valid entry was in the config file and parse the value
	if (JALDB_OK != jaldb_get_db_flags(*database_option, jdb_flags))
	{
		error_seen |= JAL_CFG_FAILURE;
		fprintf(stderr, "Error: failed to validate database_option\n");
	}

	error_seen |= jal_config_lookup_string(root, JALLS_CFG_HOSTNAME, hostname, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_string(root, JALLS_CFG_LOG_DIR, log_dir, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_string(root, JALLS_CFG_PID_FILE, pid_file, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_string(root, JALLS_CFG_DB_ROOT, db_root, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_string(root, JALLS_CFG_SOCKET, socket, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_string(root, JALLS_CFG_SOCKET_OWNER, socket_owner, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_string(root, JALLS_CFG_SOCKET_GROUP, socket_group, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_string(root, JALLS_CFG_SOCKET_MODE, socket_mode, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_bool(root, JALLS_CFG_DAEMON, daemon, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_bool(root, JALLS_CFG_SIGNATURE, sign_sys_meta, JAL_CFG_OPTIONAL);
	error_seen |= jal_config_lookup_bool(root, JALLS_CFG_MANIFEST, manifest_sys_meta, JAL_CFG_OPTIONAL);

	// Set a default value for a digest algorithm. This is necessary because a journal record
	// always uses a digest and isn't dependent on whether the system metadata is to be signed
	*sys_meta_dgst_alg = JAL_DIGEST_ALGORITHM_DEFAULT;

	// Only attempt to override the default value if 'true' is specified for manifest_sys_meta
	if (*manifest_sys_meta) {
		error_seen |= jal_config_lookup_string(root, JALLS_CFG_SYS_META_DGST_ALG, &dgst_alg_str, JAL_CFG_OPTIONAL);

		// If we found a digest algorithm in the config
		if (dgst_alg_str) {
			enum jal_status status = jal_get_digest_from_str(dgst_alg_str, sys_meta_dgst_alg);

			// If we couldn't convert the config's digest algorithm into a valid algorithm
			if (JAL_OK != status) {
				error_seen |= JAL_CFG_FAILURE;
				fprintf(stderr, "Config Error: Invalid digest found: field: %s value: %s\n", JALLS_CFG_SYS_META_DGST_ALG, dgst_alg_str);
			}
		}
	}

	*accept_delay_thread_count = JALLS_CFG_ACCEPT_DELAY_THREAD_COUNT_DEFAULT;
	error_seen |= jal_config_lookup_int(root, JALLS_CFG_ACCEPT_DELAY_THREAD_COUNT, accept_delay_thread_count, JAL_CFG_OPTIONAL);

	*accept_delay_increment = JALLS_CFG_ACCEPT_DELAY_INCREMENT_DEFAULT;
	error_seen |= jal_config_lookup_int(root, JALLS_CFG_ACCEPT_DELAY_INCREMENT, accept_delay_increment, JAL_CFG_OPTIONAL);

	if (0 > *accept_delay_increment) {
		*accept_delay_increment = JALLS_CFG_ACCEPT_DELAY_INCREMENT_DEFAULT;
	}

	*accept_delay_max = JALLS_CFG_ACCEPT_DELAY_MAX_DEFAULT;
	error_seen |= jal_config_lookup_int(root, JALLS_CFG_ACCEPT_DELAY_MAX, accept_delay_max, JAL_CFG_OPTIONAL);

	if (0 > *accept_delay_max ||
		*accept_delay_increment > *accept_delay_max) {
		*accept_delay_max = JALLS_CFG_ACCEPT_DELAY_MAX_DEFAULT;
	}

	*journal_record_size_limit = JALLS_CFG_JOURNAL_RECORD_SIZE_LIMIT_DEFAULT;
	error_seen |= jal_config_lookup_int64(root, JALLS_CFG_JOURNAL_RECORD_SIZE_LIMIT, journal_record_size_limit, JAL_CFG_OPTIONAL);

	*audit_record_size_limit = JALLS_CFG_AUDIT_RECORD_SIZE_LIMIT_DEFAULT;
	error_seen |= jal_config_lookup_int64(root, JALLS_CFG_AUDIT_RECORD_SIZE_LIMIT, audit_record_size_limit, JAL_CFG_OPTIONAL);

	*log_record_size_limit = JALLS_CFG_LOG_RECORD_SIZE_LIMIT_DEFAULT;
	error_seen |= jal_config_lookup_int64(root, JALLS_CFG_LOG_RECORD_SIZE_LIMIT, log_record_size_limit, JAL_CFG_OPTIONAL);

	if (NULL == *hostname) {
		char name[_POSIX_HOST_NAME_MAX+1];
		if (gethostname(name, sizeof(name)) == 0) {
			name[_POSIX_HOST_NAME_MAX] = '\0';
			*hostname = strdup(name);
		} else {
			error_seen |= JAL_CFG_FAILURE;
			fprintf(stderr, "Error: could not gather hostname\n");
		}
	}

	if (*db_root == NULL) {
		*db_root = strdup(JALLS_CFG_DB_DEFAULT);
	}
	if ((*db_root)[strlen(*db_root) - 1] != '/') {
		int len = strlen(*db_root);
		char *tmp = jal_malloc(len + 2);
		strncpy(tmp, *db_root, len);
		tmp[len] = '/';
		tmp[len + 1] = 0;
		free(*db_root);
		(*jalls_ctx)->db_root = tmp;
	}

	if (*socket == NULL) {
		*socket = strdup(JALLS_CFG_SOCKET_DEFAULT);
	}

	if (JAL_CFG_SUCCESS != error_seen) {
		free((*jalls_ctx)->private_key_file);
		free((*jalls_ctx)->public_cert_file);
		free(system_uuid_str);
		free(dgst_alg_str);
		free((*jalls_ctx)->database_option);
		free((*jalls_ctx)->hostname);
		free((*jalls_ctx)->db_root);
		free((*jalls_ctx)->socket);
		free((*jalls_ctx)->socket_owner);
		free((*jalls_ctx)->socket_group);
		free((*jalls_ctx)->socket_mode);
		free(*jalls_ctx);
		*jalls_ctx = NULL;
		config_destroy(&jalls_config);
		return JAL_CFG_FAILURE;
	}

	config_destroy(&jalls_config);
	free(system_uuid_str);
	free(dgst_alg_str);
	return JAL_CFG_SUCCESS;
}
