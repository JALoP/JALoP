/**
 * @file jalls_config.c This file contains functions for parsing the
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

#include <libconfig.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include "jal_alloc.h"
#include "jal_config.h"
#include "jalls_config.h"
#include "jalls_context.h"

int jalls_parse_config(const char *config_file_path, struct jalls_context **jalls_ctx) {

	if (!config_file_path || !jalls_ctx || *jalls_ctx)
	{
		return -1; //should never happen
	}

	*jalls_ctx = calloc(1, sizeof(**jalls_ctx));
	if (*jalls_ctx == NULL)
	{
		fprintf(stderr, "failed to allocate memory\n");
		return -1;
	}

	// Note - the use of calloc to initialize the jalls_ctx means that all
	// fields are initialized to 0 - so pointers are all NULL and ints are 0
	// by default
	// Any settings using the JAL_CFG_OPTIONAL parameter will be left unchanged
	// by the lookup functions if that setting is not present in the config file
	char *system_uuid_str = NULL;
	char **private_key_file = &((*jalls_ctx)->private_key_file);
	char **public_cert_file = &((*jalls_ctx)->public_cert_file);
	uuid_t *system_uuid = &(*jalls_ctx)->system_uuid;
	char **hostname = &((*jalls_ctx)->hostname);
	char **schemas_root = &((*jalls_ctx)->schemas_root);
	char **pid_file = &((*jalls_ctx)->pid_file);
	char **log_dir = &((*jalls_ctx)->log_dir);
	char **db_root = &((*jalls_ctx)->db_root);
	char **socket = &((*jalls_ctx)->socket);
	char **socket_owner = &((*jalls_ctx)->socket_owner);
	char **socket_group = &((*jalls_ctx)->socket_group);
	char **socket_mode = &((*jalls_ctx)->socket_mode);
	int *db_recover = &((*jalls_ctx)->db_recover);
	int *daemon = &((*jalls_ctx)->daemon);
	int *sign_sys_meta = &((*jalls_ctx)->sign_sys_meta);
	int *manifest_sys_meta = &((*jalls_ctx)->manifest_sys_meta);
	int *accept_delay_thread_count = &((*jalls_ctx)->accept_delay_thread_count);
	int *accept_delay_increment = &((*jalls_ctx)->accept_delay_increment);
	int *accept_delay_max = &((*jalls_ctx)->accept_delay_max);
	enum jal_digest_algorithm *sys_meta_dgst_alg = &((*jalls_ctx)->sys_meta_dgst_alg);

	config_t jalls_config;
	if(JAL_CFG_SUCCESS != jal_config_init(&jalls_config))
	{
		fprintf(stderr, "Failed to initialize libconfig\n");
		goto err_out;
	}

	if(JAL_CFG_SUCCESS != jal_config_read_file(&jalls_config, config_file_path))
	{
		goto err_out;
	}

	config_setting_t *root = config_root_setting(&jalls_config);
	if(NULL == root)
	{
		fprintf(stderr, "Libconfig cannot provide root of configuration file\n");
		goto err_out;
	}

	// Private key file setting
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_PRIVATE_KEY_FILE,
		private_key_file,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	// Public cert file setting
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_PUBLIC_CERT_FILE,
		public_cert_file,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	if (NULL != *public_cert_file && NULL == *private_key_file) {
		fprintf(stderr, "Error: public certificate given and no private key specified\n");
		goto err_out;
	}

	// uuid setting
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_SYSTEM_UUID,
		&system_uuid_str,
		JAL_CFG_REQUIRED))
	{
		goto err_out;
	}

	//validate the uuid:
	if(-1 == uuid_parse(system_uuid_str, *system_uuid))
	{
		fprintf(stderr, "Error: failed to validate uuid\n");
		goto err_out;
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_HOSTNAME,
		hostname,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	// If a hostname was not provided in the config file, attempt to get the local
	// machine hostname
	if (*hostname == NULL)
	{
		char name[_POSIX_HOST_NAME_MAX+1] = {0};
		if (gethostname(name, sizeof(name)) == 0)
		{
			*hostname = strdup(name);
		}
		else
		{
			fprintf(stderr, "Error: could not gather hostname\n");
			goto err_out;
		}
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_SCHEMAS_ROOT,
		schemas_root,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	if (*schemas_root == NULL) {
		*schemas_root = strdup(SCHEMAS_ROOT);
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_LOG_DIR,
		log_dir,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_PID_FILE,
		pid_file,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_DB_ROOT,
		db_root,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	// If no db_root was specified, use a default path instead
	if (*db_root == NULL)
	{
		*db_root = strdup(JALLS_CFG_DB_DEFAULT);
	}

	// Ensure the db_root ends with a '/' in all cases
	// Extra scope layer for len to avoid goto crosses instantiation warnings
	{
		// *db_root guaranteed non-null at this point
		int len = strlen(*db_root);
		if ((*db_root)[len - 1] != '/')
		{
			// Create a new buffer that is one spot larger to hold the /
			char *tmp = jal_malloc(len + 2);
			strncpy(tmp, *db_root, len);
			tmp[len] = '/';
			tmp[len + 1] = 0;
			free(*db_root);
			(*jalls_ctx)->db_root = tmp;
		}
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_SOCKET,
		socket,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	// If no socket is provided, use a default path
	if (*socket == NULL)
	{
		*socket = strdup(JALLS_CFG_SOCKET_DEFAULT);
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_SOCKET_OWNER,
		socket_owner,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_SOCKET_GROUP,
		socket_group,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALLS_CFG_SOCKET_MODE,
		socket_mode,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
		root,
		JALLS_CFG_DB_RECOVER,
		db_recover,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	// If there is no daemon config setting, default to true (daemonize).
	*daemon = 1;
	if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
		root,
		JALLS_CFG_DAEMON,
		daemon,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
		root,
		JALLS_CFG_SIGNATURE,
		sign_sys_meta,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
		root,
		JALLS_CFG_MANIFEST,
		manifest_sys_meta,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	// Set a default value for a digest algorithm. This is necessary because a journal record
	// always uses a digest and isn't dependent on whether the system metadata is to be signed
	*sys_meta_dgst_alg = JAL_DIGEST_ALGORITHM_DEFAULT;

	// Only attempt to override the default value if manifest_sys_meta is 'true' (1)
	if(*manifest_sys_meta)
	{
		char *dgst_alg_str = NULL;
		if(JAL_CFG_SUCCESS != jal_config_lookup_string(
			root,
			JALLS_CFG_SYS_META_DGST_ALG,
			&dgst_alg_str,
			JAL_CFG_OPTIONAL))
		{
			goto err_out;
		}

		// If we found a digest algorithm in the config
		if (NULL != dgst_alg_str)
		{
			// If we couldn't convert the config's digest algorithm into a valid algorithm
			if(JAL_OK != jal_get_digest_from_str(dgst_alg_str, sys_meta_dgst_alg))
			{
				fprintf(stderr,
					"Config Error: Invalid digest found: field: %s value: %s\n",
					JALLS_CFG_SYS_META_DGST_ALG,
					dgst_alg_str);
				free(dgst_alg_str);
				goto err_out;
			}
			free(dgst_alg_str);
		}
	}

	// Set non-zero default for delay thread count
	*accept_delay_thread_count = JALLS_CFG_ACCEPT_DELAY_THREAD_COUNT_DEFAULT;
	if(JAL_CFG_SUCCESS != jal_config_lookup_int(
		root,
		JALLS_CFG_ACCEPT_DELAY_THREAD_COUNT,
		accept_delay_thread_count,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	// Set non-zero default for delay increment
	*accept_delay_increment = JALLS_CFG_ACCEPT_DELAY_INCREMENT_DEFAULT;
	if(JAL_CFG_SUCCESS != jal_config_lookup_int(
		root,
		JALLS_CFG_ACCEPT_DELAY_INCREMENT,
		accept_delay_increment,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	// Set non-zero default for delay max
	*accept_delay_max = JALLS_CFG_ACCEPT_DELAY_MAX_DEFAULT;
	if(JAL_CFG_SUCCESS != jal_config_lookup_int(
		root,
		JALLS_CFG_ACCEPT_DELAY_MAX,
		accept_delay_max,
		JAL_CFG_OPTIONAL))
	{
		goto err_out;
	}

	// Prohibit the increment being larger than the maximum delay
	if (*accept_delay_max < *accept_delay_increment)
	{
		fprintf(stderr,
			"Error: %s (%d) must not be less than configured: %s (%d).\n",
			JALLS_CFG_ACCEPT_DELAY_MAX,
			*accept_delay_max,
			JALLS_CFG_ACCEPT_DELAY_INCREMENT,
			*accept_delay_increment);
		goto err_out;
	}

	config_destroy(&jalls_config);
	free(system_uuid_str);
	return 0;

err_out:

	free((*jalls_ctx)->private_key_file);
	free((*jalls_ctx)->public_cert_file);
	free(system_uuid_str);
	free((*jalls_ctx)->hostname);
	free((*jalls_ctx)->schemas_root);
	free((*jalls_ctx)->db_root);
	free((*jalls_ctx)->socket);
	free((*jalls_ctx)->socket_owner);
	free((*jalls_ctx)->socket_group);
	free((*jalls_ctx)->socket_mode);
	free(*jalls_ctx);
	*jalls_ctx = NULL;
	config_destroy(&jalls_config);
	return -1;
}
