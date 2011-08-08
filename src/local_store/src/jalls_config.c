/**
 * @file jalls_config.c This file contains functions for parsing the
 * local store config file.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011 Tresys Technology LLC, Columbia, Maryland, USA
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

#include "jalu_config.h"
#include "jalls_config.h"
#include "jalls_context.h"

int jalls_parse_config(const char *config_file_path, struct jalls_context **jalls_ctx) {

	if (!config_file_path || !jalls_ctx || *jalls_ctx) {
		return -1; //should never happen
	}

	*jalls_ctx = calloc(1, sizeof(**jalls_ctx));
	if (jalls_ctx == NULL) {
		fprintf(stderr, "failed to allocate memory\n");
		return -1;
	}

	char **private_key_file = &((*jalls_ctx)->private_key_file);
	char **public_cert_file = &((*jalls_ctx)->public_cert_file);
	char **system_uuid = &((*jalls_ctx)->system_uuid);
	char **hostname = &((*jalls_ctx)->hostname);
	char **db_root = &((*jalls_ctx)->db_root);
	char **socket = &((*jalls_ctx)->socket);

	config_t jalls_config;
	config_init(&jalls_config);

	int ret = config_read_file(&jalls_config, config_file_path);

	if (ret == CONFIG_FALSE) {
		fprintf(stderr, "parse error: \"%s\" line %d\n",
			config_error_text(&jalls_config), config_error_line(&jalls_config));
		goto err_out;
	}

	config_setting_t *root = config_root_setting(&jalls_config);

	ret = jal_config_lookup_string(root, JALLS_CFG_PRIVATE_KEY_FILE, private_key_file, JALU_CFG_REQUIRED);
	if (-1 == ret) {
		goto err_out;
	}

	ret = jal_config_lookup_string(root, JALLS_CFG_PUBLIC_CERT_FILE, public_cert_file, JALU_CFG_OPTIONAL);
	if (-1 == ret) {
		goto err_out;
	}

	ret = jal_config_lookup_string(root, JALLS_CFG_SYSTEM_UUID, system_uuid, JALU_CFG_REQUIRED);
	if (-1 == ret) {
		goto err_out;
	}
	//validate the uuid:
	uuid_t tmp_uu;
	ret = uuid_parse(*system_uuid, tmp_uu);
	if (-1 == ret) {
		fprintf(stderr, "Error: failed to validate uuid\n");
		goto err_out;
	}

	ret = jal_config_lookup_string(root, JALLS_CFG_HOSTNAME, hostname, JALU_CFG_OPTIONAL);
	if (-1 == ret) {
		goto err_out;
	}

	ret = jal_config_lookup_string(root, JALLS_CFG_DB_ROOT, db_root, JALU_CFG_OPTIONAL);
	if (-1 == ret) {
		goto err_out;
	}

	ret = jal_config_lookup_string(root, JALLS_CFG_SOCKET, socket, JALU_CFG_OPTIONAL);
	if (-1 == ret) {
		goto err_out;
	}

	if (*hostname == NULL) {
		char name[_POSIX_HOST_NAME_MAX+1];
		if (gethostname(name, sizeof(name)) == 0) {
			name[_POSIX_HOST_NAME_MAX] = '\0';
			*hostname = strdup(name);
		} else {
			fprintf(stderr, "Error: could not gather hostname\n");
			ret = -1;
			goto err_out;
		}
	}

	if (*db_root == NULL) {
		*db_root = strdup(JALLS_CFG_DB_DEFAULT);
	}

	if (*socket == NULL) {
		*socket = strdup(JALLS_CFG_SOCKET_DEFAULT);
	}

	config_destroy(&jalls_config);
	return 0;

err_out:

	free((*jalls_ctx)->private_key_file);
	free((*jalls_ctx)->public_cert_file);
	free((*jalls_ctx)->system_uuid);
	free((*jalls_ctx)->hostname);
	free((*jalls_ctx)->db_root);
	free((*jalls_ctx)->socket);
	free(*jalls_ctx);
	*jalls_ctx = NULL;
	config_destroy(&jalls_config);
	return ret;
}
