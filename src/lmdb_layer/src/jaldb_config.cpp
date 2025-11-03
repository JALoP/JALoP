/**
 * @file
 *
 * @brief This file implements the DB context management
 * functions using Lightning Memory-Mapped Database (LMDB).
 *
 * ### LICENSE
 *
 * Copyright (C) 2025 Concurrent Technologies Corporation.
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

#define __STDC_FORMAT_MACROS

#include <fcntl.h>
#include <jalop/jal_status.h>
#include <inttypes.h> // For PRIu64
#include <list>
#include <sstream>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "jaldb_context.hpp"
#include "jaldb_context.h"
#include "jaldb_status.h"
#include "jaldb_config.h"
#include "jal_config.h"
#include "jal_alloc.h"

#define LMDB_CONFIG_FILE "LMDB_CONFIG"

enum jaldb_config_status get_jaldb_config(const char* db_root, jaldb_config **jdb_config)
{
	if (NULL == db_root || NULL == jdb_config || NULL != *jdb_config )
	{
		return JALDB_CONFIG_E_MEM;
	}

	std::string jaldb_config_path = std::string(db_root) + "/" + std::string(LMDB_CONFIG_FILE);
	//Only attempt to load if LMDB_CONFIG file is present
	struct stat jaldb_config_stat;
	int rc = stat(jaldb_config_path.c_str(), &jaldb_config_stat);
	if (0 != rc) {
		return JALDB_CONFIG_E_NOTFOUND;
	}

	*jdb_config = (jaldb_config*)jal_calloc(1, sizeof(jaldb_config));

	if (NULL == *jdb_config)
	{
		return JALDB_CONFIG_E_MEM;
	}

	// Load config file as config_t object
	config_t config;
	if(JALDB_OK != jal_config_init(&config)) {
		free_jaldb_config(jdb_config);
		// Error printed internally
		return JALDB_CONFIG_E_LOAD;
	}

	// Attempt to read from the provided config file path
	if(JAL_CFG_SUCCESS != jal_config_read_file(&config, jaldb_config_path.c_str()))
	{
		free_jaldb_config(jdb_config);
		// Error printed internally
		return JALDB_CONFIG_E_LOAD;
	}

	// Extract root configuration setting
	config_setting_t *root = config_root_setting(&config);

	// Extract map_size
	(*jdb_config)->map_size = DEFAULT_LMDB_MAP_SIZE;
	if(JAL_CFG_SUCCESS != jal_config_lookup_int(
		root,
		JALDB_MAP_SIZE,
		&(*jdb_config)->map_size,
		JAL_CFG_OPTIONAL)) {
			free_jaldb_config(jdb_config);
			// Error printed internally
			return JALDB_CONFIG_E_LOAD;
	}

	//Check lmdb_map_size value
	if ((*jdb_config)->map_size < 1) {
		CONFIG_ERROR(root, JALDB_MAP_SIZE, "invalid value, less than 1");
		free_jaldb_config(jdb_config);
		return JALDB_CONFIG_E_LOAD;
	}

	if ((*jdb_config)->map_size > MAX_LMDB_MAP_SIZE) {
		CONFIG_ERROR(root, JALDB_MAP_SIZE, "invalid value, greater than max value of %d", MAX_LMDB_MAP_SIZE);
		free_jaldb_config(jdb_config);
		return JALDB_CONFIG_E_LOAD;
	}

	//database_option config setting
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
		root,
		JALDB_DATABASE_OPTION,
		&(*jdb_config)->database_option,
		JAL_CFG_OPTIONAL)) {
			free_jaldb_config(jdb_config);
			// Error printed internally
			return JALDB_CONFIG_E_LOAD;
	}

	//Ensure valid entry was in the config file and parse the value
	if (NULL != (*jdb_config)->database_option)
	{
		if (JALDB_OK != jaldb_get_db_flags((*jdb_config)->database_option, &(*jdb_config)->jdb_flags))
		{
			CONFIG_ERROR(root, JALDB_DATABASE_OPTION, "invalid value.");
			free_jaldb_config(jdb_config);
			return JALDB_CONFIG_E_LOAD;
		}
	}
	config_destroy(&config);
	return JALDB_CONFIG_OK;
}

void free_jaldb_config(jaldb_config **jdb_config)
{
	free((*jdb_config)->database_option);
	free(*jdb_config);
	*jdb_config = NULL;
}
