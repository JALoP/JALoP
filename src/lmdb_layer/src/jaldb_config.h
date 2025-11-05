/**
 * @file
 *
 * @brief This file provides the capability to load the LMDB_CONFIG file
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

#ifndef _JALDB_CONFIG_H_
#define _JALDB_CONFIG_H_

#include "jaldb_context.h"

#ifdef __cplusplus
extern "C" {
#endif

///Default lmdb database size (map size) of 120 GB
#define DEFAULT_LMDB_MAP_SIZE 120

//25 TB
#define MAX_LMDB_MAP_SIZE 25000

#define JALDB_MAP_SIZE "lmdb_map_size"
#define JALDB_DATABASE_OPTION "database_option"

/**
 * Enumeration for error codes returned by the get_jaldb_config method.
 */
enum jaldb_config_status {
	JALDB_CONFIG_E_LOAD = 1,
	JALDB_CONFIG_E_NOTFOUND = 2,
	JALDB_CONFIG_E_MEM = 3,
	JALDB_CONFIG_OK = 0,
};

typedef struct jaldb_config_t {
	int map_size;
	char* database_option;
	enum jaldb_flags jdb_flags;
} jaldb_config;

/**
 * Parses the LMDB_CONFIG if present and returns the populated jaldb_config_t struct
 *
 * @param[in] db_root The path to the db root
 * @param[out] jdb_config The pointer to the struct containing the parsed LMDB_CONFIG data.
 *                          This struct is allocated in this method and must be freed when done.
 *
 * @return JALDB_CONFIG_OK if the function succeeds or a jaldb_config_status error code if the function
 * fails.
 */
enum jaldb_config_status get_jaldb_config(const char* db_root, jaldb_config **jdb_config);

/**
 * Frees the jaldb_config pointer returned from the get_jaldb_config method.  This is needed
 * for the rust inline filter to free this pointer.
 *
 * @param[in] jdb_config The jaldb_config pointer to free
 *
 */
void free_jaldb_config(jaldb_config **jdb_config);

#ifdef __cplusplus
}
#endif

#endif // _JALDB_CONFIG_H_
