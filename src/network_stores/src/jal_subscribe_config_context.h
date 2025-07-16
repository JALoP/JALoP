/**
 * @file
 *
 * @brief The JAL subscriber config context header
 *
 * ### LICENSE
 *
 * Copyright (C) 2023 Concurrent Technologies Corporation.
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

// This file represents a conversion layer between a C caller and the C++ implementation
// and so contains all functions a C user of the JalSubscriber should need to interact
// with the JalSubscriber class
#pragma once

#ifdef __cplusplus
extern "C"
{
#endif
/**
* Represents the options required to create a Jal_Subscribe config
*/
struct jal_subscribe_config_context {
	// path to the config file
	char *conf;
	// port to listen on
	char *port;
	// ip addr to listen on
	char *ipaddr;
	// mode to run on
	char *inmode;
	// root of the jalop db
	char *dbpath;
	// flag for debug output
	int debug;
	// disable TLS authentication
	int disableTls;
	// allowable digest algorithms
	char *digest_algorithms;
	// FileSystem storage
	int fs;
};

/**
 * Option processing function for use with argp and the jal_subscribe_config_context struct
 */
error_t jal_subscribe_parse_opt(int key, char *arg, struct argp_state *state);

/**
 * Utility function to drop any dynamic memory from a jal_subscribe_config_context struct
 */
void jal_subscribe_config_drop_memory(struct jal_subscribe_config_context* ctx);

#ifdef __cplusplus
}
#endif
