/**
 * @file
 *
 * @brief This file contains utility functions for reading config
 * files.
 *
 * ### LICENSE
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

#ifndef _JAL_CONFIG_H_
#define _JAL_CONFIG_H_

#include <libconfig.h>
#include <string.h>

#define JAL_CFG_REQUIRED 1
#define JAL_CFG_OPTIONAL 0

#define JAL_CFG_SUCCESS 0
#define JAL_CFG_FAILURE 1

#ifdef __cplusplus
extern "C" {
#endif

#define CONFIG_ERROR(setting, name, ...) \
do { \
	fprintf(stderr, "Config Error: line %d: field \"%s\" ", \
			config_setting_source_line(setting), name); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n"); \
} while (0)

#define CONFIG_WARNING(setting, name, ...) \
do { \
	fprintf(stderr, "Config Warning: line %d: field \"%s\" ", \
			config_setting_source_line(setting), name); \
	fprintf(stderr, __VA_ARGS__); \
	fprintf(stderr, "\n"); \
} while (0)

/**
 * Wraps config_init() from libconfig for better error checking
 *
 * @param [out] config config_t struct to initialize.
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
 */
int jal_config_init(config_t *config);

/**
 * Wraps config_read_file() from libconfig for better error checking
 *
 * @param [out] config   config_t struct representing the config file.
 * @param [in]  filename Filename containining the config file.
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE ON FAILURE
*/
int jal_config_read_file(config_t *config, const char *filename);

/**
 * Wraps config_lookup() from libconfig for better error checking
 *
 * @param [in]  config   config_t struct representing the config file.
 * @param [in]  name     The name of the field.
 * @param [out] field    The result read from the config file will be stored here.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
 */
int jal_config_lookup(config_t *config, const char *name, config_setting_t **field, int required);

/**
 * Wraps config_setting_get_member() from libconfig for better error checking
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [out] field    The result read from the config file will be stored here.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
*/
int jal_config_get_member(config_setting_t *setting, const char *name, config_setting_t **field, int required);

/**
 * Wraps config_lookup_string() from libconfig for better error checking,
 * and to allocate the field instead of letting libconfig own the resulting
 * string.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [out] field    The result read from the config file will be stored here,
 *   as a newly allocated string. The caller takes ownership of the pointer.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
 */
int jal_config_lookup_string(const config_setting_t *setting,
	const char *name, char **field, int required);

/**
 * Wraps config_get_bool from libconfig for better error checking
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field
 * @param [out] field    The result read from the config file will be stored here
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the field
 * 	is not found, printing an error to stderr.
 * 	If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 * 	remain unchanged.
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
 */
int jal_config_lookup_bool(const config_setting_t *setting,
	const char *name, int *field, int required);

/**
 * Wraps config_get_int from libconfig for better error checking
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field
 * @param [out] field    The result read from the config file will be stored here
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the field
 * 	is not found, printing an error to stderr.
 * 	If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 * 	remain unchanged.
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
 */
int jal_config_lookup_int(const config_setting_t *setting,
	const char *name, int *field, int required);

/**
 * Wraps config_get_int64 from libconfig for better error checking
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field
 * @param [out] field    The result read from the config file will be stored here
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the field
 * 	is not found, printing an error to stderr.
 * 	If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 * 	remain unchanged.
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
 */
int jal_config_lookup_int64(const config_setting_t *setting,
	const char *name, long long *field, int required);

/**
 * Wraps config_setting_get_member from libconfig for better error checking
 * This function should be used when the expected value of the parameter is a list or an array
 *
 * Lists and arrays are different in libconfig. Arrays can contain only scalars, but lists can
 * contain scalars, arrays, groups, and/or lists.
 *
 * @param [in]  setting     The parent setting of the field to lookup.
 * @param [in]  name        The name of the field
 * @param [out] list        The result from the config file will be stored here
 * @param [out] list_length The length of the list stored in list
 * @param [in]  required    If set to JAL_CFG_REQUIRED, the function will fail if the field
 * 	is not found, printing an error to stderr.
 * 	If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 * 	remain unchanged.
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
 */
int jal_config_lookup_list(const config_setting_t *setting,
	const char *name, config_setting_t **list, int *list_length,  int required);

/**
 * Wraps config_setting_get_elem from libconfig for better error checking
 * This function should be used when the expected value of the parameter is a group
 *
 * @param [in]  setting The parent setting of the field to lookup.
 * @param [in]  idx     The index of the item to process
 * @param [out] group   The result from the setting at index idx will be stored here
 * @param [in]  name    The name of the parent setting - for error messages only
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
 */
int jal_config_get_elem_group(const config_setting_t *setting, int idx, config_setting_t **group, const char *name);

/**
 * Wraps config_setting_get_elem from libconfig for better error checking
 * This function should be used when the expected value of the parameter is a string
 *
 * @param [in]  setting The parent setting of the field to lookup.
 * @param [in]  idx     The index of the item to process
 * @param [out] str     The result from the setting at index idx will be stored here
 * @param [in]  name    The name of the parent setting - for error messages only
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
 */
int jal_config_get_elem_string(const config_setting_t *setting, int idx, char **str, const char *name);

/**
 * Wraps config_setting_get_elem from libconfig for better error checking
 * This function should be used when the expected value of the parameter is an integer
 *
 * @param [in]  setting The parent setting of the field to lookup.
 * @param [in]  idx     The index of the item to process
 * @param [out] value   The result from the setting at index idx will be stored here
 * @param [in]  name    The name of the parent setting - for error messages only
 * @return JAL_CFG_SUCCESS on success, JAL_CFG_FAILURE on failure
 */
int jal_config_get_elem_int(const config_setting_t *setting, int idx, int *value, const char *name);


/**
 * This method takes a filepath and expands any preceding "~/" to the active
 * user directory path.
 *
 * @param raw_path The initial file path to expand
 * @param key_name The name of the current config setting key being processed
 *
 * @return The expanded file path.
*/
char* jal_expand_home_dir(const char *raw_path, const char *key_name);

/**
 * This method takes a filepath and expands any preceding "~/" to the active
 * user directory path.  It also resolves any relative paths to the absolute path.
 *
 * @param raw_path The initial file path to expand
 * @param key_name The name of the current config setting key being processed
 *
 * @return The expanded file path.
*/
char* jal_expand_path(const char *raw_path, const char *key_name);

#ifdef __cplusplus
}
#endif

#endif // _JAL_CONFIG_H_
