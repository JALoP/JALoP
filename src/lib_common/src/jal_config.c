/**
 * @file jal_config.c This file contains utility functions for reading
 * config files.
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

#include <libconfig.h>
#include <string.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include "jal_config.h"

int jal_config_init(config_t *config) {
	if (!config) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_init\n");
		return JAL_CFG_FAILURE;
	}

	config_init(config);
	return JAL_CFG_SUCCESS;
}

int jal_config_read_file(config_t *config, const char *filename) {
	if (!config || !filename) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_read_file\n");
		return JAL_CFG_FAILURE;
	}

	int rc = config_read_file(config, filename);

	if (CONFIG_FALSE == rc) {
		fprintf(stderr, "Failed to read config file: %s: (%d) %s!\n", filename, config_error_line(config), config_error_text(config));
		return JAL_CFG_FAILURE;
	}

	return JAL_CFG_SUCCESS;
}

int jal_config_lookup(config_t *config, const char *name, config_setting_t **field, int required) {
	if (!config || !name || !field || *field) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_lookup\n");
		return JAL_CFG_FAILURE;
	}

	*field = config_lookup(config, name);

	if (NULL == *field && required) {
		fprintf(stderr, "Error: required setting: %s not found\n", name);
		return JAL_CFG_FAILURE;
	}

	return JAL_CFG_SUCCESS;
}

int jal_config_get_member(config_setting_t *setting, const char *name, config_setting_t **field, int required) {
	if (!setting || !name || !field || *field) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_get_member\n");
		return JAL_CFG_FAILURE;
	}

	*field = config_setting_get_member(setting, name);

	if (NULL == *field && required) {
		fprintf(stderr, "Error: required setting: %s not found\n", name);
		return JAL_CFG_FAILURE;
	}

	return JAL_CFG_SUCCESS;
}

int jal_config_lookup_string(const config_setting_t *setting,
	const char *name, char **field, int required) {
	if (!setting || !name || !field || *field) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_lookup_string\n");
		return JAL_CFG_FAILURE;
	}
	config_setting_t *member = config_setting_get_member(setting, name);
	if (!member && required) {
		CONFIG_ERROR(setting, name, "missing required field");
		return JAL_CFG_FAILURE;
	}
	if (!member) {
		return JAL_CFG_SUCCESS;
	}
	if(config_setting_type(member) != CONFIG_TYPE_STRING) {
		CONFIG_ERROR(setting, name, "should be a string");
		return JAL_CFG_FAILURE;
	}
	const char *tmp = config_setting_get_string(member);
	if (!tmp && required) {
		CONFIG_ERROR(setting, name, "empty required field");
		return JAL_CFG_FAILURE;
	}
	if (!tmp) {
		CONFIG_ERROR(setting, name, "empty value for field");
		return JAL_CFG_SUCCESS;
	}
	*field = strdup(tmp);
	if (NULL == *field) {
		fprintf(stderr, "strdup failed: insufficient memory");
		return JAL_CFG_FAILURE;
	}

	return JAL_CFG_SUCCESS;
}

int jal_config_lookup_bool(const config_setting_t *setting,
	const char *name, int *field, int required) {
	if (!setting || !name || !field) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_lookup_bool\n");
		return JAL_CFG_FAILURE;
	}

	config_setting_t *member = config_setting_get_member(setting, name);

	if (!member && required) {
		CONFIG_ERROR(setting, name, "missing required field");
		return JAL_CFG_FAILURE;
	}

	if (!member) {
		return JAL_CFG_SUCCESS;
	}

	if (config_setting_type(member) != CONFIG_TYPE_BOOL) {
		CONFIG_ERROR(setting, name, "should be a boolean");
		return JAL_CFG_FAILURE;
	}

	// If the value for this field is empty, a 0 is returned.
	// The field should be initialized to 0 with calloc.
	*field = config_setting_get_bool(member);
	return JAL_CFG_SUCCESS;
}

int jal_config_lookup_int(const config_setting_t *setting,
	const char *name, int *field, int required) {
	if (!setting || !name || !field) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_lookup_int\n");
		return JAL_CFG_FAILURE;
	}

	config_setting_t *member = config_setting_get_member(setting, name);

	if (!member && required) {
		CONFIG_ERROR(setting, name, "missing required field");
		return JAL_CFG_FAILURE;
	}

	if (!member) {
		return JAL_CFG_SUCCESS;
	}

	if (config_setting_type(member) != CONFIG_TYPE_INT) {
		CONFIG_ERROR(setting, name, "should be an int");
		return JAL_CFG_FAILURE;
	}

	// If the value for this field is empty, a 0 is returned.
	// The field should be initialized to 0 with calloc.
	*field = config_setting_get_int(member);
	return JAL_CFG_SUCCESS;
}

int jal_config_lookup_int64(const config_setting_t *setting,
	const char *name, long long *field, int required) {
	if (!setting || !name || !field) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_lookup_int64\n");
		return JAL_CFG_FAILURE;
	}

	config_setting_t *member = config_setting_get_member(setting, name);

	if (!member && required) {
		CONFIG_ERROR(setting, name, "missing required field");
		return JAL_CFG_FAILURE;
	}

	if (!member) {
		return JAL_CFG_SUCCESS;
	}

	if (config_setting_type(member) != CONFIG_TYPE_INT64) {
		CONFIG_ERROR(setting, name, "should be an int64");
		return JAL_CFG_FAILURE;
	}

	// If the value for this field is empty, a 0 is returned.
	// The field should be initialized to 0 with calloc.
	*field = config_setting_get_int64(member);
	return JAL_CFG_SUCCESS;
}

int jal_config_lookup_list(const config_setting_t *setting,
	const char *name, config_setting_t **list, int *list_length, int required) {
	if (!setting || !name || !list || !list_length) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_lookup_list\n");
		return JAL_CFG_FAILURE;
	}

	*list = config_setting_get_member(setting, name);

	if (!*list && required) {
		CONFIG_ERROR(setting, name, "expected non-empty list");
		return JAL_CFG_FAILURE;
	}

	if (!*list) {
		return JAL_CFG_SUCCESS;
	}

	if (!config_setting_is_list(*list) && !config_setting_is_array(*list)) {
		CONFIG_ERROR(setting, name, "expected non-empty list");
		return JAL_CFG_FAILURE;
	}

	*list_length = config_setting_length(*list);

	if (0 >= *list_length) {
		CONFIG_ERROR(setting, name, "expected at least 1 element in list");
		return JAL_CFG_FAILURE;
	}

	return JAL_CFG_SUCCESS;
}

int jal_config_get_elem_group(const config_setting_t *setting, int idx, config_setting_t **group, const char *name) {
	if (!setting || !name) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_get_elem_group\n");
		return JAL_CFG_FAILURE;
	}

	*group = config_setting_get_elem(setting, idx);

	if (!config_setting_is_group(*group)) {
		CONFIG_ERROR(*group, name, " expected group for %s[%u]", name, idx);
		return JAL_CFG_FAILURE;
	}

	return JAL_CFG_SUCCESS;
}

int jal_config_get_elem_string(const config_setting_t *setting, int idx, char **str, const char *name) {
	if (!setting || !name || !str || *str) {
		// library error, should never happen
		fprintf(stderr, "Error: misuse of jal_config_get_elem_string\n");
		return JAL_CFG_FAILURE;
	}

	config_setting_t *elem = config_setting_get_elem(setting, idx);

	if (CONFIG_TYPE_STRING != config_setting_type(elem)) {
		CONFIG_ERROR(setting, name, "Expected non-empty string for %s[%u]", name, idx);
		return JAL_CFG_FAILURE;
	}

	const char *tmp_str = config_setting_get_string(elem);

	if (!tmp_str) {
		CONFIG_ERROR(setting, name, "Expected non-empty string for %s[%u]", name, idx);
		return JAL_CFG_FAILURE;
	}

	*str = strdup(tmp_str);

	if (NULL == *str) {
		fprintf(stderr, "strdup failed: insufficient memory");
		return JAL_CFG_FAILURE;
	}

	return JAL_CFG_SUCCESS;
}

int jal_config_get_elem_int(const config_setting_t *setting, int idx, int *value, const char *name) {
	if (!setting || !name || !value) {
		// library error, misuse of jal_config_get_elem_int
		fprintf(stderr, "Error: misuse of jal_config_get_elem_int\n");
		return JAL_CFG_FAILURE;
	}

	config_setting_t *elem = config_setting_get_elem(setting, idx);

	if (CONFIG_TYPE_INT != config_setting_type(elem)) {
		CONFIG_ERROR(setting, name, "Expected integer value for %s[%u]", name, idx);
		return JAL_CFG_FAILURE;
	}

	*value = config_setting_get_int(elem);
	return JAL_CFG_SUCCESS;
}

char* jal_expand_home_dir(const char *raw_path, const char *key_name)
{
	//Check if source string is NULL
	if (raw_path == NULL)
	{
		 printf("File path for key %s is empty.\n", key_name);
		 return NULL;
	}

	char *curr_path = (char *)raw_path;
	char *return_path = NULL;

	//Replaces paths that start with '~' with user home directory
	if (strlen(curr_path) >= 2 && curr_path[0] == '~' && curr_path[1] == '/')
	{
		const char *home_dir = getenv("HOME");
		if (home_dir == NULL)
		{
			struct passwd *curr_pwd_uid = getpwuid(getuid());

			if (curr_pwd_uid == NULL)
			{
				fprintf(stderr, "Failed to retrieve user info.\n");
				return NULL;
			}
			else
			{
				home_dir = curr_pwd_uid->pw_dir;
			}
		}

		if (home_dir == NULL)
		{
			fprintf(stderr, "Failed to retrieve user home directory path.\n");
			return NULL;
		}

		//removes "~"
		curr_path++;

		//Combines home dir path with config path
		return_path = (char*)calloc(strlen(home_dir) + strlen(curr_path) + 1, sizeof(char));
		if (return_path == NULL)
		{
			fprintf(stderr, "Failed to allocate space to expand file path.\n");
			return NULL;
		}

		sprintf(return_path, "%s%s", home_dir, curr_path);
	}
	else
	{
		//Creates copy of original file path to return, since no home dir expansion is required
		return_path = strdup(curr_path);
	}

	return return_path;
}

char* jal_expand_path(const char *raw_path, const char *key_name)
{
	//Check if source string is NULL
	if (raw_path == NULL)
	{
		 printf("File path for key %s is empty.\n", key_name);
		 return NULL;
	}

	//First expand home dir if ~/ exists at the start of the file path
	char *curr_path = jal_expand_home_dir(raw_path, key_name);
	char *absolute_path = NULL;

	if (curr_path == NULL)
	{
		//Error displayed in method call above.
		return NULL;
	}

	//Fixes relative paths
	absolute_path = realpath(curr_path, NULL);
	free(curr_path);
	if (absolute_path == NULL)
	{
		fprintf(stderr, "Failed to convert path \"%s\" for key \"%s\" to absolute path\n", raw_path, key_name);
		return NULL;
	}

	return absolute_path;
}