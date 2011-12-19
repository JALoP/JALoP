/**
 * @file jalu_config.c This file contains utility functions for reading
 * config files.
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
#include "jalu_config.h"

int jalu_config_lookup_string(const config_setting_t *setting,
	const char *name, char **field, int required) {
	if (!setting || !name || !field || *field) {
		//library error, should never happen
		fprintf(stderr, "Error: misuse of jalls_config_lookup_string\n");
		goto err_out;
	}
	config_setting_t *member = config_setting_get_member(setting, name);
	if (!member && required) {
		fprintf(stderr, "Config Error: line %d: missing required field \"%s\"\n",
			config_setting_source_line(setting), name);
		goto err_out;
	}
	if (!member) {
		goto out;
	}
	if(config_setting_type(member) != CONFIG_TYPE_STRING) {
		fprintf(stderr, "Config Error: line %d: field \"%s\" should be a string\n",
			config_setting_source_line(member), name);
		goto err_out;
	}
	const char *tmp = config_setting_get_string(member);
	if (!tmp && required) {
		fprintf(stderr, "Config Error: line %d: empty required field \"%s\"\n",
			config_setting_source_line(setting), name);
		goto err_out;
	}
	if (!tmp) {
		fprintf(stderr, "Config Warning: line %d: empty value for field \"%s\"\n",
			config_setting_source_line(setting), name);
		goto out;
	}
	*field = strdup(tmp);
	if (*field == NULL) {
		fprintf(stderr, "strdup failed: insufficient memory");
		goto err_out;
	}
out:
	return 0;

err_out:

	return -1;
}


