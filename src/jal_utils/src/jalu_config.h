/**
 * @file jalu_config.h This file contains utility functions for reading config
 * files.
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

#ifndef _JALU_CONFIG_H_
#define _JALU_CONFIG_H_

#include <libconfig.h>
#include <string.h>

#define JALU_CFG_REQUIRED 1
#define JALU_CFG_OPTIONAL 0

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Wraps config_lookup_string() from libconfig for better error checking,
 * and to allocate the field instead of letting libconfig own the resulting
 * string.
 *
 *@param [in] setting The parent setting of the field to lookup.
 *@param [in] name The name of the field.
 *@param [out] field The result read from the config file will be stored here,
 * as a newly allocated string. The caller takes ownership of the pointer.
 *@param [in] required If set to JALU_CFG_REQUIRED, the function will fail if the
 * field is not found, printing an error to stderr.
 * If set to JALU_CFG_OPTIONAL, the function will return successfully and field will
 * remain unchanged.
 * @return 0 on success, -1 on failure
 */
int jalu_config_lookup_string(const config_setting_t *setting,
	const char *name, char **field, int required);

#ifdef __cplusplus
}
#endif

#endif // _JALU_CONFIG_H_
