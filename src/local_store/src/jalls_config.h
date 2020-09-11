/**
 * @file jalls_config.h This file contains functions for parsing the local store
 * config file.
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


#ifndef _JALLS_CONFIG_H_
#define _JALLS_CONFIG_H_

#include <libconfig.h>
#include "jalls_context.h"

#define JALLS_CFG_DB_DEFAULT "/var/lib/jalop/db"
#define JALLS_CFG_SOCKET_DEFAULT "/var/run/jalop/jalop.sock"
#define JALLS_CFG_ACCEPT_DELAY_THREAD_COUNT_DEFAULT 10
#define JALLS_CFG_ACCEPT_DELAY_INCREMENT_DEFAULT 100
#define JALLS_CFG_ACCEPT_DELAY_MAX_DEFAULT 10000000

#define JALLS_CFG_PRIVATE_KEY_FILE "private_key_file"
#define JALLS_CFG_PUBLIC_CERT_FILE "public_cert_file"
#define JALLS_CFG_SYSTEM_UUID "system_uuid"
#define JALLS_CFG_HOSTNAME "hostname"
#define JALLS_CFG_DB_ROOT "db_root"
#define JALLS_CFG_SOCKET "socket"
#define JALLS_CFG_SIGNATURE "sign_sys_meta"
#define JALLS_CFG_MANIFEST "manifest_sys_meta"
#define JALLS_CFG_SCHEMAS_ROOT "schemas_root"
#define JALLS_CFG_ACCEPT_DELAY_THREAD_COUNT "accept_delay_thread_count"
#define JALLS_CFG_ACCEPT_DELAY_INCREMENT "accept_delay_increment"
#define JALLS_CFG_ACCEPT_DELAY_MAX "accept_delay_max"

/**
 * Parses the config file and fills out the jalls_context struct.
 *
 * @param[in] config_file_path The full path to the config file to parse.
 * @param[out] jalls_ctx A pointer to point to the resulting jalls_context struct
 * that will hold the parsed fields. The function will allocate the struct and fields,
 * but the caller assumes ownership of all pointers.
 * @return 0 on success, -1 on failure.
*/
int jalls_parse_config(const char *config_file_path, struct jalls_context **jalls_ctx);


#endif // _JALLS_CONFIG_H_
