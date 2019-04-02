/**
 * @file jaln_connection.h This file contains function
 * declarations for internal library functions related to a jaln_connection
 * structure.
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
#ifndef _JALN_CONNECTION_H_
#define _JALN_CONNECTION_H_
#include <jalop/jaln_network.h>
#include <vortex.h>

struct jaln_connection {
	jaln_context *jaln_ctx;
	VortexConnection *v_conn;
	jaln_session *journal_sess;
	jaln_session *audit_sess;
	jaln_session *log_sess;
	void *user_data;
};

/**
 * Create a jaln_connection object
 */
struct jaln_connection *jaln_connection_create();

/**
 * Destroy a jaln_connection object
 *
 * @param[in] conn The connection object to destroy.
 */
void jaln_connection_destroy(struct jaln_connection **conn);

#endif // _JALN_CONNECTION_H_

