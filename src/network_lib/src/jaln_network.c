/**
 * @file jaln_network.c This file contains function definitions for
 * general public network library functions.
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

#include <pthread.h>
#include <axl.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>

#include "jaln_context.h"
#include "jaln_connection.h"
#include "jaln_publisher.h"

void jaln_mark_closing(jaln_session *sess)
{
	sess->closing = axl_true;
}

enum jal_status jaln_disconnect(struct jaln_connection *jal_conn)
{
	if (!jal_conn || !jal_conn->jaln_ctx) {
		return JAL_E_INVAL;
	}

	if (jal_conn->journal_sess) {
		jaln_mark_closing(jal_conn->journal_sess);
	}
	if (jal_conn->audit_sess) {
		jaln_mark_closing(jal_conn->audit_sess);
	}
	if (jal_conn->log_sess) {
		jaln_mark_closing(jal_conn->log_sess);
	}

	return JAL_OK;
}

enum jal_status jaln_shutdown(struct jaln_connection *jal_conn)
{
	if (!jal_conn) {
		return JAL_E_INVAL;
	}

	return JAL_OK;
}
