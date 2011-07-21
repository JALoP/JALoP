/**
 * @file jalp_logger.c This file defines functions for sending log messages.
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

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <jalop/jal_status.h>
#include <jalop/jalp_app_metadata.h>
#include "jalp_context_internal.h"
#include "jalp_connection_internal.h"
#include "jalp_send_helper_internal.h"


enum jal_status jalp_log(jalp_context *ctx, struct jalp_app_metadata *app_meta,
		uint8_t *log_buffer, size_t log_buffer_size)
{
	// app_meta and log_buffer can't both be NULL, we need at least one of them
	if (!log_buffer && !app_meta) {
		return JAL_E_INVAL;
	}

	// if log_buffer is NULL, then log_buffer_size must be 0
	if (log_buffer == NULL && log_buffer_size != 0) {
		return JAL_E_INVAL;
	}

	// if log_buffer is not NULL, then log_buffer_size must be greater than 0
	if (log_buffer != NULL && log_buffer_size == 0) {
		return JAL_E_INVAL;
	}

	return jalp_send_buffer_xml(ctx, app_meta, log_buffer,
			log_buffer_size, JALP_LOG_MSG);
}
