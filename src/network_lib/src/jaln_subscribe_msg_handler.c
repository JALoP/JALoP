/**
 * @file jaln_subscribe_msg_handler.c This file contains the function
 * definitions for helper functions used to process an 'initialize'
 * message.
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

#include <jalop/jaln_network_types.h>

#include "jal_alloc.h"

#include "jaln_subscribe_msg_handler.h"
#include "jaln_message_helpers.h"
#include "jaln_strings.h"

enum jal_status jaln_process_subscribe(VortexFrame *frame)
{
	if (!frame) {
		return JAL_E_INVAL;
	}
	enum jal_status ret = JAL_E_INVAL;

	if (!jaln_check_content_type_and_txfr_encoding_are_valid(frame)) {
		goto err_out;
	}

	const char *msg = VORTEX_FRAME_GET_MIME_HEADER(frame, JALN_HDRS_MESSAGE);
	if (!msg) {
		goto err_out;
	}
	if (0 != strcasecmp(msg, JALN_MSG_SUBSCRIBE)) {
		goto err_out;
	}

	ret = JAL_OK;
	goto out;

err_out:
out:
	return ret;
}

