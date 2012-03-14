/**
 * @file jalp_send_helper_internal.h This file contains functions for sending an xml buffer.
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

#ifndef _JALPX_SEND_HELPER_INTERNAL_HPP_
#define _JALPX_SEND_HELPER_INTERNAL_HPP_

#include <jalop/jal_status.h>
#include <unistd.h> // for size_t
#include "jalp_connection_internal.h"
#include "jalp_context_internal.h"

/**
 * Send a buffer and app metadata using jalp_send_buffer().
 *
 * @param[in] ctx a #jalp_context that will be used to send the buffer.
 *
 * @param[in] app_meta The application metadata document.
 *
 * @param[in] buffer A buffer for the data record..
 *
 * @param[in] buffer_size The length of the data record.
 *
 * @param[in] message_type The type of this message.  This should be
 * one of the #jalp_connection_msg_type enums. It is either a log record
 * or a journal record.
 *
 * @return JAL_OK if the message was sent correctly.  JAL_E_INVAL on error.
 */
enum jal_status jalpx_send_buffer_xml(jalp_context *ctx,
		struct jalp_app_metadata *app_meta, const uint8_t *buffer,
		const size_t buffer_size, enum jalp_connection_msg_type message_type);

#endif // JAL_SEND_HELPER_INTERNAL_HPP

