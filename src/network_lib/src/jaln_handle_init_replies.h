/**
 * @file jaln_handl_init_replies.h This file contains function
 * declarations for internal library functions related to processing responses
 * to 'initialize' messages (init-ack/init-nack).
 *
 * @section LICENSE
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
#ifndef JALN_HANDLE_INIT_REPLIES_H_
#define JALN_HANDLE_INIT_REPLIES_H_

#include <axl.h>

#include "jaln_session.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Common utility to process an 'initialize-nack' message.
 * This will fill in the \p chan object with the data obtained in the response.
 * In addition, this function will execute the user initialize_nack() function
 * of the connection_callbacks
 *
 * @param[in] sess Then session to operate on.
 * @param[in] frame The frame that contains the 'initialze-nack' message.
 * @return axl_false if there were errors processing the message, axl_true otherwise.
 */
axl_bool jaln_handle_initialize_nack(struct jaln_session *sess,
		VortexFrame *frame);

/**
 * Common utility to process an 'initialize-ack' message.
 * This will fill in the \p session object with the data obtained in the response.
 * In addition, this function will execute the user initialize_ack() function
 * of the connection_callbacks
 *
 * @param[in] session Then session to operate on.
 * @param[in] role The role for this channel (publish or subscribe)
 * @param[in] frame The frame that contains the 'initialze-ack' message.
 * @return 0 if there were errors processing the message, 1 otherwise.
 */
axl_bool jaln_handle_initialize_ack(struct jaln_session *session,
		enum jaln_role role,
		VortexFrame *frame);

#ifdef __cplusplus
}
#endif
#endif // JALN_HANDLE_INIT_REPLIES_H_
