/**
 * @file jalls_handler.h This file contains functions to handle a connection
 * to the jalp local store.
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

#ifndef _JALLS_HANDLER_H_
#define _JALLS_HANDLER_H_

#include "jalls_context.h"

/**
 * Waits for data to become available on the domain socket. When data appears,
 * calls handle_audit() handle_log(), handle_journal(), or handle_journal_fd(),
 * depending on the message type.
 *
 * @param[in] thread_ctx A pointer to a jalls_thread_context struct that holds
 * the fd for the connection, the key and cert to sign the system metadata,
 * and the jalls_context.
*/
void *jalls_handler(void *thread_ctx);

#endif //_JALLS_HANDLER_H_
