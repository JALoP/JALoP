/**
 * @file jaln_subscribe_msg_handler.h This file contains the function
 * declarations for helper functions used to process an 'initialize'
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

#ifndef JALN_SUBSCRIBE_MSG_HANDLER
#define JALN_SUBSCRIBE_MSG_HANDLER
#include <vortex.h>

/**
 * Helper to process the contents of an 'initialize' message
 *
 * @param[in] frame The frame to inspect
 * @param[out] sid The serial ID indicated in the subscribe message.
 *
 * @return JAL_OK on success, or JAL_E_INVAL if there was an error.
 */
enum jal_status jaln_process_subscribe(VortexFrame *frame, char **sid);

#endif // JALN_SUBSCRIBE_MSG_HANDLER
