/**
 * @file jaln_sync_msg_handler.h This file contains the function
 * declarations for helper functions used to process an 'sync'
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

#ifndef JALN_SYNC_MSG_HANDLER
#define JALN_SYNC_MSG_HANDLER

#include <jalop/jal_status.h>
#include <vortex.h>

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Helper utility that processes a 'sync' message and extracts the nonce.
 *
 * @param[in] frame The Vortex frame to operate on.
 * @param[out] nonce This will get set to the nonce indicated in the
 * sync message. The caller is responsible for freeing this.
 *
 * @return JAL_OK on success, or JAL_E_INVAL.
 */
enum jal_status jaln_process_sync(VortexFrame *frame, char **nonce);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // JALN_SYNC_MSG_HANDLER
