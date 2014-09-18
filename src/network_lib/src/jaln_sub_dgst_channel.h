/**
 * @file jaln_sub_dgst_channel.h This file contains function
 * declarations for internal library functions related to the 'subscriber'
 * channel that sends 'digest' and 'sync' messages.
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

#ifndef _JALN_SUB_DGST_CHANNEL_
#define _JALN_SUB_DGST_CHANNEL_

#ifdef __cplusplus
extern "C" {
#endif

#include <vortex.h>
#include "jaln_session.h"

/**
 * Helper function that sends 'digest' and 'sync' messages. It waits for each
 * reply and calls the appropriate user provided callbacks.
 *
 * @param[in] sess The session to use.
 * @param[in] dgst_list An axlList of jaln_digest_info objects, used
 * to compose the 'digest' message.
 */
void jaln_send_digest_and_sync_no_lock(jaln_session *ctx, axlList *dgst_resp_list);

/**
 * A function that can be used as a 'VortexThread' that merely waits until a
 * maximum number of digests are calculated or for a specified timeout to
 * occur.
 *
 * @param[in] user_data This is expected to be a jaln_session pointers.
 */
axlPointer jaln_sub_dgst_wait_thread(axlPointer user_data);

/**
 * Helper function to create the thread to send 'digest' and 'sync' messages.
 *
 * @param[in] session The session to use for the new thread.
 */
void jaln_create_sub_digest_channel_thread_no_lock(jaln_session *session);

#ifdef __cplusplus
}
#endif

#endif //_JALN_SUB_DGST_CHANNEL_
