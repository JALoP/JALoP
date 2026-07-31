/**
 * @file
 *
 * @brief This file contains function
 * declarations related to publishing records to a remote.
 *
 * ### LICENSE
 *
 * Copyright (C) 2018-2026 Concurrent Technologies Corporation.
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

#ifndef JALN_PUBLISHER_H
#define JALN_PUBLISHER_H

#include <axl.h>
#include <jalop/jaln_network.h>
#include <curl/curl.h>

#include "jaln_session.h"
#include "jaln_digest_resp_info.h"
#include "jaln_digest_info.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Helper function to create a jaln_session for use as a publisher.
 *
 * @param[in] ctx The jaln_context associated with the session.
 * @param[in] host The IP/hostname of the remote
 * @param[in] type The type of records that will be sent using this session.
 *
 * @return a configured jaln_session.
 */
jaln_session *jaln_publisher_create_session(jaln_context *ctx, const char *host, enum jaln_record_type type);

/**
 * Send initialize message to subscriber and parse the returned
 * initialize-ack message.
 *
 * @param[in] session The session to initialize.
 */
enum jal_status jaln_publisher_send_init(jaln_session *session);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // JALN_PUBLISHER_H
