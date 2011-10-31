/**
 * @file jaln_connection_request.h This file contains functions related to a
 * jaln_connect_request structure.
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

#ifndef JALN_CONNECT_REQUEST_H
#define JALN_CONNECT_REQUEST_H

#include <axl.h>
#include <jalop/jaln_network_types.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a jaln_connect_request structure.
 *
 * @return A new jaln_connect_request structure.
 */
struct jaln_connect_request *jaln_connect_request_create();

/**
 * Destroy a jaln_connect_request structure.
 *
 * @param[in,out] dgst_info The dgst_info structure to destroy. This will be
 * set to NULL.
 */
void jaln_connect_request_destroy(struct jaln_connect_request **conn_req);

#ifdef __cplusplus
}
#endif
#endif //JALN_CONNECT_REQUEST_H
