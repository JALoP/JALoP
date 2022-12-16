/**
 * @file jaln_tls.h This file declares functions related to tls
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
#ifndef _JALN_TLS_H_
#define _JALN_TLS_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Populates the private key and cert parameters within the jaln_context.
 * These are used by the JNL for TLS activation.
 *
 * @param[in] ctx The jaln_context
 * @param[in] private_key The private key
 * @param[in] public_cert The public certificate
 * @param[in] peer_certs The peer certificates
 *
 * @return JAL_OK upon success or JAL_E_INVAL on error
 */
enum jal_status jaln_register_tls(jaln_context *ctx,
				const char *private_key,
				const char *public_cert,
				const char *peer_certs);

#ifdef __cplusplus
}
#endif

#endif // _JALN_TLS_H_
