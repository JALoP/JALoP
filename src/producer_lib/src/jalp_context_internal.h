/**
 * @file jalp_context_internal.h This file defines the private structures and
 * APIs for the jalp_producer context
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
#ifndef _JALP_CONTEXT_INTERNAL_H_
#define _JALP_CONTEXT_INTERNAL_H_

#include <openssl/pem.h>

#include <jalop/jalp_context.h>

#ifdef __cplusplus
extern "C" {
#endif

struct jalp_context_t {
	int socket; /**< The socket used to communicate with the JALoP Local Store */
	char *path; /**< The path that was originally used to connect to the socket */
	char *hostname; /**< The hostname to use when generating the application metadata sections */
	char *app_name; /**< The application name to use when generating the application metadata sections */
	struct jal_digest_ctx *digest_ctx; /**< The registered callback functions to use when creating a digest */
	RSA *signing_key; /**< The RSA private key to use when signing application metadata documents */
	X509 *signing_cert; /**< The certificate used for signing the application metadata */
};

/**
 * Disconnect to a local store. Close the file descriptor.
 *
 * @param[in] ctx The context to disconnect with.
 */
void jalp_context_disconnect(jalp_context *ctx);

/**
 * Connect to a local store.
 *
 * @param[in] ctx The context to connect with.
 *
 * @return JAL_OK on success.
 *         JAL_E_NOT_CONNECTED if a connection could not be established.
 */
enum jal_status jalp_context_connect(jalp_context *ctx);

#ifdef __cplusplus
}
#endif

#endif //_JALP_CONTEXT_INTERNAL_H_
