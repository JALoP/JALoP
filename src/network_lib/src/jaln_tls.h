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

#include <axl.h>
#include <vortex.h>

/**
 * A handler used to verify that the connection being requested is
 * utilizing the TLS profile.  If the profile being requested is not
 * TLS and the connection is not already utilizing TLS, the profile is
 * filtered and the connection will be rejected.
 *
 * @param[in] connection The connection
 * @param[in] channel_num The channel number
 * @param[in] uri The vortex profile URI
 * @param[in] profile_content Additional data sent with the message to
 * creat the channel
 * @param[in] encoding The encoding for \p profile_content
 * @param[in] server_name The name of the server
 * @param[in] frame The frame that contains the channel start request (when channel > 0)
 * @param[in] error_msg Optional variable to configure an error message
 * @param[in] user_data User defined data
 *
 * @return
 * 	- axl_true (filter profile)
 * 	- axl_false (do not filter profile)
 */
axl_bool jaln_profile_mask (VortexConnection *connection,
				int channel_num,
				const char *uri,
				const char *profile_content,
				VortexEncoding encoding,
				const char *server_name,
				VortexFrame *frame,
				char **error_msg,
				axlPointer user_data);

/**
 * A handler which simply calls a method that sets a profile mask (filter)
 * on the current connection.  This is used to filter out all non-TLS
 * connections.  This handler should be used as a VortexOnAcceptedConnection
 * callback.
 *
 * @param[in] connection The connection
 * @param[in] user_data User defined data
 *
 * @return
 * 	- axl_true (connection approved)
 * 	- axl_false (connection rejected)
 */
axl_bool jaln_tls_on_connection_accepted(VortexConnection *connection,
					axlPointer user_data);

/**
 * A handler which creates an SSL_CTX object that is used to perform the
 * TLS activation.
 *
 * @param[in] connection The connection
 * @param[in] user_data This is expected to be a jaln_context object
 *
 * @return SSL_CTX object on success or NULL on error
 */
axlPointer jaln_ssl_ctx_creation(VortexConnection *connection,
				axlPointer user_data);

/**
 * Initializes TLS handling on the current vortex context and sets the default
 * SSL_CTX creation handler.  Populates the private key and cert parameters within
 * the jaln_context.  These are used within the SSL_CTX creation method for TLS activation.
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

#ifdef __cpluscplud
}
#endif

#endif // _JALN_TLS_H_
