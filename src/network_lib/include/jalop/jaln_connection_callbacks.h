/**
 * @file jaln_connection_callbacks.h Thise file declares jaln_connection_callbacks
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
#ifndef _JALN_CONNECTION_CALLBACKS_H_
#define _JALN_CONNECTION_CALLBACKS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/jaln_network_types.h>
#include <stdlib.h>

/**
 * Structure that contains all the callback methods an application should
 * implement to allow/deny connections and be notified when channels close.
 */
struct jaln_connection_callbacks {
	/**
	 * The JNL will execute this callback when it receives a 'initialize'
	 * message from the remote peer.
	 * @param[in] req A structure containing the connection info requested by
	 * the peer, including additional MIME headers.
	 *
	 * @param[in,out] selected_encoding Indicates which encoding the JNL is going
	 * to select. Applications may change this value and override the selection
	 * made by JNL.
	 * The index starts at zero, so if the remote peer indicates
	 * @verbatim
	 * accept-encoding: exi, xml
	 * @endverbatim
	 * The application would signal 'EXI' by setting selected_encoded to 0, or
	 * signal XML by setting selected_encoded to 1. The application may
	 * refuse all encodings by setting selected_encoded to -1.
	 * @param[in,out] selected_digest Indicates which digest method the JNL is
	 * going to select. Applications may change this value and override the selection
	 * made by JNL.
	 * The index starts at zero, so if the remote peer indicates
	 * @verbatim
	 * accept-digest: sha512, sha256
	 * @endverbatim
	 * The application would signal 'sha512' by setting selected_digest to 0, or
	 * signal sha256 to 1. The application may refuse all digest methods by setting
	 * selected_encoded to -1.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @returns JALN_CE_ACCEPT to accept the connection, or any of the
	 * or'ed combination of jaln_connect_errors to indicate the failure to return.
	 *
	 * @note: This limits applications to a single error code. In
	 * practice this is probably fine, but not sure it should be so limited...
	 *
	 *
	 */
	enum jaln_connect_error (*connect_request_handler)(const struct jaln_connect_request *const req,
			int *selected_encoding,
			int *selected_digest,
			void *user_data);

	/**
	 * Notify the application that a channel was closed.
	 * @param[in] channel_info Information about the channel that is closing.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 */
	void (*on_channel_close)(const struct jaln_channel_info *const channel_info,
		void *user_data);

	/**
	 * Notify the application when all channels for a connection have
	 * closed.
	 * @param[in] jaln_conn The connection object. The JNL releases this
	 * object when the function returns.
	 */
	void (*on_connection_close)(const struct jaln_connection *const jal_conn, void *user_data);

	/**
	 * The JNL will execute this callback when it receives a 'connect-ack'
	 * message from the remote peer.
	 * @param[in] ack A structure containing information about the connection,
	 * including the MIME headers.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @see jaln_connect_ack
	 */
	void (*connect_ack)(const struct jaln_connect_ack *const ack,
			    void *user_data);

	/**
	 * The JNL will execute this callback when it receives a 'connect-nack'
	 * message from the remote peer.
	 * @param nack The failure reasons given by the remote peer.
	 * This includes any additional MIME headers.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 */
	void (*connect_nack)(const struct jaln_connect_nack *const nack,
			     void *user_data);
};

/**
 * Create a jaln_connection_callbacks structure
 *
 * @return a newly created and initialized jaln_conection_callbacks structure.
 */
struct jaln_connection_callbacks *jaln_connection_callbacks_create();

/**
 * Destroy a jaln_connection_callbacks structure
 *
 * @param[in,out] callbacks The structure to destroy
 */
void jaln_connection_callbacks_destroy(struct jaln_connection_callbacks **callbacks);

#ifdef __cplusplus
}
#endif

#endif // _JALN_CONNECTION_CALLBACKS_H_
