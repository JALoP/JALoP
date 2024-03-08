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
	 * Notify the application that a channel was closed.
	 * @param[in] channel_info Information about the channel that is closing.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_publish.
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
	 * or \p jaln_publish.
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
	 * \p jaln_publish.
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
