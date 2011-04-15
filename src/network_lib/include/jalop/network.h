/**
 * @file network.h
 *
 * Public API for functions, structures and enums shared by both publisher and
 * subscriber code.
 *
 * @section LICENSE
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
#ifndef JALN_NETWORK_H
#define JALN_NETWORK_H
#include <jalop/network_callbacks.h>
#include <jalop/network_types.h>
/**
 * Adds the TLS profile and a connection handler to prevent showing the JALoP
 * profile in greeting messages until after TLS is negotiated. This installs a
 * default TLS handler that checks that the certificate sent by the remote side
 * matches a known certificate.
 *
 * @param[in] jaln_ctx The JAL ctx to register the TLS profile on.
 * @param[in] private_key The private key that should be used for TLS
 * @param[in] public_cert The public certificate for the private key
 * @param[in] peer_certs A directory containing certificates for remote peers.
 * @return JAL_OK, or an error code.
 */
enum jal_status jaln_register_tls(jaln_context *jaln_ctx,
				  const char *private_key,
				  const char *public_cert,
				  const char *peer_certs);

/**
 * Register a XML encoding.
 * By default, the JNL will only accept or send 'XML' as an encoding for the
 * metadata and audit records. Applications may choose to support additional
 * encodings (such as EXI, deflate, etc) by calling this function.
 *
 * When the JNL initiates a connection to a remote peer, it will propose all
 * registered encodings. When the JNL receives a connection request, it will
 * auto-select which encoding to use. Applications may select a different
 * encoding in their jaln_connect_handler.
 *
 * Converting XML to other formats must be handled by the application.
 *
 * @param jaln_ctx The context to add the encoding to.
 * @param encoding The encoding to add to the list.
 * @return JAL_OK on success.
 */
enum jal_status jaln_register_encoding(jaln_context *jaln_ctx,
				  const char *encoding);
/**
 * Create and initialize a new jaln_context
 * @return A pointer to the new context
 */
jaln_context *jaln_context_create(void);
/**
 * Retain a hold on the jaln_context
 *
 * @param[in] jaln_ctx The context to keep a reference on.
 * @return JAL_OK on success, or an error code.
 *
 */
enum jal_status jaln_context_add_ref(jaln_context *jaln_ctx);
/**
 * Release a hold on the jaln_context
 *
 * @param[in] jaln_ctx The context to release.
 * @return JAL_OK on success, or an error code.
 *
 */
enum jal_status jaln_context_release(jaln_context *jaln_ctx);
/**
 * Register a callbacks that the JNL executes when channels are created and
 * closed.
 * @param jaln_ctx The context object
 * @param connection_handlers The connection handlers.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_register_connection_handlers(jaln_context *jaln_ctx,
		struct jaln_connection_handlers *connection_handlers);

/**
 * Register the callbacks required to act as a subscriber.
 * @param jaln_ctx The context object
 * @param subscriber_callbacks The structure containing all the callbacks.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_register_subscriber_callbacks(jaln_context *jaln_ctx,
				    struct jaln_publisher_callbacks subscriber_callbacks);

/**
 * Register the callbacks required to act as a publisher.
 * @param[in] jaln_ctx The context object
 * @param[in] publisher_callbacks The structure containing all the callbacks.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_register_publisher_callbacks(jaln_context *jaln_ctx,
				    struct jaln_publisher_callbacks publisher_callbacks);

/**
 * Register the JALoP profile and start listening for connections. Once this
 * function is called, the \p jaln_ctx cannot be used to with calls to
 * jaln_context_subscribe or jaln_context_publish.
 *
 * @param[in] jaln_ctx The jaln_context that will parse incoming and format
 *            outgoing JALoP messages.
 * @param[in] host the host interface IP to listen on
 * @param[in] port The port to listen on
 * @param[in] user_data An address that will be passed into all the callback
 * methods.
 * @return a Connection object
 *
 */
struct jaln_connection *jaln_context_listen(jaln_context *jaln_ctx,
				    const char *host,
				    int port,
				    void *user_data);

/**
 * Connect to a remote peer and indicate a desire to receive JAL records from the
 * remote. Once connected, the JNL will execute the
 * jaln_subscriber_callbacks::get_subscribe_request for each data type
 * identified by data_classes.
 * @param[in] ctx The jaln_context to use for the connection.
 * @param[in] host The hostname or IP address of the remote to connect to.
 * @param[in] port The port to connect to.
 * @param[in] data_classes bitmask of JAL record types to publish. Must be
 * comprised of the entries of enum jaln_record_type.
 * @param[in] user_data An address that will be passed into all the callback
 * methods.
 * @return A connection object that represents the link to the remote peer.
 */
struct jaln_connection *jaln_subscribe(
		jaln_context *ctx,
		char *host,
		char *port,
		int data_classes,
		void *user_data);

/**
 * Connect to a remote peer and indicate a desire to send JAL records to the
 * remote. The remote peer will need to send appropriate 'subscribe'
 * messages.
 * @param ctx The context to use for the connection.
 * @param host The host, as and IP address or hostname, to connect to.
 * @param port The port to connect to on the remote peer.
 * @param data_classes bitmask of JAL record types to publish. Must be
 * comprised of the entries of enum jaln_record_type.
 * @param[in] user_data An address that will be passed into all the callback
 * methods.
 *
 * @return a jaln_connection object
 */
struct jaln_connection *jaln_publish(
		jaln_context *ctx,
		char *host,
		char *port,
		int data_classes,
		void *user_data);


/**
 * Disconnect from a remote peer. This immediately sever to connection without
 * waiting for transfers to complete. To gracefully close connections,
 * applications should return something other than JAL_OK in their callbacks.
 *
 * @param jal_conn The connection to shutdown.
 * @return JAL_OK if everything was successful, an error otherwise.
 */
enum jaln_status jaln_shutdown(struct jaln_connection *jal_conn);

#endif // JALN_NETWORK
