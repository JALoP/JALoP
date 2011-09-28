/**
 * @file jaln_network.h
 *
 * Public functions for creating and configuring a jaln_context.
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
#ifndef _JALN_NETWORK_H_
#define _JALN_NETWORK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>
#include <jalop/jaln_network_types.h>
#include <jalop/jaln_connection_callbacks.h>
#include <jalop/jaln_publisher_callbacks.h>
#include <jalop/jaln_subscriber_callbacks.h>

/**
 * Create and initialize a new jaln_context
 * @return A pointer to the new context
 */
jaln_context *jaln_context_create(void);

/**
 * Destroy a jaln_context
 * All connections using this context must have already been shutdown via
 * jaln_disconnect or jaln_shutdown.
 *
 * If the \p jaln_context is still connected to remotes, this function will return
 * an error.
 *
 * @param[in,out] jaln_ctx the context to destroy. If the jaln_ctx is \p jaln_ctx will be set to
 * NULL.
 *
 * @return JAL_OK if the context was destroyed, or an error code.
 */
enum jal_status jaln_context_destroy(jaln_context **jaln_ctx);

/**
 * Adds the TLS profile and a connection handler to prevent showing the JALoP
 * profile in greeting messages until after TLS is negotiated. This installs a
 * default TLS handler that checks that the certificate sent by the remote side
 * matches a known certificate.
 *
 * @param[in] jaln_ctx The jaln_ctx to register the TLS profile on.
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
 * Register a callbacks that the JNL executes when channels are created and
 * closed.
 * @param jaln_ctx The context object
 * @param connection_callbacks The connection callbacks.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_register_connection_callbacks(jaln_context *jaln_ctx,
		struct jaln_connection_callbacks *connection_callbacks);

/**
 * Register the callbacks required to act as a subscriber.
 * @param jaln_ctx The context object
 * @param subscriber_callbacks The structure containing all the callbacks.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_register_subscriber_callbacks(jaln_context *jaln_ctx,
				    struct jaln_subscriber_callbacks *subscriber_callbacks);

/**
 * Register the callbacks required to act as a publisher.
 * @param[in] jaln_ctx The context object
 * @param[in] publisher_callbacks The structure containing all the callbacks.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_register_publisher_callbacks(jaln_context *jaln_ctx,
				    struct jaln_publisher_callbacks *publisher_callbacks);

/**
 * Register a new digest algorithm.
 *
 * @param[in] jal_ctx The jaln_context to associate with this the jal_digest_ctx.
 * @param[in] algorithm The name of the digest method. The JNL makes a copy of this
 * string. Algorithm names are case-insensitive, so sha256, SHA256, and sHa256
 * are all the same. The JNL strips any leading or trailing whitespace from the
 * algorithm name.
 * @param[in] digest_ctx The function pointers and data sizes for the digest algorithm.
 *
 * Based on the 'connect' message exchange, the JNL will choose a specific
 * digest algorithm for all records sent/received on a particular channel. The
 * For each record the JNL processes, it first calls digest_ctx#create,
 * followed by digest_ctx#init to create and initialize a context.
 * As bytes of the JAL records become available, the JNL feeds the message to
 * the digest context using digest_ctx#update. Once the entire message is read,
 * the JNL calls digest_ctx#final to complete processing and retrieve the
 * results of the digest calculation. Lastly, the JNL calls
 * jal_digtest_ctx#destroy to clean up any allocated memory.
 *
 * If a digest_ctx already exists for a given algorithm it is replaced. The JNL
 * assumes ownership of the jal_digest_ctx, and will call jal_digest_destroy as
 * appropriate.
 *
 * @returns JAL_OK on success
 */
enum jal_status jaln_register_digest_algorithm(jaln_context *jal_ctx,
				struct jal_digest_ctx *digest_ctx);

/**
 * Register the JALoP profile and start listening for connections. Once this
 * function is called, the \p jaln_ctx cannot be used to with calls to
 * jaln_context_subscribe or jaln_context_publish. \p jaln_context_listen may
 * be used to implement a server process that waits for remote systems to
 * connect.
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
struct jaln_connection *jaln_listen(jaln_context *jaln_ctx,
				    const char *host,
				    const int port,
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
		const char *host,
		const char *port,
		const int data_classes,
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
		const char *host,
		const char *port,
		const int data_classes,
		void *user_data);

/**
 * Disconnect from the remote peers.
 *
 * This will begin a graceful shutdown process for the connection.
 *
 * For Publishers, this means that the JNL will complete sending of any JAL
 * records, and then close the connection. If the remote end sends any digest
 * or sync messages, these will still be delivered to the application.
 *
 * For Subscribers, this means that the JNL will continue delivering data for
 * any JAL records that are currently getting transfered and deliver any
 * digest-response messages.
 *
 * Once the connection is closed, the JNL will execute
 * jaln_connection_callbacks::on_connection_close
 *
 * @param jal_conn The connection to shutdown.
 * @return JAL_OK if everything was successful, an error otherwise.
 */
enum jal_status jaln_disconnect(struct jaln_connection *jal_conn);

/**
 * Disconnect from a remote peer. This immediately sever to connection without
 * waiting for transfers to complete. To gracefully close the connection
 * applications should use jaln_disconnect.
 *
 * @param jal_conn The connection to shutdown.
 * @return JAL_OK if everything was successful, an error otherwise.
 */
enum jal_status jaln_shutdown(struct jaln_connection *jal_conn);


#ifdef __cplusplus
}
#endif

#endif // _JALN_NETWORK_
