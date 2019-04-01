/**
 * @file jaln_network.h
 *
 * Public functions for creating and configuring a jaln_context.
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
 * closed.  The network library assumes ownership of the jaln_connection_callbacks
 * struct and will free it when jaln_destroy_ctx() is called
 *
 * @param jaln_ctx The context object
 * @param connection_callbacks The connection callbacks.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_register_connection_callbacks(jaln_context *jaln_ctx,
		struct jaln_connection_callbacks *connection_callbacks);

/**
 * Register the callbacks required to act as a subscriber.  The network library
 * will create a copy of the jaln_subscriber_callbacks_struct.  The calling process
 * should free the original struct with jaln_subscriber_callbacks_destroy().
 *
 * @param jaln_ctx The context object
 * @param subscriber_callbacks The structure containing all the callbacks.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_register_subscriber_callbacks(jaln_context *jaln_ctx,
				    struct jaln_subscriber_callbacks *subscriber_callbacks);

/**
 * Register the callbacks required to act as a publisher.  The network library
 * will create a copy of the jaln_publisher_callbacks_struct.  The calling process
 * should free the original struct with jaln_publisher_callbacks_destroy().
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
 * Register digest challenge configuration.
 *
 * @param[in] jal_ctx The jaln_context to associate with the digest challenge
 *            configuration.
 * @param[in] dc_configuration Representation
 *
 * Based on the initialization message exchange, the JNL will choose a whether
 * digest challenges will be required for all records sent over a particular
 * channel. The configuration(s) registered with this function are permitted
 * for connections made with context \p jal_ctx. Accepted values are "on" or
 * "off" for \p dc_configuration.
 *
 * If a digest challenge configuration has already been associated with this
 * context, the configuration is the union of \p dc_configuration and the
 * existing value. Preference is given to the first value registered.
 *
 * @returns JAL_OK on success
 */
enum jal_status jaln_register_digest_challenge_configuration(
				jaln_context *jal_ctx,
				const char *dc_configuration);

/**
 * Register the JALoP profile and start listening for connections. Once this
 * function is called, the \p jaln_ctx cannot be used to with calls to
 * jaln_context_subscribe or jaln_context_publish. \p jaln_context_listen may
 * be used to implement a server process that waits for remote systems to
 * connect.
 *
 * Once called, the caller must ensure the program continues to run to keep the
 * connections active. This may be accomplished via an external event loop, or
 * by calling jaln_listener_wait().
 *
 * When the program is ready to shutdown, it should call
 * jaln_listener_shutdown().
 *
 * @param[in] jaln_ctx The jaln_context that will parse incoming and format
 *            outgoing JALoP messages.
 * @param[in] host the host interface IP to listen on
 * @param[in] port The port to listen on
 * @param[in] user_data An address that will be passed into all the callback
 * methods.
 *
 * @return JAL_OK on success, or an error.
 *
 */
enum jal_status jaln_listen(jaln_context *jaln_ctx,
				    const char *host,
				    const char *port,
				    void *user_data);

/**
 * Shutdown a listener. This will close all connections of a jaln_context used
 * as a listener.
 *
 * @param[in] ctx The context to shutdown.
 *
 * @return JAL_OK on success, or an error code.
 *
 */
enum jal_status jaln_listener_shutdown(jaln_context *ctx);

/**
 * Block the calling thread until the all connections are closed and the
 * listener is finished.
 *
 * @param[in] ctx The context to wait on.
 * 
 * @return JAL_OK on success, or an error.
 */
enum jal_status jaln_listener_wait(jaln_context *ctx);

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
 * @param[in] mode Indicates if the session should be in archive or live mode.
 * @param[in] user_data An address that will be passed into all the callback
 * methods.
 * @return A connection object that represents the link to the remote peer.
 */
struct jaln_connection *jaln_subscribe(
		jaln_context *ctx,
		const char *host,
		const char *port,
		const int data_classes,
		enum jaln_publish_mode mode,
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
 * @param mode The mode (archive or live) to publish in.
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
		enum jaln_publish_mode mode,
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

/**
 * Determine if a session is OK.
 *
 * This function may be called to determine if a session is still active, for
 * example, if a publisher is waiting for more records to send to the remote,
 * it should periodically call this function to determine if the remote is
 * still connected. Otherwise, the internal resources can never be reclaimed.
 *
 * @param[in] sess The session containg the connection and subscriber information
 *  
 * @return JAL_OK if the session is active, or an error if the connection was
 * disconnected.
 */
enum jal_status jaln_session_is_ok(jaln_session *sess);

/**
 * Send the journal record to the awaiting subscriber.
 *
 * This method should be called to send a journal record to the awaiting
 * subscriber. The method expects the calling implementation to obtain
 * and provide the journal record information and provide a payload feeder
 * that will be used to read the journal payload data. The calling implementation
 * is in charge of freeing the allocated resources.
 *
 * @param[in] sess The session containg the connection and subscriber information
 * @param[in] nonce The current record sequence id
 * @param[in] sys_meta_buf The buffer containing the system metadata
 * @param[in] sys_meta_len The length of the system metadata buffer
 * @param[in] app_meta_buf The buffer containing the application metadata
 * @param[in] app_meta_len The length of the system metadata buffer
 * @param[in] payload_len The length of the payload buffer
 * @param[in] feeder The payload feeder that will be used to read the journal data
 *
 * @return JAL_OK on successfully sending the journal record or an error otherwise
 */
enum jal_status jaln_send_journal(
			jaln_session *sess,
			char *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len,
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			uint64_t payload_len,
			struct jaln_payload_feeder *feeder);

/**
 * Send the audit record to the awaiting subscriber.
 *
 * This method should be called to send an audit record to the awaiting
 * subscriber. The method expects the calling implementation to obtain
 * and provide the audit record information. The calling implementation
 * is in charge of freeing the allocated resources.
 *
 * @param[in] sess The session containg the connection and subscriber information
 * @param[in] nonce The current record sequence id
 * @param[in] sys_meta_buf The buffer containing the system metadata
 * @param[in] sys_meta_len The length of the system metadata buffer
 * @param[in] app_meta_buf The buffer containing the application metadata
 * @param[in] app_meta_len The length of the system metadata buffer
 * @param[in] payload_buf The buffer containing the audit record
 * @param[in] payload_len The length of the payload buffer
 *
 * @return JAL_OK on successfully sending the audit record or an error otherwise
 */
enum jal_status jaln_send_audit(
			jaln_session *sess,
			char *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len,
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			uint8_t *payload_buf,
			uint64_t payload_len);

/**
 * Send the log record to the awaiting subscriber.
 *
 * This method should be called to send a log record to the awaiting
 * subscriber. The method expects the calling implementation to obtain
 * and provide the log record information. The calling implementation
 * is in charge of freeing the allocated resources.
 *
 * @param[in] sess The session containing the connection and subscriber information
 * @param[in] nonce The current record sequence id
 * @param[in] sys_meta_buf The buffer containing the system metadata
 * @param[in] sys_meta_len The length of the system metadata buffer
 * @param[in] app_meta_buf The buffer containing the application metadata
 * @param[in] app_meta_len The length of the system metadata buffer
 * @param[in] payload_buf The buffer containing the log record
 * @param[in] payload_len The length of the payload buffer
 *
 * @return JAL_OK on successfully sending the log record or an error otherwise
 */
enum jal_status jaln_send_log(
			jaln_session *sess,
			char *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len,
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			uint8_t *payload_buf,
			uint64_t payload_len);

/**
 * Notify the library that the publisher is finished sending records.
 *
 * This method should be called when all records have been sent. The
 * method will send the final message to the subscriber, indicating
 * that the record sending has been completed. This method will also
 * attempt to close the channel used to send the records.
 *
 * @param[in] sess The session containing the connection information
 *
 * @return JAL_OK on success or an error otherwise
 */
enum jal_status jaln_finish(jaln_session *sess);

#ifdef __cplusplus
}
#endif

#endif // _JALN_NETWORK_
