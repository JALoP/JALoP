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
/**
 * Adds the TLS profile and a connection handler to prevent showing the JALoP
 * profile in greeting messages until after TLS is negotiated. This installs a
 * default TLS handler that checks that the certificate sent by the remote side
 * matches a known certificate.
 *
 * In addition to configuring the openssl context, this also installs a 
 *
 * @param[in] jaln_ctx The JAL ctx to register the TLS profile on.
 * @param[in] private_key The private key that should be used for TLS
 * @param[in] public_cert The public certificate for the private key
 * @param[in] peer_certs A directory containing certificates for remote peers.
 * @return JAL_OK, or an error code.
 */
enum jal_status jaln_register_tls(jaln_context jaln_ctx,
				  const char *private_key,
				  const char *public_cert,
				  const char *peer_certs);

/**
 * Create and initialize a new jaln_context
 * @param[out] jaln_ctx Receives a pointer to the new context
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jaln_context_create(jaln_context *jaln_ctx);
/**
 * Retain a hold on the jaln_context
 *
 * @param[in] ctx The context to keep a reference on.
 * @return JAL_OK on success, or an error code.
 *
 */
enum jal_status jaln_context_add_ref(jaln_context ctx);
/**
 * Release a hold on the jaln_context
 *
 * @param[in] ctx The context to release.
 * @return JAL_OK on success, or an error code.
 *
 */
enum jal_status jaln_context_release(jaln_context ctx);
/**
 * Register the JALoP profile and start listening for connections. Once this
 * function is called, the \p jaln_ctx cannot be used to initiate connections
 * to remote peers.
 *
 * @param[in] jaln_ctx The jalop context that will parse incoming and format
 *            outgoing JALoP messages.
 * @param[in] host the host interface IP to listen on
 * @param[in] port The port to listen on
 * @param[in] connect_handler A user supplied callback the the jaln_ctxt
 *            will execute when it receives a JALoP 'connect' message. This provides a hook for
 *            the application to accept/reject connetions based on additional
 *            criteria.
 * @param[in] connect_data User pointer past into the connect_handler.
 * @param[in] publish_callbacks Callbacks to to use when the remote peer sends a
 * @param[in] publisher_data User pointer past into the publish_callbacks.
 *            'subscribe' message. If these are NULL, remote peers will be denied
 *            any request 'connect' request that indicates the remote peer wishes to
 *            subscribe. The JNL will send a 'unauthorized-mode' error.
 * @return JAL_OK on success, or an error.
 *
 * @note should this have a blocking alternative? i.e, if the caller passes
 * NULL for the connect_handler, block until the channel created & connected,
 * or an error occurs.
 */
enum jal_status jaln_context_listen(jaln_context jaln_ctx,
				    const char *host,
				    int port,
				    jaln_connect_handler connect_handler,
				    void *connect_data,
				    struct jaln_publisher_callbacks *publish_callbacks,
				    void *publisher_data);
/**
 * Creates a JALoP channel and sends connect message and prepare to act as
 * publisher.
 *
 * @param[in] connection An already established JALoP connection. Any security
 *            negotiations must be performed before calling this method.
 * @param[in] channel_num, a hint to the requested channel number. Specifing 0
 *            allows the implementation to auto select the channel number. This 
 *            is the preferred method of channel creation.
 * @param[in] close_handler callback to allow/deny a request to close the channel.
 *            If NULL, close requests are always honored.
 * @param[in] close_data user data passed into the close_handler
 * @param[in] on_channel_created Called when the channel is created, or an error
 *            occurs. Applications only need to provide this if they wish to take some
 *            additional action when the channel is created, or be notified of channel
 *            creation errors.
 * @param[in] channel_created_data passed into the on_channel_created handler
 * @param[in] connection_handler The set of callbacks that are called when the
 *            response to the connect message returned
 * @param[in] connect_data user pointer passed into to the handlers in
 *            jal_connection_handler
 * @param[in] publisher_callbacks Set of callbacks for to implement the
 *            'publisher' role.
 * @param[in] publisher_data user data passed into the publisher_callbacks.
 * @param[in] request The parameters of the request message.
 *
 * @return A jaln_channel.
 */
struct jaln_channel *jaln_create_publisher_channel(
				jaln_connection connection,
				int channel_num,
	 			jaln_on_close_handler close_handler,
		 		void *close_data,
			 	jaln_on_channel_created on_channel_created,
				void *channel_created_data,
				struct jaln_connection_response_handlers *connection_handler,
				void *connect_data,
				struct jaln_publisher_callbacks *publisher_callbacks,
				void *publisher_data,
				struct jaln_connect_request *request
				 );

/**
 * Create a jalop channel and send the initial 'connect' message. Note that
 * this does not send a subscribe message. After the channel is connected, and
 * the initial connect message is sent, applications may wish to send any
 * number of 'journal-resume' messages. They should complete all
 * 'journal-resume' transactions before sending a 'subscribe'. The application
 * must provide the jal_connection_handler in order to start sending messages
 * once the channel is created and the initial 'connect' is sent.
 *
 * @param[in] connection An already established JALoP connection. Any security
 *            negotiations must be performed before calling this method.
 * @param[in] channel_num, a hint to the requested channel number. Specifing 0
 *            allows the implementation to auto select the channel number.
 *            This is the preferred method of channel creation.
 * @param[in] close_handler callback to allow/deny a request to close the channel.
 *            If NULL, close requests are always honored.
 * @param[in] close_data user data passed into the close_handler
 * @param[in] on_channel_created Called when the channel is created. This is
 *            purely informational.
 * @param[in] channel_created_data passed into the on_channel_created handler
 * @param[in] connection_handler callbacks that are invoked when the response to
 *            a JALoP 'connect' message is received. It is in these callbacks the
 *            application should invoke the jaln_journal_recover or jaln_subscribe
 *            functions.
 * @param[in] jal_connect_data user pointer passed into the jal_connection_handler
 *            callbacks
 * @param[in] request The parameters of the request message. The JLN make an
 *            internal copy of this structure. The application must release any
 *            memory allocated in this structure.
 *
 * @return a jaln_channel
 * @note should this have a blocking mode too?
 */
struct jaln_channel *jaln_create_subscriber_channel(jaln_connection,
			 int channel_num,
			 jaln_on_close_handler close_handler,
			 void *close_data,
			 jaln_on_channel_created on_channel_created,
			 void *channel_created_data,
			 struct jaln_connection_response_handlers *connection_handler,
			 void *jal_connect_data,
			 struct jaln_connect_request *request
			);
/**
 * Recover a journal entry.
 *
 * This returns immediately if all input paramters are valid and 
 * subscriber_callbacks::on_message_complete is defined. Once the exchange is
 * completed, the callback is executed on another thread. If the
 * subscriber_callbacks::on_message_complete is NULL, this call blocks until
 * the exchange is complete.
 *
 * @param[in] channel the JALoP channel to start journal recovery on
 * @param[in] serial_id The serial id of the journal record to recover
 * @param[in] subscriber_callbacks The callbacks to handle the incoming record
 * @param[in] subscriber_data User data passed into the subscribe_callbacks
 * @param[in] recover_complete Callback that is invoked once the entire journal
 * record is downloaded.
 * @param[in] recover_complete_data User data passed into the recover_complete
 * callback.
 *
 * @return JAL_OK on success, or an error.
 */
enum jal_status jaln_journal_recover(jaln_channel channel,
				const char *serial_id,
				struct jaln_subscriber_callbacks *subscriber_callbacks,
				void *subscriber_data,
				jaln_on_message_complete recover_complete,
				void *recover_complete_data
			);
/**
 * Send a subscribe message on the given channel.
 * If the all input paramters are valid and
 * susbscriber_callbacks::on_message_complete is defined this call will return
 * immediately, and execute on_message_complete in a seperate thread when the
 * exchange finishes. When susbscriber_callbacks::on_message_complete is NULL,
 * this call blocks until the message exchange completes.
 *
 * subscriber_data is passed to all the callbacks defined in
 * jaln_subscriber_callbacks
 *
 * @param[in] channel The JalChannel to send the subscribe message on.
 * @param[in] serial_id The serial_id of the entry to start from.
 * @param[in] subscriber_callbacks Callbacks to handle the reponse from a
 * 'subscribe' message
 * @param[in] subscriber_data User data pointer passed to the
 * subscriber_callbacks
 * @param[in] subscribe_complete Callback for when the message exchange is
 * finished.
 * @param[in] subscribe_complete_data User data pointer passed to the
 * subscribe_complete callback
 *
 *
 * @return JAL_OK on success, or an error.
 */
enum jal_status jaln_subscribe(struct jaln_channel *channel,
			  const char *serial_id,
			  struct jaln_subscriber_callbacks *subscriber_callbacks,
			  void *subscriber_data,
			  jaln_on_message_complete subscribe_complete,
			  void *subscribe_complete_data);

#endif // JALN_NETWORK
