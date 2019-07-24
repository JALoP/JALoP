/**
 * @file jaln_doc_mainpage.h
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2014 Tresys Technology LLC, Columbia,
 * Maryland, USA
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

/**
 * \page page_jnl JALoP Network Library (JNL)
 *
 * \section intro_sec Introduction
 *
 * The JALoP Network Library (JNL) provides an API to send and receive JAL
 * records between 2 JALoP Network Stores using the JALoP Network Protocol
 * (JNP) over HTTP. The document "JALoP v2.0.0.0 Specification" describes the
 * protocol in detail.
 *
 * The JNL exposes an API that applications may use to listen for
 * incoming network connections from a remote JALoP Network Store, or initiate
 * a JALoP connection to a remote JALoP Network Store. By using the JNL, an
 * application may act as a JALoP Publisher, JALoP Subscriber, or both.
 *
 *  \section jal_protocol The JAL Network Protocol
 *
 * The JNP is used to exchange the 3 different types of JALoP records
 *  - Journal - records that have potentially large payloads that will be
 *    passed through without modification, for examples files that fail
 *    antivirus checks.
 *  - Audit - System events that conform to the Mitre CEE XML schema.
 *  - Log - Application events that need not conform to any schema.
 *    These may be text or binary, and do not have a maximum size or minimum.
 *    Some examples are syslog messages, Apache log entries and messages
 *    originating from log framework like log4c++.
 *
 * Each record is accompanied by a XML document that conforms to the JALoP
 * System Metadata Schema. Each record may optionally be a accompanied by a XML
 * document that conforms to the JALoP System Metadata Schema. Additionally,
 * audit records are expected to conform to the Mitre CEE XML schema. Applications
 * using the JNP should confirm that these documents conform to the appropriate
 * schemas as the JNL does not perform any schema validation.
 *
 *  \section devel_sec Development
 *
 *  \subsection d_step1 Step 1: Initializing a context
 *
 *  The library state related to a connection(s) is stored in an opaque context.
 *  Therefore, the first order of business is to create a context
 *  The context should always be allocated on the heap via the jalp_context_create()
 *  function.
 *
 *  After allocating the context it must be initialized with the location of the JAL
 *  local store socket and the schema directory, if those aren't going to be the default.
 *
 *  \code
 *
#include <jalop/jaln_network.h>
#include <jalop/jal_status.h>

int main(void)
{
	jaln_context *context;
	enum jal_status ret;

	context = jalp_context_create();
	if (context == NULL)
		return -1;

	return 0;
}

\endcode
 *
 *  \subsection d_step2 Step 2: Loading keys and certificates (optional)
 *
 *  The JALoP protocol requires JALoP Peers to authenticate themselves and that
 *  all communications have some level of privacy. To achieve this, the JNL
 *  can negotiate a TLS connection using pre-shared keys. If TLS is configured,
 *  then the JNL will authenticate the remote PEER and reject any connections
 *  where TLS is not successfully negotiated. TLS should always be used, unless
 *  operating in a debug environment.
 *
 *  There are 3 distinct pieces of information that must be provided to the JNL
 *  in order to successfully negotiate TLS.
 *  - A PEM formatted private key
 *  - A PEM formatted public certificate
 *  - A directory contained PEM formatted certificates for all authorized
 *  peers.
 * Consult the file test-input/README_keys in the source code for more
 * information on how to create these files. The JNL performs mutual
 * authenticate of the peers involved, so the listener machine must have a copy
 * of the certificate for the initiator, and the initiator must have a copy of
 * the certificate for the listener.
 *
 * Also note that contents of the directory that holds all of the remote
 * certificates must conform to the standard configuration for OpenSSL. That is
 * to say, there should be a set of symbolic links in this directory, each with
 * the name \<subj_hash\>.\<num\>, where \<sub_hash\> is the subject has of the
 * certificate, and \<num\> is a sequence number, starting with 0. The easiest
 * way to populate this directory is by placing all your certificates in the
 * directory, each with the extension .pem, and then executing the \p c_rehash
 * script for that directory (see the documentation of the c_rehash utility for
 * more information). \p c_rehash is usually shipped as part of the OpenSSL
 * package, or as part the PERL extras for OpenSSL. If you cannot find the \p
 * c_rehash tool for your platform, you can create the links by hand. To obtain
 * the subject hash for each certificate, execute the command:
 * \code
$> openssl x509 -noout -hash -in <certificate_file>
 * \endcode
 * or the command:
 * \code
$> openssl x509 -noout -subject_hash -in <certificate_file>
 * \endcode
 * It should also be noted that different versions of OpenSSL utilize different
 * hashing algorithms for the subject hash so you should always run these
 * commands, or the \p c_rehash tool, using the versions of OpenSSL that will
 * be used by the JNL. Do not assume that you can run c_rehash on one machine,
 * and copy the links over to another.
 * \code
#include <jalop/jaln_network.h>
#include <jalop/jal_status.h>

int main(void)
{
	jaln_context *context;
	enum jal_status ret;

	context = jalp_context_create();
	if (context == NULL)
		return -1;

	ret = jaln_register_tls(context, "/path/to/private/key", "/path/to/public/cert",
			"/path/to/remote/certs");

	if (context == NULL)
		return -1;
	return 0;
}
 * \endcode
 *
 * \subsection d_step3 Step 3: Register additional digest algorithms (optional)
 * When 2 JALoP Network begin communicating, they will negotiate the use of a
 * particular digest algorithm. As records are sent from the Publisher the
 * Subscriber, both peers will use the agreed upon digest algorithm to
 * calculate the message digest of each JALoP record.
 * Periodically, the Subscriber will send a message to the publisher that with
 * the calculated digest values. The Publisher will verify that these digest
 * values match their own calculated values. If the values do not match, the
 * Subscriber should re-send the incorrect records.
 *
 * The JNL provides an implementation of the SHA256 digest algorithm using
 * OpenSSL. Applications may choose to support other encodings. To do so, they
 * must register the encoding with the jaln_context before starting
 * communications.
 *
 * Register an additional digest algorithm is simply a matter of creating a
 * #jal_digest_ctx structure and filling in all the function callbacks. The
 * jal_digest_ctx::algorithm_uri will be presented to the remote JALoP Peer
 * name of the algorithm. Applications may choose to support as many digest
 * algorithms as they would like.
 *
 * \subsection d_step4 Step 4: Register additional XML encodings (optional)
 * In order to reduce the bandwidth required to send XML data, 2 JALoP Network
 * Stores may choose to support different encodings schemes for XML, such as
 * EXI, or compressing the data using the deflate algorithm. All
 * implementations must support the transferring XML documents as raw XML, that
 * is, without any encoding.
 *
 * The encoding in use is always available in the #jaln_channel_info structure,
 * which is passed into the various callbacks.
 *
 * \subsection d_step5 Step 5: Registering the Publisher or Subscriber callbacks
 * Before any data can be transfered, and application must register the
 * appropriate callbacks for the role they wish to take. If the application is
 * going to be a listener (wait for connections from remotes) then it may choose
 * to register both publisher and subscriber callbacks. If the application is
 * going to act as an initiator, it may act as either a subscriber, or a
 * publisher, but not both. Therefore, you need only register the callbacks for
 * the role the application will take.
 *
 * Registering the callbacks is simply a matter of creating the appropriate
 * structure(s), either #jaln_publisher_callbacks, #jaln_subscriber_callbacks,
 * or both (if acting as a listener). These should be created with their
 * corresponding jaln_publisher_callbacks_create() and
 * jaln_subscriber_callbacks_create() functions. Once created, all function
 * pointers must be set before calling the corresponding functions to register
 * with the JNL, either jaln_register_publisher_callbacks(), or
 * jaln_register_producer_callbacks().
 *
 * \subsection d_step6 Step 6: Registering the connection callbacks. Before
 * listnener for incoming connections, or initiating a connection to a remote,
 * you will need to register a #jaln_connection_callbacks object with the JNL.
 * This structure must be filled out with callbacks that the JNL will execute
 * at various points during the lifetime of a connection. See the documentation
 * for #jaln_connection_callbacks for more information. This structure should
 * be created via a call to jaln_connection_callbacks_create() and have all the
 * members set to valid functions. It must be registered with the #jaln_context
 * via a call to jaln_register_connection_callbacks().
 *
 * \subsection d_step7 Step 7: Initiate a connection to a remote, or listen for
 * connections from remotes. A jaln_connection may be used with
 * used with single call to jaln_subscribe(), jaln_publish(), or
 * jaln_listen(). The #jaln_context must be fully configured,
 * with all necessary callbacks, digest algorithms, XML
 * encodings, etc. registered prior to these calls. Each of
 * these functions accepts a \p user_data pointer as one of the
 * arguments. This pointer is passed into every callback
 * function for the application to use. It may be anything at
 * all, or NULL.
 *
 * \subsubsection d_step7a Step 7a: Using a #jaln_context to initiate a
 * connection a subscribe to a remote peer. If the #jaln_context is going to be
 * used to initiate a connection to a remote and subscribe to JALoP data, you
 * must use the jaln_subscribe() function. Once jaln_subscribe() is called, the
 * same context cannot be used with additional calls to jaln_subscribe() or
 * calls to jaln_publish() or jaln_listen(). The caller should check the return
 * code of jaln_subscribe(). A return value of NULL indicates there was a
 * failure created the connection to the remote. The JNL will create sessions
 * for each type of data indicated in the call to jaln_subscribe() and attempt
 * to negotiate the connections with the remote peer. If negotiation fails, the
 * jaln_connection_callbacks::connect_nack callback is executed. If session
 * negotiation is successful, the jaln_connection_callbacks:connect_ack
 * callback is executed.
 *
 * Once the session is negotiated, the JNL will execute
 * the jaln_subscriber_callbacks::get_subscribe_request callback to obtain the
 * details of the subscribe or journal-resume message it should sent. See the
 * documentation for jaln_subcriber_callbacks::get_subscribe_request for more
 * details.
 *
 * As records are transfered over the network, the JNL will execute the
 * jaln_subscriber_callbacks::on_record_info function to notify the application
 * of the start of a new record. This function provides the serial ID for the
 * record, the application metadata (if any) and the system metadata. Depending
 * on the record type, the JNL will execute the
 * jaln_subscriber_callbacks::on_audit, jaln_subscriber_callbacks::on_log, or
 * jaln_subscriber_callbacks::on_journal. The callbacks for audit and log are
 * very similar and will deliver the entire contents of the record in the
 * callbacks. The callbacks for journal is slightly different in that it will
 * deliver chunks of data as they are received over the network. See the
 * relevant documentation for #jaln_subscriber_callbacks for more details.
 * Callbacks will be executed on threads other than the one that called
 * jaln_subscribe() so applications need to take proper steps to lock shared
 * structures.
 *
 * When the application wishes to terminate the connection,
 * jaln_disconnect(). This will attempt to perform an orderly
 * disconnect from the remote peer.  If an orderly disconnect is taking too long,
 * the application may execute jaln_shutdown() which will sever the connection.
 *
 * \subsubsection d_step7b Step 7b: Using a #jaln_context to initiate a
 * connection to a remote and act as a publisher. The initial setup for a
 * publisher is similar to that of a subscriber except that rather than
 * registering a #jaln_subscriber_callbacks object, you must register a
 * #jaln_publisher_callbacks object and you must execute jaln_publish()
 * rather than jaln_subscribe(). Just like for jaln_subscriber() all digest
 * algorithms, XML encodings, and #jaln_connection_callbacks must be registered
 * prior to executing jaln_subscriber() and once jaln_subscribe() is called,
 * the #jaln_context may not be used in any other calls to jaln_publish()
 * jaln_subscribe() or jaln_listen().
 *
 * When jaln_publish() is called, the JNL will initiate a connection to the
 * indicated host and configure the connection. The caller should check the
 * return value of jaln_listen() to to make sure the connection was
 * successfully established. Once the connection is established, the JNL will
 * automatically create JALoP sessions for the record types indicated in the
 * call to jaln_publish(). For each session, if it is successfully configured,
 * the JNL will execute the jaln_connection_callbacks::connection_ack callback.
 * Conversely, if the JALoP session could not be configured, the JNL executes
 * the jaln_connection_callbacks::connect_nack callback. Once the JALoP
 * sessions are established, it is the responsibility of the remote to send a
 * 'subscribe' of 'journal-resume' message as described in "JALoP v2.0.0.0 Specification."
 *
 * If the remote sends a 'subscribe' message, the JNL will execute the
 * jaln_publisher_callbacks::subscribe callback to inform the application of
 * the details of the subscribe message, then the publisher may execute
 * jaln_send_journal, jaln_send_audit, or jaln_send_log, when it is ready to send
 * data.  The application must provide buffers to the system and application metadata for
 * the next record that should be sent. The application will be able to free these
 * buffers as soon as the function returns.
 *
 * After that, the JNL will call either
 * jaln_publisher_callbacks::acquire_log_data, jaln_publisher_callbacks::acquire_audit_data,
 * or jaln_publisher_callbacks::acquire_journal_feeder depending on the type of
 * record being sent over the connection. Regardless of the record type, the
 * JNL will call the appropriate callbacks to give the application a chance to
 * release any memory. See the documentation for #jaln_publisher_callbacks for
 * more details.
 *
 * As records are sent, the JNL will notify the application of the calculated
 * digests with calls to jaln_publisher_callbacks::notify_digest. These notifications
 * are informational, and the application need not do anything special with the
 * information provided.
 *
 * When the remote peer sends a 'digest' message, the JNL executes the
 * jaln_publisher_callbacks::peer_digest callback. If a record was not
 * transfered correctly (i.e. the \p local_digest and \p peer_digest do not
 * match) the application may wish to resend the particular record. When the
 * the remote sends a 'sync' message, the JNL will execute the
 * jaln_publisher_callbacks::sync callback. The "JALoP v2.0.0.0 Specification" has
 * more details.
 *
 * As with jaln_subscribe(), the callbacks are executed on other threads and
 * the application must take measures to lock any shared data as needed.
 * When the application wishes to terminate the connection, they should call
 * jaln_disconnect(). This will attempt to perform an orderly
 * disconnect from the remote peer.  If an orderly disconnect is taking too long,
 * the application may execute jaln_shutdown() which will sever the connection.
 *
 * \subsubsection d_step7c Step 7c: Using a #jaln_context to listen for
 * connections. If the #jaln_context is going to be used for listening to
 * incoming connections, you must first register any additional digest
 * algorithms or XML encodings. You must also register your
 * #jaln_connection_callbacks and either #jaln_publisher_callbacks,
 * #jaln_subscriber_callbacks, or both. If you do not register both
 * #jaln_publisher_callbacks and #jaln_subscriber_callbacks, the JNL will
 * automatically reject requests from remote peers wishing to connect as the
 * related roles. For example, if you only register the #jaln_publisher_callbacks
 * and a remote peer initiates a connection indicating
 * a desire to act as a subscriber, the JNL will be automatically reject the request.
 *
 * Once jaln_listen() is called, the associated context cannot be used with
 * another call to jaln_listen() or any calls to jaln_publish() or
 * jaln_subscribe(). After jaln_listen() is called, the JNL waits for
 * remote peers to initiate connections. When a remote peer attempts to
 * connect, the JNL will execute the
 * jaln_connection_callabacks::connection_request_handler registered with the
 * context. This gives the application to modify the configuration of the
 * connection, or reject the connection altogether.
 *
 */
