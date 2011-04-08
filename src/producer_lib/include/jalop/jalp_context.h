#ifndef JALP_PRODUCER_H
#define JALP_PRODUCER_H
/**
 * @file jal_producer.h This file defines the public API available to
 * applications generating JAL data. It provides the interfaces needed to build
 * the application metadata sections and submit JAL data (and metadata) to the
 * JAL Local Store.
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
#include <stdint.h>
#include <stdlib.h>

/**
 * Opaque pointer to the internal jalp_context_t type.
 * The jalp_context holds information about the connection to the JALoP Local Store.
 * The jalp_context is not thread safe. Applications should either create
 * separate logging connections for each thread, or properly guard the jalp_context.
 *
 * Because each connection requires resources in the JAL Local Store, a
 * massively threaded process should avoid creating a connection for each thread.
 */
typedef struct jalp_context_t jalp_context;

/**
 * Enumeration for error codes returned by JALoP calls.
 */
enum jal_status {
	JAL_E_XML_PARSE = -1024,
	JAL_E_XML_SCHEMA,
	JAL_E_NOT_CONNECTED,
	JAL_E_INVAL,
	JAL_E_NO_MEM,
	JAL_OK = 0,
};


/**
 * Load an RSA private key. If successful, every application metadata document
 * will get signed (using RSA+SHA256). Once a key is set, it cannot be changed.
 * You must create a new context.
 *
 * @param[in] jalp_context The context to attach the RSA keys to.
 * @param[in] keyfile The path to the private key file.
 * @param[in] password The password for the key file.
 *
 * @return JAL_OK on success, or an error code.
 *
 */
enum jal_status jalp_context_load_pem_rsa(jalp_context *ctx,
		const char *keyfile,
		const char *password);
/**
 * Load an RSA public certificate. This must be the public certificate that
 * corresponds to the private key set with #jalp_context_load_pem_rsa.
 * If applications add the certificate, the Producer Library will add a KeyInfo
 * block for the certificate.
 *
 * @param[in] ctx The context to attach the certificate to.
 * @param[in] certfile The path to the x509 public certificate file.
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jalp_context_load_x509_cert(jalp_context *ctx,
		const char *certfile);

/**
 * Create a jalp_context. This must be initialized with a call to
 * #jalp_context_init
 * @return a newly created jalp_context
 */
jalp_context *jalp_context_create(void);
/**
 * Initialize a jalp_context.
 * @param[in] path The name of the socket to connect to. If this is NULL, the
 * default path defined in JALP_SOCKET_NAME is used.
 *
 * In most cases, it is safe pass NULL as the path. For testing purposes, or
 * when the path to the domain socket in the producer process is different
 * from the path in the JALoP Local Store, the caller may specify a different
 * path.
 *
 * @param[in] ctx The context to create.
 * @param[in] hostname A string to use when filling out metadata sections. If
 * this is set to NULL or the empty string, the JPL will try to generate a suitable
 * hostname (i.e. by calling gethostname() on POSIX systems).
 * @param[in] app_name A string to use when filling out metadata sections. If
 * this is set to NULL, or the empty string, the JPL will try to generate a
 * suitable process name.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jalp_context_init(jalp_context *ctx,
		char* path,
		char *hostname,
		char *app_name);

/**
 * Connect to the JALoP Local Store. It is safe to call this repeatedly, even
 * after a connection was made. This call will block until the connection is
 * established.
 *
 * @param[in] ctx the #jalp_context to connect
 * @return JAL_OK if the connection is complete.
 */
enum jal_status jalp_context_connect(jalp_context *ctx);
/*
 * Disconnect from a JAL Local Store
 * @param[in] ctx the connection to disconnect.
 */
enum jal_status jalp_context_disconnect(jalp_context *ctx);
/**
 * Disconnect (if needed) and destroy the connection.
 *
 * @param[in,out] ctx The #jalp_context to destroy. On return, this will be set to
 * NULL.
 */
void jalp_context_destroy(jalp_context **ctx);

/**
 * Send a log message to the JALoP Local Store
 *
 * @param[in] ctx The context to send the data over
 * @param[in] app_meta An optional struct that the ProducerLib will convert into XML
 * for the application metadata.
 * schema.
 * @param[in] log_buffer An optional byte buffer that is the log message
 * @param[in] log_buffer_size The size of the byte buffer.
 *
 * @note It is an error to pass NULL for both \p app_meta and \p log_buffer.
 * 
 *
 * @return JAL_OK on sucess.
 *         JAL_XML_EINVAL if there is something wrong with the parameters
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * @note The ctx will be connected if it isn't already.
 */
enum jal_status jalp_log(jalp_context *ctx,
		struct jalp_app_meta *app_meta,
		uint8_t *log_buffer,
		size_t log_buffer_size);

/**
 * Send a journal data to the JALoP Local Store.
 *
 * @param[in] jalp_context ctx The connection to send the data over.
 * @param[in] app_meta An optional structure that will be converted into an XML
 * document conforming to the application metadata schema.
 * @param[in] journal_buffer A byte buffer that contains the full contents of
 * a journal entry.
 * @param[in] journal_buffer_size The size (in bytes) of \p journal_buffer.
 *
 * @note It is an error to pass NULL for both \p app_metadata and \p
 * journal_buffer.
 *
 * @return JAL_OK on success.
 *         JAL_EINVAL If the parameters are incorrect.
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * @note The ctx will be connected if it isn't already.
 */
enum jal_status jalp_journal(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		uint8_t *journal_buffer,
		uint64_t journal_buffer_size);

/**
 * Send an open file descriptor to the JAL Local Store.
 *
 * The caller must not write to the file identified by \p fd after making this
 * call, or else the JAL local store may receive incorrect data. This call
 * works by sending just the file descriptor and is not available on all
 * platforms. You can check for it's existence by checking for
 * JALP_CAN_SEND_FDS, example:
 * @code
 * #ifdef JALP_CAN_SEND_FDS
 * \/\* do something *\/
 * #endif
 * @endcode
 *
 * @param[in] ctx The context to send the record over.
 * @param[in] app_meta The optional application provided metadata.
 * @param[in] fd The file descriptor of the journal.
 *
 * @note would it be better to fake this call if sending the file descriptor is
 * impossible? Considering that would make this call extremely slow on
 * platforms that don't have SCM_RIGHTS, I don't think it's a good idea to do that.
 * Could be done in a separate worker thread, but that could still cause confusing
 * behaviour since the sending thread here would need to prevent the app from
 * exiting while it's sending the data to the JNL....
 */
enum jal_status jalp_journal_fd(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		int fd);

/**
 * Open the file at \p path and send it the JAL local store.
 *
 * This uses the #jalp_journal_fd internally to send a file descriptor. The
 * application should never write to the file after calling this method, but is
 * free to unlink it.
 *
 * @param[in] ctx The context to send the journal over.
 * @param[in] app_meta An optional structure that the library will convert into
 * an XML document.
 * @param[in] path The path to the file to journal.
 *
 * @note It is an error to pass NULL for both \p app_meta and \p journal_buffer.
 *
 * @return JAL_OK if the JPL was successful at opening the file and sending the
 * descriptor to the JAL local store.
 *
 * @note same comment as for #jalp_journal_fd, should we emulate this?
 *
 */
enum jal_status jalp_journal_path(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		char *path);
/**
 * Send an audit record to the JALoP Local Store
 *
 * @param[in] ctx The context to send the data over
 * @param[in] app_meta An optional struct that the library will convert into an
 * XML document. The resulting document will conform to the applicationMetadata
 * XML Schema defined in the JALoP-v1.0-Specification.
 * @param[in] audit_buffer An optional byte buffer that contains the full contents of
 * a audit entry.
 * @param[in] audit_buffer_size The size (in bytes) of \p audit_buffer.
 *
 * @note It is an error to pass NULL for both \p app_meta and \p audit_buffer.
 *
 * @return JAL_OK on sucess.
 *         JAL_EINVAL If the parameters are incorrect.
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * @note \p ctx will be connected if it isn't already.
 */
enum jal_status jalp_audit(jalp_context *ctx,
		struct jalp_app_metadata *app_meta,
		uint8_t *audit_buffer,
		size_t audit_buffer_size);

#endif /* JALP_PRODUCER_H */

