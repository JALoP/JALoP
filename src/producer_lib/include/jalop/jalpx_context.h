/**
 * @file jalp_context.h This file defines the public API available to
 * applications for sending JAL data to a JALoP Local Store.
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
#ifndef _JALPX_CONTEXT_H_
#define _JALPX_CONTEXT_H_

#include <stdint.h>
#include <stdlib.h>

#include <openssl/pem.h>

#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>


/**
 * Path to the socket used when making a connection to the JALoP Local Store.
 */
#define JALP_SOCKET_NAME "/var/run/jalop/jalop.sock"
/**
 * Path to the schemas
 */
#define JALP_SCHEMA_ROOT "/usr/share/jalop/schemas"

/**
 * @defgroup ProducerContext Producer Context
 * Each producer application that generates JAL data to send to a JALoP Local
 * Store must first create and initialize a jalp_context object. This object
 * maintains connection information and is used to send JAL data to the JALoP
 * Local Store.
 * @{
 */
/**
 * Opaque pointer to the jalp_context.
 * The jalp_context holds information about the connection to the JALoP Local Store.
 * The jalp_context is not thread safe. Applications must either create
 * separate logging connections for each thread, or properly guard the jalp_context.
 *
 * Because each connection requires resources in the JAL Local Store, a
 * massively threaded process should avoid creating a connection for each thread.
 */
typedef struct jalp_context_t jalp_context;

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
 * In most cases, it is safe pass NULL as the path. In some rare cases, it may
 * be necessary to indicate a different path to use when connecting to the
 * JALoP Local Store.
 *
 * @param[in] ctx The context to create.
 * @param[in] hostname A string to use when filling out metadata sections. If
 * this is set to NULL or the empty string, the JPL will try to generate a suitable
 * hostname (i.e. by calling gethostname() on POSIX systems).
 * @param[in] app_name A string to use when filling out metadata sections. If
 * this is set to NULL, or the empty string, the JPL will try to generate a
 * suitable process name.
 * @param[in] schema_root The path to the JALoP Schemas. In most cases, this
 * may be NULL. In rare instances, it may be necessary to provide the install
 * path of the schemas.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jalp_context_init(jalp_context *ctx,
		const char *path,
		const char *hostname,
		const char *app_name,
		const char *schema_root);

/**
 * Disconnect (if needed) and destroy the connection.
 *
 * @param[in,out] ctx The #jalp_context to destroy. On return, this will be set to
 * NULL.
 */
void jalp_context_destroy(jalp_context **ctx);

/**
 * Load an RSA private key. If successful, every application metadata document
 * will get signed (using RSA+SHA256). Once a key is set, it cannot be changed.
 * You must create a new context.
 *
 * @param[in] ctx The context to attach the RSA keys to.
 * @param[in] keyfile The path to the private key file.
 * @param[in] password_cb The callback function used to provide a password, if
 * needed. If NULL, the default behavior is determined by the underlying SSL
 * implementation.
 *
 * @return JAL_OK on success or one of the following possible errors: JAL_E_INVAL, 
 * JAL_E_EXISTS, JAL_E_FILE_OPEN, JAL_E_READ_PRIVKEY.
 */
enum jal_status jalp_context_load_pem_rsa(jalp_context *ctx,
		const char *keyfile,
		pem_password_cb *cb);

/**
 * Load an RSA public certificate. This must be the public certificate that
 * corresponds to the private key set with #jalp_context_load_pem_rsa.
 * If applications add the certificate, the Producer Library will add a KeyInfo
 * block for the certificate.
 *
 * @param[in] ctx The context to attach the certificate to.
 * @param[in] certfile The path to the pem formatted x509 public certificate file.
 *
 * @return JAL_OK on success, or one of the following possible errors: JAL_E_INVAL,
 * JAL_E_FILE_OPEN, JAL_E_READ_X509.
 */
enum jal_status jalp_context_load_pem_cert(jalp_context *ctx,
		const char *certfile);

/**
 * Register a set of functions to implement a digest algorithm.
 * The Producer Library will use the functions in the jal_digest_ctx to
 * automatically create digests for data sent to the JALoP Local Store. By
 * default, no digests are created.
 *
 * @param[in] ctx The jalp_context
 * @param[in] digest_ctx The callbacks to implement a digest algorithm.
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jalp_context_set_digest_callbacks(jalp_context *ctx,
		const struct jal_digest_ctx *digest_ctx);


/** @} */

/**
 * Initialize the Producer Library
 * Must be the first function called to prepare the library for use.
 *
 * @return JAL_OK on success
 */
enum jal_status jalpx_init();

/**
 * Free data allocated by the Producer Library. Should be called by the 
 * application to clean up resources prior to exit.
 */
void jalpx_shutdown();

#endif // _JALPX_CONTEXT_H_
