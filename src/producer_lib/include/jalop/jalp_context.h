/**
 * @file jalp_context.h This file defines the public API available to
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
#ifndef JALP_CONTEXT_H
#define JALP_CONTEXT_H
#include <stdint.h>
#include <stdlib.h>

/**
 * @defgroup ProducerContext Producer Context
 * Each producer application that generates JAL data to send to a JAL local
 * store must first create and initialize a jalp_context object. The functions
 * and structures here are used to connect to JAL local store and send JAL
 * data.
 * @{
 */
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
 * Register a set of functions to implement a digest algorithm.
 * The ProducerLibrary will use the functions in the jal_digest_ctx to
 * automatically create digests for data sent to the JALoP Local Store. By
 * default, no digests are created.
 *
 * @param[in] ctx The jalp_context
 * @param[in] digest_ctx The callbacks to implement a digest algorithm.
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jalp_context_set_digest_callbacks(jalp_context *ctx,
		struct jal_digest_ctx *digest_ctx);


/** @} */
#endif // JALP_CONTEXT_H

