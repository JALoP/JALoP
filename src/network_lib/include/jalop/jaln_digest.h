/**
 * @file jaln_digest.h
 *
 * APIs for implementing and registering additional digest algorithms
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
#ifndef _JAL_DIGEST_H_
#define _JAL_DIGEST_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/jaln_network.h>
#include <stdint.h>

/** 
 * User supplied functions to implement additional digest algorithms.
 */
struct jal_digest_ctx {
	/**
	 * The size, in bytes, of the digest output. For example, sha256 always
	 * generates a 32 byte (256 bit) digest.
	 */
	int len;
	/**
	 * Function to call to create an instance of a particular digest context.
	 * The pointer returned by this function is passed as the \p instance
	 * parameter to all the other functions in this structure.
	 *
	 * @return Non-NULL on success. If a NULL pointer is returned,
	 * returning a NULL value indicates a allocation failure.
	 */
	void *(*create)(void);
	/**
	 * Function to call to initialize a digest context. This is called
	 * immediately after create()
	 *
	 * @param instance The instance pointer.
	 * @returns JAL_OK on success, JAL_ERROR on failure
	 */
	int (*init)(void *instance);
	/**
	 * Function to call to update a digest context.
	 * @param[in] instance the instance pointer.
	 * @param[in] data a buffer containing bytes to feed into the digest context
	 * @param[in] len the number of bytes in the buffer \p data
	 *
	 * @returns JAL_OK on success, JAL_ERROR on failure.
	 */
	int (*update)(void *instance, uint8_t *data, uint32_t len);
	/**
	 * Function to signal that the end of a message to digest was reached. After
	 * this call, the JNL will not call the corresponding #update() using
	 * this instance ever again.
	 *
	 * @param[in] instance The instance pointer.
	 * @param[out] digest a buffer to hold the digest
	 * @param[in,out] len A pointer to the size of buffer. This indicates the
	 * number of bytes available in buffer. The implementation must set this to
	 * the number of bytes copied into buffer, or -1 on error.
	 *
	 * @returns the number of bytes written into buffer, or -1 on error.
	 */
	int (*final)(void *instance, uint8_t *digest, uint32_t *len);
	/**
	 * Function to clean up resources used by a digest instance.
	 * @param[in] instance The instance to destroy.
	 */
	void (*destroy)(void *instance);
};
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
int jaln_register_digest_algorithm(jaln_context *jal_ctx,
			      char *algorithm,
			      struct jal_digest_ctx *digest_ctx);

#ifdef __cplusplus
}
#endif

#endif // _JAL_DIGEST_H_
