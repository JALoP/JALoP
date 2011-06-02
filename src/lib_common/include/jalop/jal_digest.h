/**
 * @file jal_digest.h
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

#ifdef __cplusplus
}
#endif

#endif // _JAL_DIGEST_H_
