/**
 * @file jal_digest.h
 *
 * APIs for implementing and registering additional digest algorithms
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <stdlib.h>
#include <string.h>

#include <jalop/jal_status.h>

/**
 * @name Digest Algorithm URIs
 * @{ 
 * URI values for supported digest algorithms.
 * Supported digest algorithms and their URIs are defined in the JALoP specification.
 */
#define JAL_SHA256_ALGORITHM_URI "http://www.w3.org/2001/04/xmlenc#sha256"
#define JAL_SHA384_ALGORITHM_URI "http://www.w3.org/2001/04/xmldsig-more#sha384"
#define JAL_SHA512_ALGORITHM_URI "http://www.w3.org/2001/04/xmlenc#sha512"
/**@}*/

/**
 * @name Digest Algorithm Names
 * @{
 * Digest Algorithm names used in config/CLI parameters
 * Supported digest algorithms are defined in the JALoP specification
 */
#define JAL_SHA256_ALGORITHM_STR "sha256"
#define JAL_SHA384_ALGORITHM_STR "sha384"
#define JAL_SHA512_ALGORITHM_STR "sha512"
/**@}*/

/**
 * Delimeter used to separate digest algorithms in config/CLI parameters
 */
#define JAL_DIGEST_ALGORITHM_DELIMETER " "

/**
 * Digest algorithms supported
 * It is important to keep these sequential in order to keep the count accurate
 * which will allow us to loop through all of the digest algorithms where appropriate.
 */
enum jal_digest_algorithm {
	JAL_DIGEST_ALGORITHM_SHA256 = 0,
	JAL_DIGEST_ALGORITHM_SHA384,
	JAL_DIGEST_ALGORITHM_SHA512,
	JAL_DIGEST_ALGORITHM_COUNT,
};

/**
 * Default digest algorithm to use if the JAL-Accept-Digest header is not present
 */
#define JAL_DIGEST_ALGORITHM_DEFAULT JAL_DIGEST_ALGORITHM_SHA256

/**
 * @name Config/CLI String <-> Enum Value Conversion
 * @{
 * Allow for conversion from config/CLI string to enum value
 */
static const struct {
	/**
	 * Enum value
	 */
	enum jal_digest_algorithm val;
	/**
	 * Config/CLI string value
	 */
	const char *str;
} conversion [] = {
	/**
	 * Mappings between config/CLI Strings and enum values
	 */
	{JAL_DIGEST_ALGORITHM_SHA256, JAL_SHA256_ALGORITHM_STR},
	{JAL_DIGEST_ALGORITHM_SHA384, JAL_SHA384_ALGORITHM_STR},
	{JAL_DIGEST_ALGORITHM_SHA512, JAL_SHA512_ALGORITHM_STR},
};

/**
 * Allow for conversion from enum value to config/CLI string
 */
static const char * const digest_str[] = {
	[JAL_DIGEST_ALGORITHM_SHA256] = JAL_SHA256_ALGORITHM_STR,
	[JAL_DIGEST_ALGORITHM_SHA384] = JAL_SHA384_ALGORITHM_STR,
	[JAL_DIGEST_ALGORITHM_SHA512] = JAL_SHA512_ALGORITHM_STR,
};
/**@}*/

/** 
 * @name URI String <-> Enum Value Conversion
 * @{
 * Allow for conversion from URI string to enum value
 */
static const struct {
	/**
	 * Enum value
	 */
	enum jal_digest_algorithm val;
	/**
	 * URI string value
	 */
	const char *str;
} uri_conversion [] = { 
	/**
	 * Mappings between URI strings and enum values
	 */
	{JAL_DIGEST_ALGORITHM_SHA256, JAL_SHA256_ALGORITHM_URI},
	{JAL_DIGEST_ALGORITHM_SHA384, JAL_SHA384_ALGORITHM_URI},
	{JAL_DIGEST_ALGORITHM_SHA512, JAL_SHA512_ALGORITHM_URI},
};

/**
 * Allow for conversion from enum value to URI string
 */
static const char * const digest_uri_str[] = {
	[JAL_DIGEST_ALGORITHM_SHA256] = JAL_SHA256_ALGORITHM_URI,
	[JAL_DIGEST_ALGORITHM_SHA384] = JAL_SHA384_ALGORITHM_URI,
	[JAL_DIGEST_ALGORITHM_SHA512] = JAL_SHA512_ALGORITHM_URI,
};
/**@}*/

/**
 * Assert that the number of elements in an array match the expected number
 * @param[in] sarray Array to check the number of elements in
 * @param[in] max Expected number of elements in sarray
 * @returns 1 if the array contains the expected number of elements, -1 otherwise
 */
#define ASSERT_NUM_ENUM_CONVERSIONS(sarray, max) typedef char assert_sizeof_##max[(sizeof(sarray)/sizeof(sarray[0]) == (max)) ? 1 : -1]

/** 
 * @name Compile-time Completion Checks
 * @{
 * Compile-time checks to ensure that we have the right number of conversions 
 * from string representation to enum and from enum to URI
 */
ASSERT_NUM_ENUM_CONVERSIONS(conversion, JAL_DIGEST_ALGORITHM_COUNT);
ASSERT_NUM_ENUM_CONVERSIONS(digest_str, JAL_DIGEST_ALGORITHM_COUNT);
ASSERT_NUM_ENUM_CONVERSIONS(digest_uri_str, JAL_DIGEST_ALGORITHM_COUNT);
/**@}*/

/**
 * User supplied functions to implement additional digest algorithms.
 * jal_digest_ctx objects should be created and destroyed with the
 * jal_digest_ctx_create() and jal_digest_ctx_destroy() functions.
 */
struct jal_digest_ctx {

	/**
	 * The uri for the algorithm used to generate the digest.
	 * The jal_library assumes ownership of this pointer.
	 */
	char *algorithm_uri;
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
	 * @returns JAL_OK on success, JAL_E_INVAL on failure
	 */
	enum jal_status (*init)(void *instance);
	/**
	 * Function to call to update a digest context.
	 * @param[in] instance the instance pointer.
	 * @param[in] data a buffer containing bytes to feed into the digest context
	 * @param[in] len the number of bytes in the buffer \p data
	 *
	 * @returns JAL_OK on success, JAL_E_INVAL on failure.
	 */
	enum jal_status (*update)(void *instance, const uint8_t *data, size_t len);
	/**
	 * Function to signal that the end of a message to digest was reached. After
	 * this call, the JNL will not call the corresponding #update() using
	 * this instance ever again.
	 *
	 * @param[in] instance The instance pointer.
	 * @param[out] digest a buffer to hold the digest
	 * @param[in,out] len A pointer to the size of buffer. This indicates the
	 * number of bytes available in buffer. The implementation must set this to
	 * the number of bytes copied into buffer.
	 *
	 * @returns the JAL_OK on success, or JAL_E_INVAL on error.
	 */
	enum jal_status (*final)(void *instance, uint8_t *digest, size_t *len);
	/**
	 * Function to clean up resources used by a digest instance.
	 * @param[in] instance The instance to destroy.
	 */
	void (*destroy)(void *instance);
};

/**
 * Create a jal_digest_ctx structure
 * @param[in] algorithm The enum value of the digest algorithm to create a ctx for
 * @return the newly created jal_digest_ctx
 */
struct jal_digest_ctx *jal_digest_ctx_create(enum jal_digest_algorithm algorithm);

/**
 * Release memory associated with the jal_digest_ctx object.
 * Does not attempt to free the function pointers associated
 * with the object.
 * @param[in] digest_ctx The jal_digest_ctx to destroy, this will be set to NULL
 */
void jal_digest_ctx_destroy(struct jal_digest_ctx **digest_ctx);
/**
 * Utility function to sanity check a jal_digest_ctx
 * @param [in] ctx the jal_digest_ctx to check;
 * @return 1 if the digest context is valid, 0 otherwise.
 */
int jal_digest_ctx_is_valid(const struct jal_digest_ctx *ctx);

/**
 * Create a digest from a byte buffer
 *
 * @param[in] digest_ctx The application supplied jal_digest_ctx to use.
 * @param[in] data A buffer containing bytes to feed into the digest context.
 * @param[in] len The size of the buffer.
 * @param[out] digest A pointer to hold the created digest. Should point to NULL.
 *
 * @returns JAL_OK on success.
*/
enum jal_status jal_digest_buffer(struct jal_digest_ctx *digest_ctx,
		const uint8_t *data, size_t len, uint8_t **digest);

/**
 * Create a digest from an open file descriptor
 *
 * @param[in] digest_ctx The application supplied jal_digest_ctx to use.
 * @param[in] fd An open file descriptor to feed into the digest context.
 * @param[out] digest A pointer to hold the created digest. Should point to NULL.
 *
 * @returns JAL_OK on success.
*/
enum jal_status jal_digest_fd(struct jal_digest_ctx *digest_ctx,
		int fd, uint8_t **digest);

/**
 * Get the digest algorithm enum value from a string representation.
 * This is a case-insensitive comparison
 * 
 * @param[in] str The string to convert to an enum value
 * @param[out] digest The resulting digest algorithm enum value is placed into this parameter
 * @returns JAL_OK on success
 */
enum jal_status jal_get_digest_from_str(const char *str, enum jal_digest_algorithm *digest);

/**
 * Get the digest algorithm enum value from a URI string representation.
 * This is a case-sensitive comparison
 * 
 * @param[in] uri The string to convert to an enum value
 * @param[out] digest The resulting digest algorithm enum value is placed into this parameter
 * @returns JAL_OK on success
 */
enum jal_status jal_get_digest_from_uri(const char *uri, enum jal_digest_algorithm *digest);

/**
 * Parse a string for digest algorithms
 * 
 * @param[in] str The string to parse
 * @param[out] digest_list The list of digest algorithms found in the input string.
 *                         The order in this list corresponds to the order found in the input string
 *                         The caller is responsible for malloc'ing and free'ing this list
 * @param[out] num_digests The number of digests in the digest list
 * @returns JAL_OK on success
 */
enum jal_status jal_parse_digest_algorithm_str(const char *str, enum jal_digest_algorithm **digest_list, size_t *num_digests);

/**
 * Take the config and cli digest algorithms, and determine the correct set of digest algorithms
 * 
 * @param[in] config String of digest algorithms set by the config file
 * @param[in] cli String of digest algorithms set by the CLI
 * @param[out] digest_list The list of digest algorithms found in the input string.
 *                         The order in this list corresponds to the order found in the config/CLI input
 *                         The caller is responsible for malloc'ing and free'ing this list
 * @param[out] num_digests The number of digests in the digest list
 * @returns JAL_OK on success
 */
enum jal_status jal_get_digest_algorithm_list(const char *config, const char *cli, enum jal_digest_algorithm **digest_list, size_t *num_digests);

#ifdef __cplusplus
}
#endif

#endif // _JAL_DIGEST_H_
