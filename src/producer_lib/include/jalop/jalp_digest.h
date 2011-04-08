/**
 * @file jalp_app_metadata.h This file defines the jalp_digest structure and
 * related functions.
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
#ifndef JALP_DIGETS_H
#define JALP_DIGETS_H

/**
 * @addtogroup AppMetadata
 * @{
 * @defgroup PayloadDigest Payload Digest
 * Structures and functions to add a digest of the payload to the application
 * metadata document. Applications are encourage to use a digest algorithm of
 * the SHA family (except SHA 1).
 * @{
 */
/**
 * Holds a digest value for any digest algorithm. Applications should only ever
 * create/destroy jalp_digest objects with calls to jalp_digest_create() and
 * japl_digest_destroy(). The destructor function assumes ownership of the
 * member variables and will free them will calls to 'free()'.
 */
struct jalp_digest {
	/** The URI for the digest algorithm */
	char *uri;
	/** the digest value */
	uint8_t *val;
	/** The length, in bytes, of the digest */
	uint32_t len;
};
/**
 * Create a jalp_digest object.
 *
 * @return The newly allocated object.
 */
struct jalp_digest *jalp_digest_create(void);
/**
 * Release all the memory associated with a jalp_digest object. This will
 * release all members will calls to 'free()'.
 *
 * @param[in,out] digest The object to free, this is set to NULL.
 */
void jalp_digest_destroy(struct jalp_digest **digest);
/**
 * Creates a new string representing the sha256 digest URI.
 * @return a URI for the SHA 256 digest method. This must be released with
 * "free()"
 */
char *jalp_digest_sha256();
/** @} */
/** @} */
#endif // JALP_APP_METADATA_H

