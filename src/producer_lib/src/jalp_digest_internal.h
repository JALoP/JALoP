/**
 * @file jalp_logger_metadata.h This file defines functions for calculating
 * digests.
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
enum jal_status jalp_digest_buffer(struct jal_digest_ctx *digest_ctx,
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
enum jal_status jalp_digest_fd(struct jal_digest_ctx *digest_ctx,
		int fd, uint8_t **digest);
