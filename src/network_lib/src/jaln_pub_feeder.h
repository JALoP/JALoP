/**
 * @file jaln_pub_feeder.h This file contains the functions related to the
 * implementation of the payload feeder for sending records from a publisher
 * to a subscriber.
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

#ifndef JALN_PUB_FEEDER
#define JALN_PUB_FEEDER

#include "jaln_session.h"

/**
 * return the 'size' of the record.
 *
 * @param[in] sess The session to operate on.
 * @param[out] size The size (in bytes).
 *
 * @return axl_true on success, axl_false otherwise.
 */
axl_bool jaln_pub_feeder_get_size(
		jaln_session *sess,
		uint64_t *size);

/**
 * Structure passed to jaln_pub_feeder_fill_buffer.
 *
 * Struct used as argument to jaln_pub_feeder_fill_buffer, the curl readfunc
 * callback used to get the underlying data of a record being sent.
 */
struct jaln_readfunc_info
{
        jaln_session *sess;
};

/**
 * function for libcurl to fill a buffer to send data.
 *
 * @param[out] b A buffer to fill
 * @param[in] size The size of one section of the buffer
 * @param[in] nmemb The number of items of size size in the buffer
 * @param[in] userdata The jaln_session associated with this session
 *
 * @return the number of bytes written or CURL_READFUNC_ABORT on failure
 */
size_t jaln_pub_feeder_fill_buffer(
		void *b,
		size_t size,
		size_t nmemb,
		void *userdata);

/**
 * Function used to report if we are finished sending this record.
 *
 * @param[in] sess The session to operate on
 * @param[out] finished This will be set to axl_true if all bytes were sent or
 * there was an error,
 * axl_false otherwise.
 *
 * @return axl_true on success, or axl_false if there was an error.
 */
axl_bool jaln_pub_feeder_is_finished(
		jaln_session *sess,
		int *finished);

/**
 * Function used to send a record using curl and receive
 * the response.
 *
 * @param[in] sess The jaln_session
 */
void jaln_pub_feeder_handler(jaln_session* sess);

/**
 * Helper function to reset the state of the publisher data. This resets the
 * offsets/sizes to NULL, creates a new digest context instance, etc.
 *
 * @param[in] sess The session to reset.
 */
void jaln_pub_feeder_reset_state(jaln_session *sess);

/**
 * Helper function that determines a size for the message.
 *
 * This sets the jaln_session::pub_data::feeder_sz.
 *
 * @param[in] sess The jaln_session to operate on
 */
void jaln_pub_feeder_calculate_size(jaln_session *sess);

/**
 * Helper utility for calculating the 'size' for the feeder.
 * This function adds \p to_add to \p cnt, while detecting integer overflow.
 * If the results of the addition would overflow an integer, then \p is set to
 * INT_MAX and axl_false is returned.
 *
 * @param[in,out] cnt The value to add to.
 * @param[in] to_add The value to add
 *
 * @return 
 *   - axl_true if the addition was performed successfull
 *   - axl_false if the addtion would result in integer overflow.
 */
axl_bool jaln_pub_feeder_safe_add_size(int64_t *cnt, const uint64_t to_add);

/**
 * Callback executed by when the payload feeder is finished sending a
 * record. This function gets the next record from the user, and gets a new
 * payload feeder primed to send the next record.
 *
 * If the next record cannot be obtained for any reason, then the answer stream
 * is finalized.
 *
 * @param[in] sess The jaln_session sending records.
 */
void jaln_pub_feeder_on_finished(jaln_session *sess);

/**
 * Helper function to start the next record.
 *
 * @param[in] sess The session to operate on.
 * @param[in] journal_offset The offset where to begin sending journal data
 * from. For audit and log data, this is ignored.
 * @param[in] rec_info The record info for the record to be sent.
 *
 * @return JAL_OK on success, or an error.
 */
enum jal_status jaln_pub_begin_next_record_ans(jaln_session *sess,
		struct jaln_record_info *rec_info);

/**
 * Helper function to safely copy data between 2 buffers. Note that the buffers
 * must not overlap, and calling this function with overlapping buffers is
 * undefined.
 *
 * This function copies the maximum number of bytes that is possible, that is
 * to say, if there are 10 bytes left in the source buffer, and 20 bytes
 * available to fill the destination buffer, only 10 bytes will be copied.
 * Conversely, if there are 20 bytes left in the source buffer, and 10 bytes
 * available to fill the destination buffer, only 10 bytes will be copied.
 *
 * Note that this function will fail when there are not enough bytes in the
 * source buffer to fill the destination buffer AND \p more is false.
 *
 * @param[in] dst The destination buffer.
 * @param[in] dst_sz The size of the destination buffer
 * @param[in, out] pdst_off The offset into the destination of where to copy
 * to.
 * @param[in] src The source buffer.
 * @param[in] src_sz The size of the source buffer.
 * @param[in, out] psrc_off The offset into the source of where to begin
 * copying data from.
 * @param[in] more indicates whether or not there are more source buffers
 * (frames) expected
 *
 * @return
 *  - axl_false if an error occured.
 *  - axl_true otherwise.
 */
axl_bool jaln_copy_buffer(uint8_t *dst, const uint64_t dst_size, uint64_t *pdst_off,
		const uint8_t *src, const uint64_t src_sz, uint64_t *psrc_off, axl_bool more);

#endif // JALN_PUB_FEEDER
