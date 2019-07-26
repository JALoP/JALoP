/**
 * @file jaln_pub_feeder.h This file contains the functions related to the
 * implementation of VortexPayloadFeeder for sending records from a publisher
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

#include <apr-1/apr_thread_pool.h>

#include "jaln_session.h"

/**
 * function for Vortex to return the 'size' of the record.
 *
 * @param[in] sess The session to operate on.
 * @param[out] size The size (in bytes). The size returned may not be accruate,
 * but vortex only uses it as an estimate. Vortex will continue to try and send
 * data until 'jaln_pub_feeder_is_finished' returns true.
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
 * If the callback has aborted or the record has been successfully read,
 * complete will be set true so that the transfer is treated as "finished" twice
 * the case of a curl failure (eg connection reset by peer).
 */
struct jaln_readfunc_info
{
        jaln_session *sess;
        axl_bool complete;
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
 * Function used to report to vortex if there is more data available, or if we
 * are finished sending this record.
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
 * Function registered with apr to send a record using curl and receive
 * the response.
 *
 * @param[in] thread The thread we are running in
 * @param[in] user_data The jaln_session
 *
 * @return axl_true on success, axl_false otherwise.
 */
void * APR_THREAD_FUNC jaln_pub_feeder_handler(__attribute__((unused)) apr_thread_t *thread,
		void *user_data);

/**
 * Helper function to reset the state of the publisher data. This resets the
 * offsets/sizes to NULL, creates a new digest context instance, etc.
 *
 * @param[in] sess The session to reset.
 */
void jaln_pub_feeder_reset_state(jaln_session *sess);

/**
 * Helper function that determines a size for the message.
 * This fudges the numbers slightly since BEEP essentially allows any sized
 * data to be sent. Vortex requests the size as an int, but only uses this to
 * determine the initial window size to allocate for the feeder. Vortex will
 * not stop sending data until we report there is no more data to send.
 *
 * This sets the jaln_session::pub_data::vortex_feeder_sz.
 *
 * @param[in] sess The jaln_session to operate on
 */
void jaln_pub_feeder_calculate_size_for_vortex(jaln_session *sess);

/**
 * Helper utility for calculating the 'size' for vortex.
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
 * @param[in] chan The vortex channel to send the data over.
 *
 * @return JAL_OK on success, or an error.
 */
enum jal_status jaln_pub_begin_next_record_ans(jaln_session *sess,
		struct jaln_record_info *rec_info);

#endif // JALN_PUB_FEEDER
