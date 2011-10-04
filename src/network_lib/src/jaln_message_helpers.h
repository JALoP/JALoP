/**
 * @file jaln_message_helpers.h This file contains function
 * declarations for internal library functions related to creating JALoP
 * messages
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
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
#ifndef _JALN_MESSAGE_HELPERS_H_
#define _JALN_MESSAGE_HELPERS_H_

#include <inttypes.h>
#include <stddef.h>
#include <vortex.h>

/**
 * Helper function to create a journal_resume_msg
 *
 * @param[in] serial_id The serial ID to resume
 * @param[in] offset The offset in the journal record to resume data from.
 * @param[out] msg_out This will contain the contents of the initialize message.
 * @param[out] msg_len_out The length of the initialize message
 *
 * @return JAL_E_INVAL if there is something wrong with the parameters, or
 * JAL_OK on success
 *
 */
enum jal_status jaln_create_journal_resume_msg(const char *serial_id,
		uint64_t offset, char **msg_out, size_t *msg_out_len);

/**
 * Helper function to create a sync msg
 *
 * @param[in] serial_id The serial ID to sync
 * @param[out] msg The full message to send to the remote.
 * @param[out] msg_len The length of the resulting message (including the NULL
 * terminator
 */
enum jal_status jaln_create_sync_msg(const char *serial_id, char **msg, size_t *msg_len);

/**
 * Helper function to create a 'subscribe' message
 *
 * @param[in] serial_id The last serial_id to send
 * @param[out] msg_out This will contain the contents of the initialize message.
 * @param[out] msg_len_out The length of the initialize message
 *
 * @return JAL_E_INVAL if there is something wrong with the parameters, or
 * JAL_OK on success
 *
 */
enum jal_status jaln_create_subscribe_msg(const char *serial_id, char **msg_out, size_t *msg_out_len);

/**
 * Sanity check to make sure the MIME headers for a particular frame contain
 * the correct content-type and transfer encoding.
 */
int jaln_check_content_type_and_txfr_encoding_are_valid(VortexFrame *frame);

#endif // _JALN_MESSAGE_HELPERS_H_
