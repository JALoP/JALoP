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

#include "jaln_digest_info.h"

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
 *
 * @param[in] frame the VortexFrame to inspect
 * @return axl_true if the content-type and content-transfer encoding are
 * valid, axl_false otherwise.
 */
axl_bool jaln_check_content_type_and_txfr_encoding_are_valid(VortexFrame *frame);

/**
 * Helper function to calculate the number of bytes needed to to convert a
 * jaln_digest_info to a string for sending as part of a digest message.
 *
 * @param[in] di the digest info object.
 * @param return the length of the resulting string, or 0 if an error occurred.
 */
size_t jaln_digest_info_strlen(const struct jaln_digest_info *di);

/**
 * Helper function to append a jaln_digest_info as line for a digest message.
 * This works similar to strcat, and appends the string 'dgst=sid\r\n', i.e.
 * the digest value (as a hex string with no leading 0x) followed by the equals
 * symbol ('=') followed by the serial ID, and finished with a carriage return
 * and line feed.
 * The string \p dst must contain enough space for the entire message and the
 * trailing NULL terminator.
 *
 * @param[in,out] dst The character string to append to.
 * @param[in] di The jaln_digest_info object to output.
 *
 * @return a pointer to \p dst.
 */
char *jaln_digest_info_strcat(char *dst, const struct jaln_digest_info *di);

/**
 * Create the 'digest' message.
 *
 * It is an error to try and create a digest message for an empty list.
 * It is also an error if any of the digest_info objects in the list are not
 * valid.
 *
 * @param[in] dgst_list The list of jaln_digest_info structures to send in the
 * message.
 * @param[out] msg_out The resulting message
 * @param[out] msg_len The length of the resulting message
 *
 *
 * @return
 *  - JAL_OK on success
 *  - JAL_E_INVAL on error
 */
enum jal_status jaln_create_digest_msg(axlList *dgst_list, char **msg_out, size_t *msg_len);

#endif // _JALN_MESSAGE_HELPERS_H_
