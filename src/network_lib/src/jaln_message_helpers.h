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
enum jal_status jaln_create_journal_resume_msg(const char *serial_id, uint64_t offset, char **msg_out, size_t *msg_out_len);

#endif // _JALN_MESSAGE_HELPERS_H_
