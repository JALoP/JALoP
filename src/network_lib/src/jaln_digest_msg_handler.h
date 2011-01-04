/**
 * @file jaln_digest_msg_handler.h This file contains the function
 * declarations for helper functions used to process a 'digest'
 * message.
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
#ifndef JALN_DGST_MSG_HANDLER_H
#define JALN_DGST_MSG_HANDLER_H

#include <vortex.h>

#include "jaln_digest_info.h"

/**
 * This function will create a list of jaln_digest_info structures for a
 * given frame.
 *
 * @param[in] frame The (complete) VortexFrame that contains a digest
 * message.
 * @param[out] dgst_list If the message is valid, this will contain a list
 * of jaln_digest_info structures. The caller should free this pointer
 * with axl_list_free().
 *
 * @return
 *  - JAL_OK on success
 *  - JAL_E_INVAL if one of the parameters is bad.
 *  - JAL_E_PARSE_ERROR if the message could not be parsed.
 */
enum jal_status jaln_process_digest(VortexFrame *frame, axlList **dgst_list_out);

#endif // JALN_DGST_MSG_HANDLER_H

