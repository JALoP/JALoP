/**
 * @file jalls_handle_journal.hpp This file contains functions to handle a journal
 * to the jal local store.
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

#ifndef _JALLS_HANDLE_JOURNAL_HPP_
#define _JALLS_HANDLE_JOURNAL_HPP_

#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "jalls_handler.h"

#ifdef __cplusplus
extern "C" {
#endif

int jalls_handle_journal(struct jalls_thread_context *thread_ctx, uint64_t data_len, uint64_t meta_len);

#ifdef __cplusplus
}
#endif

#endif // _JALLS_HANDLE_JOURNAL_HPP_

