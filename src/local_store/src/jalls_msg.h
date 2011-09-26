/**
 * @file jalls_msg.h This file contains helper functions to deal with
 * receiving messages for the jal local store.
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

#ifndef _JALLS_MSG_H_
#define _JALLS_MSG_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Wrapper function for recvmsg()
 *
 * @param[in] fd The file descriptor to read from.
 * @param[in, out] msgh The msghdr structure to read into.
 * @param[in] debug A flag to indicate whether to print debug messages to stderr.
 *
 * @return -1 on failure, or the number of bytes received on success.
 */
int jalls_recvmsg_helper(int fd, struct msghdr *msgh, int debug);

#ifdef __cplusplus
}
#endif

#endif // _JALLS_MSG_H_
