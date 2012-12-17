/**
 * @file jalls_record_utils.h Function declarations for obtaining various hunks
 * of metadata.
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
#ifndef _JALLS_UID_UTILS_H_
#define _JALLS_UID_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __HAVE_SELINUX
/**
 * Retrieve the platform specific security label.
 * @param[in] socketFd the file descriptor to use when obtaining the security
 * label.
 */
char *jalls_get_security_label(int socketFd);
#endif

#ifdef __cplusplus
}
#endif

#endif

