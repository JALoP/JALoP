/**
 * @file jalu_daemonize.h This file contains utility functions to daemonize a process.
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

#ifndef _JALU_DAEMONIZE_H_
#define _JALU_DAEMONIZE_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * daemonizes the process.
 *
 * @return 0 on success, -1 on failure.
 */
int jalu_daemonize();

/**
 * gets the pid and write it to a file if path is not null.
 *
 * @return pid on success, -1 on failure.
 */
int jalu_pid(const char* path);

#ifdef __cplusplus
}
#endif

#endif // _JALU_DAEMONIZE_H_
