/**
 * @file jal_asprintf_internal.h
 * Declares the jal_asprintf function
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2010, 2011 Tresys Technology LLC, Columbia, Maryland, USA
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
 *
 */

#ifndef _JAL_ASPRINTF_INTERNAL_H_
#define _JAL_ASPRINTF_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * wrapper for asprintf
 *
 * @param str pointer to the string to be allocated
 * @param fmt format string
 *
 * @returns The length of the str (not counting the '\0' character). Calls
 * error handler on error.
 */
int jal_asprintf(char **str, const char *fmt, ...);

#ifdef  __cplusplus
}
#endif
#endif
