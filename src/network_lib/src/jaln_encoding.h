/**
 * @file This file contains function declarations for code related
 * to the xml encodings.
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
#ifndef _JALN_ENCODING_INTERNAL_H_
#define _JALN_ENCODING_INTERNAL_H_
#include <axl.h>
#include <jalop/jal_digest.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>

/**
 * Case-insensitive comparison function for a list of strings.
 *
 * @param[in] a the first string
 * @param[in] b the second string
 * @return
 *  - 0 if the strings are equal
 *  - a negative value if a is '<' b
 *  - a positive value if b is '<' a
 */
int jaln_string_list_case_insensitive_func(axlPointer a, axlPointer b);

/**
 * Function to perform a case-insensitive search in an axl_list object that
 * contains strings.
 *
 * @param[in] ptr The object in the list
 * @param[in] data The string to look for
 */
axl_bool jaln_string_list_case_insensitive_lookup_func(axlPointer ptr, axlPointer data);

#endif // _JALN_ENCODING_INTERNAL_H_