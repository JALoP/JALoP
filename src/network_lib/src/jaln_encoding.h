/**
 * @file jaln_encoding.h This file contains function declarations for code related
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

/**
 * Function to convert an axlList of strings (char*) to an array of strings.
 * The resulting array is not NULL terminated. Each element in the array is a
 * copy of the string that was in the axlList. If NULL pointers are found in
 * \p list, they are copied to the resulting array as NULL. The array may be
 * freed by calling jaln_string_array_destroy();
 *
 * @param[in] list The list of strings
 * @param[out] arr_out The resulting array.
 * @param[out] size_out The size of the array.
 *
 * @return JAL_OK on success, or JAL_E_INVAL if any of the parameters were
 * invalid.
 */
enum jal_status jaln_axl_string_list_to_array(axlList *list,
		char ***arr_out,
		int *size_out);

/**
 * Function to release the memory allocated for an array of char *, such as is
 * returned by jaln_axl_string_list_to_array.
 *
 * @param[in,out] arr The array to destroy.
 * @param[in] arr_size The length of the array.
 */
void jaln_string_array_destroy(char ***arr, int arr_size);

#endif // _JALN_ENCODING_INTERNAL_H_
