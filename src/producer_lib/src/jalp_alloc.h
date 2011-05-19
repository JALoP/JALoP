/**
 * @file jalp_alloc.h This file defines wrappers for malloc, calloc,
 * and realloc for use by the Producer Library.
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

#ifndef _JALP_ALLOC_H_
#define _JALP_ALLOC_H_

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup Malloc Wrappers
 * The functions here are wrappers for malloc calls.
 *
 * The jalp producer library wraps the standard malloc calls
 * and checks the return code. If an allocation failure occurs,
 * this results in a call to jalp_error_handler.
 *
 */


/**
 * Calls calloc.
 * If calloc returns with no issues, returns a pointer to the allocated memory.
 * Otherwise, calls jalp_error_handler.
 *
 * @param[in] nmemb Number of elements to be allocated.
 *
 * @param[in] size Size of each element.
 *
 * @return a void pointer to the allocated memory, to be freed with free()
 *
 */
void *jalp_calloc(size_t nmemb, size_t size);

/**
 * Calls malloc.
 * If malloc returns with no issues, returns a pointer to the allocated memory.
 * Otherwise, calls jalp_error_handler.
 *
 * @param[in] size The size of the allocation.
 *
 * @return a void pointer to the allocated memory, to be freed with free()
 *
 */
void *jalp_malloc(size_t size);

/**
 * Calls realloc.
 * If realloc returns with no issues, returns a pointer to the allocated memory.
 * Otherwise, calls jalp_error_handler.
 *
 * @param[in] ptr pointer to memory block to be changed.
 *
 * @param[in] size New size of the allocation.
 *
 * @return a void pointer to the reallocated memory, to be freed with free()
 *
 */
void *jalp_realloc(void *ptr, size_t size);

/**
 * Calls strdup.
 * If strdup returns with no issues, returns a pointer to the new duplicate 
 * string.
 * Otherwise, calls jalp_error_handler.
 * 
 * @param[in] str pointer to string to be duplicated.
 *
 * @return a char pointer to the duplicate string, to be freed with free()
 *
 */
char *jalp_strdup(void *str);

#ifdef __cplusplus
}
#endif

#endif //_JALP_ALLOC_H_
