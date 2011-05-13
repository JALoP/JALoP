/**
 * @file jalp_malloc_wrappers.c This file contains wrappers for malloc,
 * calloc, and realloc.
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


#include <include/jalop/jalp_malloc_wrappers.h>
#include <src/jalp_error_callback_internal.h>
#include <lib_common/include/jalop/jal_status.h>


void *jalp_calloc(size_t nmemb, size_t size)
{
        void *tmp = calloc(nmemb, size);
        if (!tmp) {
		if (!nmemb || !size) {
			jalp_error_handler(JAL_E_INVAL);
		}
		else {
                	jalp_error_handler(JAL_E_NO_MEM);
		}
        }
        return tmp;
}

void *jalp_malloc(size_t size)
{
	void * tmp = malloc(size);
	if (!tmp) {
		if (!size) {
			jalp_error_handler(JAL_E_INVAL);
		else {
                	jalp_error_handler(JAL_E_NO_MEM);
		}
	}
	return tmp;
}

void *jalp_realloc(void *ptr, size_t size)
{
        void *tmp = realloc(ptr, size);
        if (!tmp) {
		/* if realloc returns null, but ptr was not null and size was zero,
		 * then this is essentially a call to free and will return normally.
		 * Otherwise, there was an error */
		if (!ptr && !size) {
			jalp_error_handler(JAL_E_INVAL);
		}
		else if (!ptr) {
                	jalp_error_handler(JAL_E_NO_MEM);
		}
		else if (size) {
			jalp_error_handler(JAL_E_NO_MEM);
		}
        }
        return tmp;
}
