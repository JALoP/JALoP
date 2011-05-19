/**
 * @file jalp_alloc.c This file contains wrappers for malloc,
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


#include <jalop/jal_status.h>
#include "jalp_error_callback_internal.h"
#include "jalp_alloc.h"


void *jalp_calloc(size_t nmemb, size_t size)
{
        void *tmp = calloc(nmemb, size);
        if (!tmp) {
               	jalp_error_handler(JAL_E_NO_MEM);
        }
        return tmp;
}

void *jalp_malloc(size_t size)
{
	void * tmp = malloc(size);
	if (!tmp) {
		jalp_error_handler(JAL_E_NO_MEM);
	}
	return tmp;
}

void *jalp_realloc(void *ptr, size_t size)
{
        void *tmp = realloc(ptr, size);
        if (!tmp) {
	/* if ptr was valid and size was zero,then this was
	 * a valid free-like call to realloc and should return a NULL pointer.
	 * Otherwise, a NULL return indicates an error. */
		if (ptr && !size) {
			return NULL;
		}
		else {
			jalp_error_handler(JAL_E_NO_MEM);
		}
        }
        return tmp;
}

char *jalp_strdup(char *str)
{
	if (!str) {
		return NULL;
	}
	char *tmp = strdup(str);
	if (!tmp) {
		jalp_error_handler(JAL_E_NO_MEM);
	}
	return tmp;
}
