/**
 * @file jal_alloc.c This file contains wrappers for malloc,
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


#include <string.h>
#include <jalop/jal_status.h>
#include "jal_error_callback_internal.h"
#include "jal_alloc.h"


void *jal_calloc(size_t nmemb, size_t size)
{
        void *tmp = calloc(nmemb, size);
        if (!tmp) {
               	jal_error_handler(JAL_E_NO_MEM);
        }
        return tmp;
}

void *jal_malloc(size_t size)
{
	void * tmp = malloc(size);
	if (!tmp) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	return tmp;
}

void *jal_realloc(void *ptr, size_t size)
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
			jal_error_handler(JAL_E_NO_MEM);
		}
        }
        return tmp;
}

char *jal_strdup(const char *str)
{
	if (!str) {
		return NULL;
	}
	char *tmp = strdup(str);
	if (!tmp) {
		jal_error_handler(JAL_E_NO_MEM);
	}
	return tmp;
}

char *jal_strndup(const char *str, size_t size)
{
	/* Return immediately if there is nothing to copy */
	if (0 == size || !str) {
		return NULL;
	}

	char *tmp = strndup(str, size);
	if (!tmp) {
		jal_error_handler(JAL_E_NO_MEM);
	}

	return(tmp);
}

char *jal_memdup(const char *buf, size_t size)
{
	/* Return immediately if there is nothing to copy */
	if (0 == size || !buf) {
		return NULL;
	}

	char *tmp = malloc(size); 
	if (!tmp) {
		jal_error_handler(JAL_E_NO_MEM);
	}

	/* binary copy of requested size */
	memcpy(tmp, buf, size);
	return(tmp);
}

