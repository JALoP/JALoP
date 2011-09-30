/**
 * @file jaln_connection.c This file contains function
 * definitions for internal library functions related to a jaln_connection
 * structure.
 *
 * @section LICENSE
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
#include "jaln_connection.h"
#include "jal_alloc.h"

struct jaln_connection *jaln_connection_create()
{
	return (struct jaln_connection*) jal_calloc(1, sizeof(struct jaln_connection));
}

void jaln_connection_destroy(struct jaln_connection **conn) {
	// The connection doesn't actually own any of the data members, it just
	// needs pointers back to them.
	if (!conn || !*conn) {
		return;
	}
	free(*conn);
	*conn = NULL;
}
