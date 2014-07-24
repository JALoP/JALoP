/**
 * @file jaldb_record_extract.c Implementation of utilties related to the record
 * UUID stored with the JALoP record in the database.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <uuid/uuid.h>
#include <stdio.h>
#include <string.h>

#include "jal_alloc.h"

#include "jaldb_record_extract.h"
#include "jaldb_serialize_record.h"

int jaldb_extract_record_uuid(DB *secondary, const DBT *key, const DBT *data, DBT *result)
{
	struct jaldb_serialize_record_headers *headers = NULL;

	if (!data || !result || !data->data || (sizeof(headers) > data->size)) {
		return -1;
	}

	headers = (struct jaldb_serialize_record_headers*)data->data;

	// TODO: Need BOM for this to work correctly
	if (headers->version != JALDB_DB_LAYOUT_VERSION) {
		return -1;
	}

	result->data = jal_malloc(sizeof(uuid_t));
	uuid_copy(result->data, headers->record_uuid);
	result->size = sizeof(uuid_t);
	result->flags = DB_DBT_APPMALLOC;

	return 0;
}

int jaldb_extract_record_sent_flag(DB *secondary, const DBT *key, const DBT *data, DBT *result)
{
	struct jaldb_serialize_record_headers *headers = NULL;

	if (!data || !result || !data->data || (sizeof(headers) > data->size)) {
		return -1;
	}

	headers = (struct jaldb_serialize_record_headers*)data->data;

	// TODO: Need BOM for this to work correctly
	if (headers->version != JALDB_DB_LAYOUT_VERSION) {
		return -1;
	}

	result->data = jal_malloc(sizeof(uint32_t));
	*((uint32_t*)(result->data)) = headers->flags & JALDB_RFLAGS_SENT;
	result->size = sizeof(uint32_t);
	result->flags = DB_DBT_APPMALLOC;

	return 0;
}

int jaldb_extract_record_network_nonce(DB *secondary, const DBT *key, const DBT *data, DBT *result)
{
	char *nnString = NULL;
	size_t nnLen = 0;

	struct jaldb_serialize_record_headers *headers = NULL;

	if (!data || !result || !data->data || (sizeof(headers) > data->size + JALDB_TIMESTAMP_LENGTH + 1)) {
		return -1;
	}

	const uint8_t *buffer = data->data;
	headers = (struct jaldb_serialize_record_headers*) buffer;

	// TODO: Need BOM for this to work correctly
	if (headers->version != JALDB_DB_LAYOUT_VERSION) {
		return -1;
	}

	// Skip the headers and timestamp string (including null terminator).
	buffer += sizeof(*headers) + JALDB_TIMESTAMP_LENGTH + 1;
	nnString = (char*)buffer;
	nnLen = strlen(nnString);

	result->data = jal_strdup(nnString);
	result->size = nnLen + 1; // keep the null terminator

	result->flags = DB_DBT_APPMALLOC;

	return 0;
}

int jaldb_extract_record_confirmed_flag(DB *secondary, const DBT *key, const DBT *data, DBT *result)
{
	struct jaldb_serialize_record_headers *headers = NULL;

	if (!data || !result || !data->data || (sizeof(headers) > data->size)) {
		return -1;
	}

	headers = (struct jaldb_serialize_record_headers*)data->data;

	// TODO: Need BOM for this to work correctly
	if (headers->version != JALDB_DB_LAYOUT_VERSION) {
		return -1;
	}


	result->data = jal_malloc(sizeof(uint32_t));
	*((uint32_t*)(result->data)) = headers->flags & JALDB_RFLAGS_CONFIRMED;
	result->size = sizeof(uint32_t);

	result->flags = DB_DBT_APPMALLOC;

	return 0;
}
