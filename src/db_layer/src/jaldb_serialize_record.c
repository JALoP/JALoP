/**
 * @file jaldb_serialize_record.c This file contains to seriailze/deserialize a
 * jaldb_record to/from a raw memory buffer.
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
#include <stdint.h>
#include <string.h>

#include "jal_alloc.h"
#include "jal_byteswap.h"

#include "jaldb_record.h"
#include "jaldb_segment.h"
#include "jaldb_serialize_record.h"

typedef uint16_t (*bs16_func)(const uint16_t);
typedef uint32_t (*bs32_func)(const uint32_t);
typedef uint64_t (*bs64_func)(const uint64_t);

static uint16_t jaldb_bs16_nop(const uint16_t b)
{
	return b;
}
static uint32_t jaldb_bs32_nop(const uint32_t b)
{
	return b;
}
static uint64_t jaldb_bs64_nop(const uint64_t b)
{
	return b;
}

static uint16_t jaldb_bs16(const uint16_t b)
{
	return jal_bswap_16(b);
}
static uint32_t jaldb_bs32(const uint32_t b)
{
	return jal_bswap_32(b);
}
static uint64_t jaldb_bs64(const uint64_t b)
{
	return jal_bswap_64(b);
}

/**
 * This macro performs the needed checks to increment a size_t variable by a
 * given value. The macro expects a \b err_out as well as a variable named \b
 * ret to hold the results of the addition.
 *
 * @param v The variable to increment.
 * @param inc The amount to increment by.
 */
#define JALDB_SAFE_INC_OR_GOTO_ERR_OUT(v, inc) \
	do {\
		uint64_t __inc = inc; \
		if (__inc >= SIZE_MAX) { \
			ret = JALDB_E_SIZE; \
			goto err_out; \
		} \
		if (SIZE_MAX - __inc < v) { \
			ret = JALDB_E_SIZE; \
			goto err_out; \
		} \
		v += __inc; \
	} while(0)

void jaldb_serialize_add_string(uint8_t **buf, const char *str)
{
	if (!str) {
		(*buf)[0] = '\0';
		*buf += 1;
		return;
	}
	size_t len = strlen(str);
	memcpy(*buf, str, len + 1);
	*buf += len + 1;
}

enum jaldb_status jaldb_serialize_inc_by_string(size_t *size, const char *str)
{
	size_t tmp = *size;
	enum jaldb_status ret;
	if (!str) {
		JALDB_SAFE_INC_OR_GOTO_ERR_OUT(*size, (unsigned)1); // still need null terminator
		ret = JALDB_OK;
		goto err_out;;
	}
	JALDB_SAFE_INC_OR_GOTO_ERR_OUT(tmp, strlen(str));
	JALDB_SAFE_INC_OR_GOTO_ERR_OUT(tmp, (unsigned)1);
	*size = tmp;
	ret = JALDB_OK;
err_out:
	return ret;
}

void jaldb_serialize_add_segment(uint8_t **buf, const struct jaldb_segment *segment)
{
	if (!segment) {
		return;
	}
	if (segment->on_disk) {
		return jaldb_serialize_add_string(buf, (char*)segment->payload);
	}
	memcpy(*buf, segment->payload, segment->length);
	*buf += segment->length;
}

enum jaldb_status jaldb_serialize_inc_by_segment_size(size_t *size, const struct jaldb_segment *segment)
{
	int ret;
	if (!segment) {
		return JALDB_OK;
	}
	if (segment->on_disk) {
		if (!segment->payload) {
			ret = JALDB_E_INVAL;
			goto err_out;
		}
		size_t tmp = *size;
		JALDB_SAFE_INC_OR_GOTO_ERR_OUT(tmp, strlen((char*) segment->payload));
		JALDB_SAFE_INC_OR_GOTO_ERR_OUT(tmp, 1);
		*size = tmp;
		ret = JALDB_OK;
		goto err_out;
	}
	JALDB_SAFE_INC_OR_GOTO_ERR_OUT(*size, segment->length);
	ret = JALDB_OK;
err_out:
	return ret;
}

enum jaldb_status jaldb_serialize_record(
					const char byte_swap,
					struct jaldb_record *record,
					uint8_t **buffer,
					size_t *bsize)
{
	uint8_t *buf = NULL;
	enum jaldb_status ret;
	if (!record || !buffer || *buffer || !bsize) {
		ret = JALDB_E_INVAL;
		goto err_out;
	}
	bs16_func bs16;
	bs32_func bs32;
	bs64_func bs64;
	if (byte_swap) {
		bs16 = jaldb_bs16;
		bs32 = jaldb_bs32;
		bs64 = jaldb_bs64;
	} else {
		bs16 = jaldb_bs16_nop;
		bs32 = jaldb_bs32_nop;
		bs64 = jaldb_bs64_nop;
	}

	size_t size = 0;
	struct jaldb_serialize_record_headers headers;
	memset(&headers, 0, sizeof(headers));

	JALDB_SAFE_INC_OR_GOTO_ERR_OUT(size, sizeof(headers));
	ret = jaldb_serialize_inc_by_segment_size(&size, record->sys_meta);
	if (JALDB_OK != ret) {
		goto err_out;
	}
	ret = jaldb_serialize_inc_by_segment_size(&size, record->app_meta);
	if (JALDB_OK != ret) {
		goto err_out;
	}
	ret = jaldb_serialize_inc_by_segment_size(&size, record->payload);
	if (JALDB_OK != ret) {
		goto err_out;
	}
	ret = jaldb_serialize_inc_by_string(&size, record->source);
	if (JALDB_OK != ret) {
		goto err_out;
	}
	ret = jaldb_serialize_inc_by_string(&size, record->sec_lbl);
	if (JALDB_OK != ret) {
		goto err_out;
	}
	ret = jaldb_serialize_inc_by_string(&size, record->hostname);
	if (JALDB_OK != ret) {
		goto err_out;
	}
	ret = jaldb_serialize_inc_by_string(&size, record->username);
	if (JALDB_OK != ret) {
		goto err_out;
	}
	ret = jaldb_serialize_inc_by_string(&size, record->timestamp);
	if (JALDB_OK != ret) {
		goto err_out;
	}

	headers.version = bs16(JALDB_DB_LAYOUT_VERSION);
	if (record->sys_meta) {
		headers.flags |= bs32(JALDB_RFLAGS_HAVE_SYS_META);
		if (record->sys_meta->on_disk) {
			headers.flags |= bs32(JALDB_RFLAGS_SYS_META_ON_DISK);
		}
		headers.sys_meta_sz = bs64(record->sys_meta->length);
	}
	if (record->app_meta) {
		headers.flags |= bs32(JALDB_RFLAGS_HAVE_APP_META);
		if (record->app_meta->on_disk) {
			headers.flags |= bs32(JALDB_RFLAGS_APP_META_ON_DISK);
		}
		headers.app_meta_sz = bs64(record->app_meta->length);
	}
	if (record->payload) {
		headers.flags |= bs32(JALDB_RFLAGS_HAVE_PAYLOAD);
		if (record->payload->on_disk) {
			headers.flags |= bs32(JALDB_RFLAGS_PAYLOAD_ON_DISK);
		}
		headers.payload_sz = bs64(record->payload->length);
	}
	if (record->have_uid) {
		headers.flags |= bs32(JALDB_RFLAGS_HAVE_UID);
	}
	if (record->synced) {
		headers.flags |= bs32(JALDB_RFLAGS_SYNCED);
	}
	headers.pid = bs64(record->pid);
	headers.uid = bs64(record->uid);
	uuid_copy(headers.host_uuid, record->host_uuid);
	uuid_copy(headers.record_uuid, record->uuid);

	buf = (uint8_t*)jal_malloc(size);
	memcpy(buf, &headers, sizeof(headers));
	uint8_t *tmp = buf + sizeof(headers);
	jaldb_serialize_add_string(&tmp, record->timestamp);
	jaldb_serialize_add_string(&tmp, record->source);
	jaldb_serialize_add_string(&tmp, record->sec_lbl);
	jaldb_serialize_add_string(&tmp, record->hostname);
	jaldb_serialize_add_string(&tmp, record->username);
	jaldb_serialize_add_segment(&tmp, record->sys_meta);
	jaldb_serialize_add_segment(&tmp, record->app_meta);
	jaldb_serialize_add_segment(&tmp, record->payload);

	*buffer = buf;
	*bsize = size;
	ret = JALDB_OK;
	goto out;
err_out:
	free(buf);
out:
	return ret;
}

enum jaldb_status jaldb_deserialize_record(
					const char byte_swap,
					const uint8_t *buffer,
					const size_t bsize,
					struct jaldb_record **record)
{
	if (!buffer || !record || !*record) {
		return JALDB_E_INVAL;
	}
	return JALDB_E_NOT_IMPL;
}
