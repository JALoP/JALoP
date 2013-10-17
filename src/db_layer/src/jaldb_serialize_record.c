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

/**
 * @section DB_LAYOUT Database Layout
 *
 * This section covers the in-database layout of of a JALoP record.
 * The goal of the in-database layout is to be as simple as possible while
 * allowing access to important fields (i.e. for indexing) in a simple
 * manner. Boolean fields are packed using bit-masks for some minor space
 * savings.
 *
 * @subsection ByteOrdering Byte Ordering
 * Berkeley DB does not perform any byte swapping of data as it is inserted or
 * retrieved from the DB. Therefore, the code here that
 * serializes/de-serializes a JALoP record performs byte-swapping as necessary.
 * This would allow (in the future) for a JALoP DB created on a big-endian
 * machine to be transferred & read by JALoP Processes on a little-endian
 * machine.
 *
 * @subsection RecordLayout Record Layout
 * The type of record (journal, audit, log) does not affect the layout of the
 * record in the database, nor is the type of the record stored with the data
 * associated withe the record. Distinct databases are kept for each type of
 * record. The in-database representation of a record can be viewed as a
 * collection of record headers (binary numbers & flags) followed by a
 * collection of strings. All strings are null-terminated. The length of a
 * string is not stored in the database.
 *
 * @subsubsection RecordHeaders Record Headers
 * The order, size, and type of the records headers is documented in the
 * section \ref jaldb_serialze_record_headers.
 *
 * @subsubsection StringData Record String Data
 * Each record includes the following string data
 *  - timestamp\n
 *      This is an <a href http://www.w3.org/TR/xmlschema-2/#dateTimeXML>XML Schema DateTime</a>.
 *      It is always stored in UTC time (i.e. timezone 'z'). Because it is not always possible to compare
 *      DateTimes when one has a timezone and another does not, when a DateTime is
 *      missing timezone data, it is assumed to be in UTC time, and a 'z' will be
 *      appended to it.
 *  - source\n
 *      This is the \p source of the record, not to be confused with
 *      the \p hostname. The \p source indicates (as far as a network store is
 *      concerned) where a record came from.
 *  - Security Label\n
 *      This is the Security Label (if any) of the process that generated the
 *      record.
 *  - hostname\n
 *      This is the \p hostname of the machine where the event was generated
 *  - username\n
 *      This is the \p username of the process that generated the event.
 *  - System Meta-data\n
 *      This is either the raw System Meta-data document, empty, or the relative
 *      path on disk to the actual system meta-data.
 *  - Application Meta-data\n
 *      This is the raw Application Meta-data document, empty, or the relative
 *      path on disk to the actual application meta-data.
 *  - Payload\n
 *      This is the raw payload (journal, audit, or log data), empty, or the relative
 *      path on disk to the actual payload data is stored
 *
 * Because the System Meta-data, Application Meta-data, and Payload, may be
 * null, a path, or just a blob of data, they are treated slightly differently
 * than the rest of the fields. The \p flags in the headers indicate which (if
 * any) of these sections are included with the record. Unlike the other string
 * data segments, if one of these sections is omitted, a \p null terminator is
 * not stored for the segment.
 *
 * Although System Meta-Data is required for each record, to reduce processing
 * on insertions to the local store, the actual System Meta-Data document may be
 * omitted. Note that the record stored in the database has all the
 * necessary information to create the XML document as needed.
 */

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
	ret = jaldb_serialize_inc_by_string(&size, record->network_nonce);
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
	if (1 == record->synced) {  // record is sent but not synced
		headers.flags |= bs32(JALDB_RFLAGS_SENT);
	}
	if (2 == record->synced) { // record is both synced and sent
		headers.flags |= bs32(JALDB_RFLAGS_SYNCED);
		headers.flags |= bs32(JALDB_RFLAGS_SENT);
	}
	headers.pid = bs64(record->pid);
	headers.uid = bs64(record->uid);
	uuid_copy(headers.host_uuid, record->host_uuid);
	uuid_copy(headers.record_uuid, record->uuid);

	buf = (uint8_t*)jal_malloc(size);
	memcpy(buf, &headers, sizeof(headers));
	uint8_t *tmp = buf + sizeof(headers);
	jaldb_serialize_add_string(&tmp, record->timestamp);
	jaldb_serialize_add_string(&tmp, record->network_nonce);
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
					uint8_t *buffer,
					size_t bsize,
					struct jaldb_record **record)
{
	struct jaldb_serialize_record_headers *headers = NULL;
	struct jaldb_record *res = NULL;
	enum jaldb_status ret = JALDB_E_UNKNOWN;
	bs16_func bs16 = NULL;
	bs32_func bs32 = NULL;
	bs64_func bs64 = NULL;
	if (!buffer || !record || *record) {
		ret = JALDB_E_INVAL;
		goto err_out;
	}

	if (bsize < sizeof(*headers)) {
		ret = JALDB_E_INVAL;
		goto err_out;
	}

	if (byte_swap) {
		bs16 = jaldb_bs16;
		bs32 = jaldb_bs32;
		bs64 = jaldb_bs64;
	} else {
		bs16 = jaldb_bs16_nop;
		bs32 = jaldb_bs32_nop;
		bs64 = jaldb_bs64_nop;
	}

	headers = (struct jaldb_serialize_record_headers*) buffer;
	res = jaldb_create_record();

	headers->version = bs16(headers->version);
	if (headers->version != JALDB_DB_LAYOUT_VERSION) {
		ret = JALDB_E_LAYOUT_VERSION_UNKNOWN;
		goto err_out;
	}
	headers->flags = bs32(headers->flags);

	res->version = JALDB_DB_LAYOUT_VERSION;
	res->type = JALDB_RTYPE_UNKNOWN;
	if (headers->flags & JALDB_RFLAGS_SENT && headers->flags & JALDB_RFLAGS_SYNCED) {
		res->synced = 2; // Record sent and synced.
	} else if (!(headers->flags & JALDB_RFLAGS_SYNCED) && headers->flags & JALDB_RFLAGS_SENT) {
		res->synced = 1; // Record sent but not synced.
	} else {
		res->synced = 0; // Record not sent.
	}
	res->have_uid = headers->flags & JALDB_RFLAGS_HAVE_UID ? 1 : 0;
	res->pid = bs64(headers->pid);
	res->uid = bs64(headers->uid);
	uuid_copy(res->host_uuid, headers->host_uuid);
	uuid_copy(res->uuid, headers->record_uuid);

	buffer += sizeof(*headers);
	bsize -= sizeof(*headers);

	ret = jaldb_deserialize_string(&buffer, &bsize, &res->timestamp);
	if (ret != JALDB_OK) {
		goto err_out;
	}
	ret = jaldb_deserialize_string(&buffer, &bsize, &res->network_nonce);
	if (ret != JALDB_OK) {
		goto err_out;
	}
	ret = jaldb_deserialize_string(&buffer, &bsize, &res->source);
	if (ret != JALDB_OK) {
		goto err_out;
	}
	ret = jaldb_deserialize_string(&buffer, &bsize, &res->sec_lbl);
	if (ret != JALDB_OK) {
		goto err_out;
	}
	ret = jaldb_deserialize_string(&buffer, &bsize, &res->hostname);
	if (ret != JALDB_OK) {
		goto err_out;
	}
	ret = jaldb_deserialize_string(&buffer, &bsize, &res->username);
	if (ret != JALDB_OK) {
		goto err_out;
	}

	if (headers->flags & JALDB_RFLAGS_HAVE_SYS_META) {
		ret = jaldb_deserialize_segment(headers->flags & JALDB_RFLAGS_SYS_META_ON_DISK ? 1 : 0,
				headers->sys_meta_sz,
				&buffer,
				&bsize,
				&res->sys_meta);
		if (ret != JALDB_OK) {
			goto err_out;
		}
	}

	if (headers->flags & JALDB_RFLAGS_HAVE_APP_META) {
		ret = jaldb_deserialize_segment(headers->flags & JALDB_RFLAGS_APP_META_ON_DISK ? 1 : 0,
				headers->app_meta_sz,
				&buffer,
				&bsize,
				&res->app_meta);
		if (ret != JALDB_OK) {
			goto err_out;
		}
	}
	if (headers->flags & JALDB_RFLAGS_HAVE_PAYLOAD) {
		ret = jaldb_deserialize_segment(headers->flags & JALDB_RFLAGS_PAYLOAD_ON_DISK ? 1 : 0,
				headers->payload_sz,
				&buffer,
				&bsize,
				&res->payload);
		if (ret != JALDB_OK) {
			goto err_out;
		}
	}

	*record = res;
	goto out;
err_out:
	jaldb_destroy_record(&res);
out:
	return ret;
}

enum jaldb_status jaldb_deserialize_string(uint8_t **buffer, size_t *size, char** str)
{
	if (!buffer || !*buffer || !size || !str || *str) {
		return JALDB_E_INVAL;
	}
	if (*size == 0) {
		return JALDB_E_INVAL;
	}
	size_t s_len = strlen((char*)*buffer);
	if (0 == s_len) {
		*str = NULL;
		*buffer += 1;
		*size -= 1;
		return JALDB_OK;
	}

	if (s_len >= *size) {
		// ran off the end, not good.
		return JALDB_E_INVAL;
	}

	*str = jal_strdup((char*)*buffer);
	*buffer += (s_len + 1);
	*size -= (s_len + 1);
	return JALDB_OK;
}

enum jaldb_status jaldb_deserialize_segment(char on_disk,
		size_t segment_length,
		uint8_t **buffer,
		size_t *bsize,
		struct jaldb_segment **segment)
{
	if (!buffer || !*buffer || !bsize || !segment || *segment) {
		return JALDB_E_INVAL;
	}
	enum jaldb_status ret;
	struct jaldb_segment *seg = jaldb_create_segment();
	seg->length = segment_length;
	if (on_disk) {
		char *pl = NULL;
		ret = jaldb_deserialize_string(buffer, bsize, &pl);
		if (ret != JALDB_OK) {
			ret = JALDB_E_INVAL;
			goto err_out;
		}
		seg->payload = (uint8_t*) pl;
		seg->on_disk = 1;
	} else {
		seg->on_disk = 0;
		if (seg->length > *bsize) {
			ret = JALDB_E_INVAL;
			goto err_out;
		}
		seg->payload = (uint8_t*)jal_malloc(seg->length);
		memcpy(seg->payload, *buffer, seg->length);
		*buffer += seg->length;
		*bsize -= seg->length;
	}
	ret = JALDB_OK;
	*segment = seg;
	goto out;
err_out:
	jaldb_destroy_segment(&seg);
out:
	return ret;
}
