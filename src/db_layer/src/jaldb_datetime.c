/**
 * @file jaldb_datetime.c Implementation of utilties related to XML DateTime
 * strings within the JALoP DBs.
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

#include <ctype.h>
#include <libxml/xmlschemastypes.h>
#include <jalop/jal_status.h>
#include <string.h>

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"

#include "jaldb_datetime.h"
#include "jaldb_serialize_record.h"

int jaldb_xml_datetime_compare(DB *db, const DBT *dbt1, const DBT *dbt2)
{
	int xml_ret;
	xmlSchemaValPtr dt1 = NULL;
	xmlSchemaValPtr dt2 = NULL;
	xmlSchemaTypePtr xs_datetime = NULL;

	xs_datetime = xmlSchemaGetBuiltInType(XML_SCHEMAS_DATETIME);
	if (NULL == xs_datetime) {
		jal_error_handler(JAL_E_UNINITIALIZED);
	}

	xml_ret = xmlSchemaValidatePredefinedType(xs_datetime, (const xmlChar*) dbt1->data, &dt1);
	if (0 != xml_ret) {
		jal_error_handler(JAL_E_XML_PARSE);
	}

	xml_ret = xmlSchemaValidatePredefinedType(xs_datetime, (const xmlChar*) dbt2->data, &dt2);
	if (0 != xml_ret) {
		jal_error_handler(JAL_E_XML_PARSE);
	}

	xml_ret = xmlSchemaCompareValues(dt1, dt2);
	xmlSchemaFreeValue(dt1);
	xmlSchemaFreeValue(dt2);

	switch(xml_ret) {
	case -1:
	case 0:
	case 1:
		return xml_ret;
	default:
		jal_error_handler(JAL_E_INVAL);
	}

	// This really never get here because of the jal_error_handler() call,
	// but need to do something or else the compiler complains.
	return 0;
}

enum jaldb_status jaldb_extract_datetime_key_common(
		const uint8_t* buffer,
		char **dtString,
		size_t *dtLen,
		char *has_tz)
{
	enum jaldb_status ret = JALDB_E_INVAL;
	struct jaldb_serialize_record_headers *headers = NULL;
	char *stmp;
	size_t slen;
	int xml_ret;

	if (!buffer || !dtString || *dtString || !dtLen || !has_tz) {
		return JALDB_E_INVAL;
	}

	headers = (struct jaldb_serialize_record_headers*)buffer;
	xmlSchemaValPtr dt = NULL;
	xmlSchemaTypePtr xs_datetime = NULL;

	xs_datetime = xmlSchemaGetBuiltInType(XML_SCHEMAS_DATETIME);
	if (NULL == xs_datetime) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	// TODO: Need BOM for this to work correctly
	if (headers->version != JALDB_DB_LAYOUT_VERSION) {
		ret = JALDB_E_CORRUPTED;
		goto out;
	}

	buffer += sizeof(*headers);
	stmp = (char*)buffer;
	slen = strlen(stmp);

	xml_ret = xmlSchemaValidatePredefinedType(xs_datetime, (const xmlChar*) buffer, &dt);
	if (0 != xml_ret) {
		ret = JALDB_E_INVAL;
		goto out;
	}

	// Check for timezone...
	*has_tz = 0;
	if (toupper(stmp[slen - 1] == 'Z')) {
		*has_tz = 1;
	} else {
		size_t tz_len = strlen("+00:00");
		if (tz_len >= slen) {
			// This should never happen since a valid datetime
			// string should be well over 6 characters long.
			ret = JALDB_E_INVAL;
			goto out;
		}
		char *tz = stmp + (slen - tz_len);
		if (('-' == tz[0]) || ('+' == tz[0])) {
			if (isdigit(tz[1]) && isdigit(tz[2]) && (':' == tz[3]) &&
				isdigit(tz[4]) && isdigit(tz[5])) {
				*has_tz = 1;
			}
		}
	}
	ret = JALDB_OK;
	*dtString = stmp;
	*dtLen = slen;
out:
	if (dt) {
		xmlSchemaFreeValue(dt);
	}
	return ret;
}

int jaldb_extract_datetime_w_tz_key(DB *secondary, const DBT *key, const DBT *data, DBT *result)
{
	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;
	char has_tz = 0;

	ret = jaldb_extract_datetime_key_common(data->data, &dtString, &dtLen, &has_tz);
	if (ret != JALDB_OK) {
		return -1;
	}
	if (has_tz) {
		result->data = jal_strdup(dtString);
		result->size = dtLen + 1; // keep the null terminator
		result->flags = DB_DBT_APPMALLOC;
		return 0;
	}
	return DB_DONOTINDEX;
}

int jaldb_extract_datetime_wo_tz_key(DB *secondary, const DBT *key, const DBT *data, DBT *result)
{
	enum jaldb_status ret;
	char *dtString = NULL;
	size_t dtLen = 0;
	char has_tz = 0;

	ret = jaldb_extract_datetime_key_common(data->data, &dtString, &dtLen, &has_tz);
	if (ret != JALDB_OK) {
		return -1;
	}
	if (!has_tz) {
		result->data = jal_strdup(dtString);
		result->size = dtLen + 1; // keep the null terminator
		result->flags = DB_DBT_APPMALLOC;
		return 0;
	}
	return DB_DONOTINDEX;
}

int jaldb_extract_nonce_timestamp_key(DB *secondary, const DBT *key, const DBT *data, DBT *result)
{
	char *timestamp = strchr((char*)key->data,'_');
	if (!timestamp) {
		return DB_DONOTINDEX;
	}
	timestamp += 1;
	char *timestamp_end = strchr(timestamp,'_');
	if (!timestamp_end) {
		return DB_DONOTINDEX;
	}
	size_t string_len = timestamp_end - timestamp;
	result->data = jal_malloc(string_len + 1);
	memset(result->data,0,string_len+1);
	result->size = string_len + 1;
	result->flags = DB_DBT_APPMALLOC;
	strncpy((char*)result->data, timestamp, string_len);

	return 0;
}
