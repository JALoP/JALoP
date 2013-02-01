/**
 * @file jaldb_reocrd_xml.c This file defines functions to deal with
 * converting jaldb_record to a system meta-data document.
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

#include <stdio.h>
#include <uuid/uuid.h>
#include <inttypes.h>

#include "jal_alloc.h"
#include "jaldb_record.h"
#include "jaldb_record_xml.h"

#define JALDB_XSI_NS         "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'"

#define JALDB_XML_PREAMBLE   "<?xml version='1.0' encoding='UTF-8' standalone='no'?>"
#define JALDB_RECORD_START   "<JALRecord xmlns='http://www.dod.mil/jalop-1.0/systemMetadata' JID='UUID-%s' xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
#define JALDB_DATA_TYPE_TAG  "<JALDataType>%s</JALDataType>"
#define JALDB_RECORD_ID_TAG  "<RecordID>%s</RecordID>"
#define JALDB_HOSTNAME_TAG   "<Hostname>%s</Hostname>"
#define JALDB_HOST_UUID_TAG  "<HostUUID>%s</HostUUID>"
#define JALDB_TIMESTAMP_TAG  "<Timestamp>%s</Timestamp>"
#define JALDB_PROCESS_ID     "<ProcessID>%"PRIu64"</ProcessID>"
#define JALDB_USER_W_UID_TAG "<User name='%s'>%"PRIu64"</User>"
#define JALDB_USER_TAG       "<User " JALDB_XSI_NS " xsi:nil='true' name='%s'/>"
#define JALDB_SEC_LABEL_TAG  "<SecurityLabel>%s</SecurityLabel>"
#define JALDB_MANIFEST_START "<ds:Manifest xmlns='http://www.w3.org/2000/09/xmldsig#'>"
#define JALDB_REF_START      "<ds:Reference URI='jalop:payload'>"
#define JALDB_DGST_METH_TAG  "<ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/>"
#define JALDB_DGST_VAL_TAG   "<ds:DigestValue>%s</DigestValue>"
#define JALDB_REF_END        "</ds:Reference>"
#define JALDB_MANIFEST_END   "</ds:Manifest>"
#define JALDB_RECORD_END     "</JALRecord>"

#define JALDB_JOURNAL "journal"
#define JALDB_AUDIT "audit"
#define JALDB_LOG "log"

#define UUID_STR_LEN 37

enum jaldb_status jaldb_record_to_system_metadata_doc(struct jaldb_record *rec, char **doc, size_t *dsize)
{
	enum jaldb_status ret;
	char uuid_str[UUID_STR_LEN];
	char host_uuid_str[UUID_STR_LEN];
	size_t bsize = 0;
	int left = 1; // start at 1 for the NULL terminator;
	int wrote;
	size_t offset = 0;
	char *res = NULL;
	char *type_str;

	if (!rec || !doc || *doc) {
		return JALDB_E_INVAL;
	}

	if (JALDB_OK != jaldb_record_sanity_check(rec)) {
		return JALDB_E_INVAL;
	}

	switch(rec->type) {
	case JALDB_RTYPE_JOURNAL:
		type_str = JALDB_JOURNAL;
		break;
	case JALDB_RTYPE_AUDIT:
		type_str = JALDB_AUDIT;
		break;
	case JALDB_RTYPE_LOG:
		type_str = JALDB_LOG;
		break;
	default:
		return JALDB_E_INVAL;
	}

	uuid_unparse(rec->uuid, uuid_str);
	uuid_unparse(rec->host_uuid, host_uuid_str);

	left += snprintf(NULL, 0, JALDB_XML_PREAMBLE);
	left += snprintf(NULL, 0, JALDB_RECORD_START, uuid_str);
	left += snprintf(NULL, 0, JALDB_DATA_TYPE_TAG, type_str);
	left += snprintf(NULL, 0, JALDB_RECORD_ID_TAG, uuid_str);
	left += snprintf(NULL, 0, JALDB_HOSTNAME_TAG, rec->hostname);
	left += snprintf(NULL, 0, JALDB_HOST_UUID_TAG, host_uuid_str);
	left += snprintf(NULL, 0, JALDB_TIMESTAMP_TAG, rec->timestamp);
	left += snprintf(NULL, 0, JALDB_PROCESS_ID, rec->pid);
	if (rec->have_uid) {
		left += snprintf(NULL, 0, JALDB_USER_W_UID_TAG, rec->username, rec->uid);
	} else {
		left += snprintf(NULL, 0, JALDB_USER_TAG, rec->username);
	}
	if (rec->sec_lbl) {
		left += snprintf(NULL, 0, JALDB_SEC_LABEL_TAG, rec->sec_lbl);
	}
	left += snprintf(NULL, 0, JALDB_RECORD_END);

	bsize = left;
	res = jal_malloc(bsize);

	wrote = snprintf(res + offset, left, JALDB_XML_PREAMBLE);
	if ((-1 == wrote) || (wrote > left)) {
		// bad calculation somewhere?
		goto err_out;
	}
	offset += wrote;
	left -= wrote;


	wrote = snprintf(res + offset, left, JALDB_RECORD_START, uuid_str);
	if ((-1 == wrote) || (wrote > left)) {
		// bad calculation somewhere?
		goto err_out;
	}
	offset += wrote;
	left -= wrote;


	wrote = snprintf(res + offset, left, JALDB_DATA_TYPE_TAG, type_str);
	if ((-1 == wrote) || (wrote > left) || (offset + wrote > bsize)) {
		// bad calculation somewhere?
		goto err_out;
	}
	left -= wrote;
	offset += wrote;

	wrote = snprintf(res + offset, left, JALDB_RECORD_ID_TAG, uuid_str);
	if ((-1 == wrote) || (wrote > left) || (offset + wrote > bsize)) {
		// bad calculation somewhere?
		goto err_out;
	}
	offset += wrote;
	left -= wrote;

	wrote = snprintf(res + offset, left, JALDB_HOSTNAME_TAG, rec->hostname);
	if ((-1 == wrote) || (wrote > left) || (offset + wrote > bsize)) {
		// bad calculation somewhere?
		goto err_out;
	}
	offset += wrote;
	left -= wrote;

	wrote = snprintf(res + offset, left, JALDB_HOST_UUID_TAG, host_uuid_str);
	if ((-1 == wrote) || (wrote > left) || (offset + wrote > bsize)) {
		// bad calculation somewhere?
		goto err_out;
	}
	offset += wrote;
	left -= wrote;

	wrote = snprintf(res + offset, left, JALDB_TIMESTAMP_TAG, rec->timestamp);
	if ((-1 == wrote) || (wrote > left) || (offset + wrote > bsize)) {
		// bad calculation somewhere?
		goto err_out;
	}
	offset += wrote;
	left -= wrote;

	wrote = snprintf(res + offset, left, JALDB_PROCESS_ID, rec->pid);
	if ((-1 == wrote) || (wrote > left) || (offset + wrote > bsize)) {
		// bad calculation somewhere?
		goto err_out;
	}
	offset += wrote;
	left -= wrote;

	if (rec->have_uid) {
		wrote = snprintf(res + offset, left, JALDB_USER_W_UID_TAG, rec->username, rec->uid);
		if ((-1 == wrote) || (wrote > left) || (offset + wrote > bsize)) {
			// bad calculation somewhere?
			goto err_out;
		}
		offset += wrote;
		left -= wrote;
	} else {
		wrote = snprintf(res + offset, left, JALDB_USER_TAG, rec->username);
		if ((-1 == wrote) || (wrote > left) || (offset + wrote > bsize)) {
			// bad calculation somewhere?
			goto err_out;
		}
		offset += wrote;
		left -= wrote;
	}
	if (rec->sec_lbl) {
		wrote = snprintf(res + offset, left, JALDB_SEC_LABEL_TAG, rec->sec_lbl);
		if ((-1 == wrote) || (wrote > left) || (offset + wrote > bsize)) {
			// bad calculation somewhere?
			goto err_out;
		}
		offset += wrote;
		left -= wrote;
	}
	wrote = snprintf(res + offset, left, JALDB_RECORD_END);
	if ((-1 == wrote) || (wrote > left) || (offset + wrote > bsize)) {
		// bad calculation somewhere?
		goto err_out;
	}
	offset += wrote;
	left -= wrote;
	if (left != 1) {
		goto err_out;
	}
	*doc = res;
	*dsize = bsize - 1; // Report the string length, not buffer length.
	ret = JALDB_OK;
	goto out;
err_out:
	ret = JALDB_E_UNKNOWN;
	free(res);
out:
	return ret;
}

