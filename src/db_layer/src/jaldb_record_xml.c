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
#include <libxml/parser.h>
#include <string.h>
#include <errno.h>

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

enum parse_state { START,IN_JAL_RECORD,END,UNKNOWN };

struct sax_parse_user_data {
	struct jaldb_record* sys_meta;
	enum jal_status ret;
	xmlChar *tag_name;
	enum parse_state state;
	char *chars;
	int chars_len;
};

void jaldb_start_document(void *user_data)
{
	struct sax_parse_user_data *sp_user_data = (struct sax_parse_user_data *)user_data;
	sp_user_data->ret = JALDB_OK;
	sp_user_data->state = START;
}

void jaldb_end_document(void *user_data)
{
	struct sax_parse_user_data *sp_user_data = (struct sax_parse_user_data *)user_data;
	free(sp_user_data->tag_name);
	if(sp_user_data->state != END		||
	   !sp_user_data->sys_meta		||
	   !sp_user_data->sys_meta->hostname	||
	   !sp_user_data->sys_meta->timestamp	||
	   !sp_user_data->sys_meta->username	||
	   !sp_user_data->sys_meta->type	||
	   !sp_user_data->sys_meta->host_uuid	||
	   !sp_user_data->sys_meta->uuid) {
		sp_user_data->ret = JALDB_E_INVAL;
	}
	if (sp_user_data->ret != JALDB_OK) {
		jaldb_destroy_record(&(sp_user_data->sys_meta));
	}
}

void jaldb_start_element(void *user_data,
			  const xmlChar *name,
			  const xmlChar **attrs)
{
	struct sax_parse_user_data *sp_user_data = (struct sax_parse_user_data *)user_data;
	if (sp_user_data->state == START) {	
		if (0 == strcmp((char *)name, "JALRecord")) {
			free(sp_user_data->tag_name);
			sp_user_data->tag_name = jal_calloc(strlen((const char *)name)+1,sizeof(xmlChar));
			strncpy((char*)sp_user_data->tag_name,(const char *)name,strlen((const char *)name));
			sp_user_data->state = IN_JAL_RECORD;
		} else {
			sp_user_data->ret = JALDB_E_INVAL;
			sp_user_data->state = UNKNOWN;
		}	
	} else if (sp_user_data->state == IN_JAL_RECORD) {
		free(sp_user_data->tag_name);
		sp_user_data->tag_name = jal_calloc(strlen((const char *)name)+1,sizeof(xmlChar));
		strncpy((char *)sp_user_data->tag_name,(const char *)name,strlen((const char *)name));
		
		if (0 == strcmp((char *)name,"User") && attrs) {
			// Even indices are names, odd are values.  The username field has name "name"
			int i=0;
			while (attrs[i]) {
				if (0 == strcmp((char *)attrs[i],"name")) {			
					sp_user_data->sys_meta->username = jal_calloc(strlen((const char *)attrs[i+1])+1,sizeof(char));
					strncpy(sp_user_data->sys_meta->username,(const char *)attrs[i+1],strlen((const char *)attrs[i+1]));
					break;
				}
				i+=2;
			}
		}
	} else {
		sp_user_data->ret = JALDB_E_INVAL;
	}
}

static void handle_type(struct sax_parse_user_data *sp_user_data,
		const char *name,
		int len)
{
	if (0 == strncmp(name, "journal",len)) {
		sp_user_data->sys_meta->type = JALDB_RTYPE_JOURNAL;
	} else if (0 == strncmp(name, "audit",len)) {
		sp_user_data->sys_meta->type = JALDB_RTYPE_AUDIT;
	} else if (0 == strncmp(name, "log",len)) {
		sp_user_data->sys_meta->type = JALDB_RTYPE_LOG;
	} else {
		sp_user_data->sys_meta->type = JALDB_RTYPE_UNKNOWN;
		sp_user_data->ret = JALDB_E_INVAL;
	}
}

void jaldb_characters(void *user_data,
		const xmlChar *name,
		int len)
{	
	struct sax_parse_user_data *sp_user_data = (struct sax_parse_user_data *)user_data;
	if (sp_user_data->chars == NULL) {
		sp_user_data->chars = jal_calloc(len+1,sizeof(char));
		strncpy(sp_user_data->chars,(char *)name,len);
		sp_user_data->chars_len = len;
	} else {
		sp_user_data->chars = jal_realloc(sp_user_data->chars,strlen(sp_user_data->chars)+len+1);
		strncat(sp_user_data->chars,(char *)name,len);
		sp_user_data->chars_len += len;
	}
}

void jaldb_end_element(void *user_data,
		const xmlChar *name)
{
	struct sax_parse_user_data *sp_user_data = (struct sax_parse_user_data *)user_data;
	if (0 == strcmp((char *)name, "JALRecord")) {
		sp_user_data->state = END;
	} else if (0 == strcmp((char *)name,"JALDataType")) {
		handle_type(sp_user_data,sp_user_data->chars,sp_user_data->chars_len);
	} else if (0 == strcmp((char *)name,"RecordID")) {
		char * record_uuid = jal_calloc(sp_user_data->chars_len+1,sizeof(char));
		strncpy(record_uuid,(char *)sp_user_data->chars,sp_user_data->chars_len);
		if (-1 == uuid_parse(record_uuid,sp_user_data->sys_meta->uuid)) {
			sp_user_data->ret = JALDB_E_INVAL;
		}
		free(record_uuid);
	} else if (0 == strcmp((char *)name,"Hostname")) {
		sp_user_data->sys_meta->hostname = (char*)jal_calloc(sp_user_data->chars_len+1,sizeof(char));
		strncpy((char *)sp_user_data->sys_meta->hostname,
			(const char *)sp_user_data->chars,
			sp_user_data->chars_len);	
	} else if (0 == strcmp((char *)name,"HostUUID")) {
		char *host_uuid = jal_calloc(sp_user_data->chars_len+1,sizeof(char));
		strncpy(host_uuid,(char *)sp_user_data->chars,sp_user_data->chars_len);
		if (-1 == uuid_parse(host_uuid,sp_user_data->sys_meta->host_uuid)) {
			sp_user_data->ret = JALDB_E_INVAL;
		}
		free(host_uuid);
	} else if (0 == strcmp((char *)name, "Timestamp")) {
		sp_user_data->sys_meta->timestamp = (char*)jal_calloc(sp_user_data->chars_len+1,sizeof(char));
		strncpy((char *)sp_user_data->sys_meta->timestamp,(const char *)sp_user_data->chars,sp_user_data->chars_len);
	} else if (0 == strcmp((char *)name,"ProcessID")) {
		errno=0;
		uint64_t pid = (uint64_t)strtoul((const char *)sp_user_data->chars,NULL,0);
		if (errno != 0) {
			sp_user_data->ret = JALDB_E_INVAL;
		}
		sp_user_data->sys_meta->pid = pid;
	} else if (0 == strcmp((char *)sp_user_data->tag_name,"User")) {
		errno=0;
		uint64_t uid = (uint64_t)strtoul((const char *)sp_user_data->chars,NULL,0);
		if (errno != 0) {
			sp_user_data->ret = JALDB_E_INVAL;
		}
		sp_user_data->sys_meta->uid = uid;
	} else if (0 == strcmp((char *)sp_user_data->tag_name,"SecurityLabel")) {
		sp_user_data->sys_meta->sec_lbl = (char*)jal_calloc(sp_user_data->chars_len+1,sizeof(char));
		strncpy((char *)sp_user_data->sys_meta->sec_lbl,(const char *)sp_user_data->chars,sp_user_data->chars_len);
	}
	free(sp_user_data->chars);
	sp_user_data->chars = NULL;
}

void jaldb_cdata_handler(void *user_data,const xmlChar *ch, int len)
{
	// We don't need to do anything with CDATA, but it will be passed to the characters
 	// callback if we don't assign a callback for it, which isn't what we want
	return;
}

void jaldb_xml_error(void *user_data,const char * msg, ...)
{	
	struct sax_parse_user_data *sp_user_data = (struct sax_parse_user_data *)jal_calloc(1,sizeof(struct sax_parse_user_data));
	sp_user_data->ret = JALDB_E_INVAL;
}

enum jal_status jaldb_xml_to_sys_metadata(uint8_t *xml, size_t xml_len, struct jaldb_record **sys_meta)
{
	struct sax_parse_user_data *sp_user_data = (struct sax_parse_user_data *)jal_calloc(1,sizeof(struct sax_parse_user_data));
	*sys_meta = jaldb_create_record();
	sp_user_data->sys_meta = *sys_meta;

	static xmlSAXHandler sys_meta_handler;

	sys_meta_handler.startDocument = &jaldb_start_document;
	sys_meta_handler.endDocument = &jaldb_end_document;
	sys_meta_handler.startElement = &jaldb_start_element;
	sys_meta_handler.characters = &jaldb_characters;
	sys_meta_handler.endElement = &jaldb_end_element;
	sys_meta_handler.warning = &jaldb_xml_error;
	sys_meta_handler.error = &jaldb_xml_error;
	sys_meta_handler.fatalError = &jaldb_xml_error;
	sys_meta_handler.cdataBlock = &jaldb_cdata_handler;

	xmlSAXUserParseMemory(&sys_meta_handler,sp_user_data,(char*)xml,(int)xml_len);

	return sp_user_data->ret;
}
