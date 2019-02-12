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
#include <libxml/tree.h>
#include <string.h>
#include <errno.h>
#include <jalop/jal_namespaces.h>

#include "jal_alloc.h"
#include "jaldb_record.h"
#include "jaldb_record_xml.h"
#include "jal_xml_utils.h"

#define JALDB_XSI_NS         "http://www.w3.org/2001/XMLSchema-instance"

#define JALDB_RECORD_TAG     "JALRecord"
#define JALDB_DATA_TYPE_TAG  "JALDataType"
#define JALDB_RECORD_ID_TAG  "RecordID"
#define JALDB_HOSTNAME_TAG   "Hostname"
#define JALDB_HOST_UUID_TAG  "HostUUID"
#define JALDB_TIMESTAMP_TAG  "Timestamp"
#define JALDB_PROCESS_ID_TAG "ProcessID"
#define JALDB_USER_TAG       "User"
#define JALDB_SEC_LABEL_TAG  "SecurityLabel"
#define JALDB_MANIFEST_START "<ds:Manifest xmlns='http://www.w3.org/2000/09/xmldsig#'>"
#define JALDB_REF_START      "<ds:Reference URI='jalop:payload'>"
#define JALDB_DGST_METH_TAG  "<ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/>"
#define JALDB_DGST_VAL_TAG   "<ds:DigestValue>%s</DigestValue>"
#define JALDB_JOURNAL "journal"
#define JALDB_AUDIT "audit"
#define JALDB_LOG "log"

#define UUID_STR_LEN 37
// Theoretical max PID on 64 bit Linux is 4194304
#define PID_STR_MAX_LEN 10
#define UID_STR_MAX_LEN 22

enum jaldb_status jaldb_record_to_system_metadata_doc(struct jaldb_record *rec,
						RSA* signing_key,
						uint8_t *app_meta_dgst, size_t app_meta_dgst_len, const char *app_meta_algorithm_uri,
						uint8_t *payload_dgst, size_t payload_dgst_len, const char *payload_algorithm_uri,
						char **doc, size_t *dsize)
{
	enum jaldb_status ret;
	char uuid_str[UUID_STR_LEN];
	char uuid_str_with_prefix[UUID_STR_LEN + 5];
	char host_uuid_str[UUID_STR_LEN];
	char pid_str[PID_STR_MAX_LEN];
	char uid_str[UID_STR_MAX_LEN];
	xmlChar *res = NULL;
	char *type_str;
	xmlDocPtr xmlDoc = NULL;
	xmlNodePtr root_node = NULL;

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
	snprintf(uuid_str_with_prefix, UUID_STR_LEN + 5, "UUID-%s", uuid_str);
	uuid_unparse(rec->host_uuid, host_uuid_str);
 
	if (PID_STR_MAX_LEN <= snprintf(pid_str, PID_STR_MAX_LEN, "%"PRIu64, rec->pid)) {
		return JALDB_E_INVAL;
	}

	if (rec->have_uid) {
		if (UID_STR_MAX_LEN <= snprintf(uid_str, UID_STR_MAX_LEN, "%"PRIu64, rec->uid)) {
			return JALDB_E_INVAL;
		}
	}

	xmlDoc = xmlNewDoc((xmlChar *) "1.0");
	root_node = xmlNewDocNode(xmlDoc, NULL, (xmlChar *) JALDB_RECORD_TAG, NULL);
	xmlSetProp(root_node, (xmlChar *) "JID", (xmlChar *) uuid_str_with_prefix);

	xmlNsPtr ns = xmlNewNs(root_node, (xmlChar *) JAL_SYS_META_NAMESPACE_URI, NULL);
	xmlSetNs(root_node, ns);

	xmlDocSetRootElement(xmlDoc, root_node);

	xmlAttrPtr attr = xmlHasProp(root_node, (xmlChar *)"JID");
	if (!attr || !attr->children) {
		return JALDB_E_INVAL;
	}
	xmlAddID(NULL, xmlDoc, (xmlChar *)uuid_str_with_prefix, attr);

	xmlNewChild(root_node, NULL, (xmlChar *) JALDB_DATA_TYPE_TAG, (xmlChar *) type_str);
	xmlNewChild(root_node, NULL, (xmlChar *) JALDB_RECORD_ID_TAG, (xmlChar *) uuid_str);
	xmlNewChild(root_node, NULL, (xmlChar *) JALDB_HOSTNAME_TAG, (xmlChar *) rec->hostname);
	xmlNewChild(root_node, NULL, (xmlChar *) JALDB_HOST_UUID_TAG, (xmlChar *) host_uuid_str);
	xmlNewChild(root_node, NULL, (xmlChar *) JALDB_TIMESTAMP_TAG, (xmlChar *) rec->timestamp);
	xmlNewChild(root_node, NULL, (xmlChar *) JALDB_PROCESS_ID_TAG, (xmlChar *) pid_str);
	xmlNodePtr last_node = xmlNewChild(root_node, NULL, (xmlChar *) JALDB_USER_TAG, NULL);
	xmlSetProp(last_node, (xmlChar *) "name", (xmlChar *) rec->username); 

	if (rec->have_uid) {
		xmlNodeSetContent(last_node, (xmlChar *) uid_str);
	} else {
		// TODO
		ns = xmlNewNs(last_node, (xmlChar *) JALDB_XSI_NS, (xmlChar*) "xsi");
		xmlNewNsProp(last_node, ns, (xmlChar *) "nil", (xmlChar *) "true");
	}

	if (rec->sec_lbl) {
		last_node = xmlNewChild(root_node, NULL, (xmlChar *) JALDB_SEC_LABEL_TAG, (xmlChar *) rec->sec_lbl);
	}

	if (payload_dgst || app_meta_dgst) {
		xmlNodePtr manifest = xmlNewDocNode(xmlDoc, NULL, (xmlChar *)"Manifest", NULL);
		xmlChar *namespace_uri = (xmlChar *)JAL_XMLDSIG_URI;
		ns = xmlNewNs(manifest, namespace_uri, NULL);
		xmlSetNs(manifest, ns);
		xmlAddChild(root_node, manifest);

		xmlNodePtr reference_elem = NULL;
		if (payload_dgst) {
			ret = jal_create_reference_elem(JAL_PAYLOAD_URI, payload_algorithm_uri, payload_dgst, payload_dgst_len, xmlDoc, &reference_elem);
			if (ret != JAL_OK) {
				free(res);
				return ret;
			}

			xmlAddChild(manifest, reference_elem);
		}
		if (app_meta_dgst) {
			reference_elem = NULL;
			ret = jal_create_reference_elem(JAL_APP_META_URI, app_meta_algorithm_uri, app_meta_dgst, app_meta_dgst_len, xmlDoc, &reference_elem);
			if (ret != JAL_OK) {
				free(res);
				return ret;
			}

			xmlAddChild(manifest, reference_elem);

		}
		last_node = manifest;
	} else {
		last_node = NULL;
	} 

	if (signing_key) {
		ret = jal_add_signature_block(signing_key, NULL, xmlDoc, last_node, uuid_str_with_prefix);
		if (ret != JAL_OK) {
			free(res);
			return ret;
		}
	}

	ret = jal_xml_output(xmlDoc, &res, dsize);
	if (ret != JAL_OK) {
		free(res);
		return ret;
	}
	*doc = (char *) res;
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
	free(sp_user_data->chars);
	sp_user_data->chars = NULL;
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
		if (sp_user_data->chars != NULL) {
			uint64_t uid = (uint64_t)strtoul((const char *)sp_user_data->chars,NULL,0);
			if (errno != 0) {
				sp_user_data->ret = JALDB_E_INVAL;
			}
			sp_user_data->sys_meta->uid = uid;
		}
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

	enum jal_status ret;
	ret = sp_user_data->ret;
	free(sp_user_data);
	return ret;
}
