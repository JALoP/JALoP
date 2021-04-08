/**
 * @file jalp_syslog_metadata_xml.c This file defines functions to handle
 * converting syslog metadata to XML.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <libxml/tree.h>

#include <sys/types.h>
#include <inttypes.h> /* PRIdMax*/
#include <unistd.h>
#include <string.h>

#include <jalop/jalp_context.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_syslog_metadata.h>
#include "jal_asprintf_internal.h"
#include "jal_alloc.h"
#include "jalp_context_internal.h"
#include "jalp_structured_data_xml.h"
#include "jalp_syslog_metadata_xml.h"
#include "jal_xml_utils.h"

#define JALP_XML_SYSLOG "Syslog"
#define JALP_XML_ENTRY "Entry"
#define JALP_XML_FACILITY "Facility"
#define JALP_XML_APPLICATION_NAME "ApplicationName"
#define JALP_XML_SEVERITY "Severity"
#define JALP_XML_TIMESTAMP "Timestamp"
#define JALP_XML_HOSTNAME "Hostname"
#define JALP_XML_PROCESS_ID "ProcessID"
#define JALP_XML_MESSAGE_ID "MessageID"

enum jal_status jalp_syslog_metadata_to_elem(
		const struct jalp_syslog_metadata *syslog,
		const struct jalp_context_t *ctx,
		xmlNodePtr doc,
		xmlNodePtr *new_elem)
{
	if (!syslog || !ctx || !doc || !new_elem || *new_elem) {
		return JAL_E_XML_CONVERSION;
	}
	enum jal_status ret;
	xmlNodePtr syslog_element = xmlNewChild(doc, NULL,
						(xmlChar *)JALP_XML_SYSLOG,
						NULL);
	char *proc_id_str = NULL;
	pid_t pid = getpid();
	jal_asprintf(&proc_id_str, "%" PRIdMAX, (intmax_t)pid);
	xmlChar *xml_procid = (xmlChar *)proc_id_str;
	xmlSetProp(syslog_element, (xmlChar *)JALP_XML_PROCESS_ID, xml_procid);
	free(proc_id_str);
	if (ctx->hostname) {
		xmlChar *xml_hostname = (xmlChar *)ctx->hostname;
		xmlSetProp(syslog_element, (xmlChar *)JALP_XML_HOSTNAME, xml_hostname);
	}
	if (ctx->app_name) {
		xmlChar *xml_appname = (xmlChar *)ctx->app_name;
		xmlSetProp(syslog_element, (xmlChar *)JALP_XML_APPLICATION_NAME, xml_appname);
	}
	if ((syslog->facility >= 0) && (syslog->facility <= 23)) {
		char *facility = NULL;
		jal_asprintf(&facility, "%d", syslog->facility);
		xmlChar *xml_facility = (xmlChar *)facility;
		xmlSetProp(syslog_element, (xmlChar *)JALP_XML_FACILITY, xml_facility);
		free(facility);
	} else if (syslog->facility < -1 || syslog->facility > 23) {
		ret = JAL_E_INVAL_SYSLOG_METADATA;
		goto cleanup;
	}
	if ((syslog->severity >= 0) && (syslog->severity <= 7)) {
		char *severity = NULL;
		jal_asprintf(&severity, "%d", syslog->severity);
		xmlChar *xml_severity = (xmlChar *)severity;
		xmlSetProp(syslog_element, (xmlChar *)JALP_XML_SEVERITY, xml_severity);
		free(severity);
	} else if ((syslog->severity < -1) || (syslog->severity > 7)) {
		ret = JAL_E_INVAL_SYSLOG_METADATA;
		goto cleanup;
	}
	if (syslog->timestamp) {
		xmlChar *xml_timestamp = (xmlChar *)syslog->timestamp;
		xmlSetProp(syslog_element, (xmlChar *)JALP_XML_TIMESTAMP, xml_timestamp);
	} else {
		char *ftime = jal_get_timestamp();
		xmlChar *xml_timestamp = (xmlChar *)ftime;
		xmlSetProp(syslog_element, (xmlChar *)JALP_XML_TIMESTAMP, xml_timestamp);
		free(ftime);
	}
	if (syslog->message_id) {
		xmlChar *xml_message_id = (xmlChar *)syslog->message_id;
		xmlSetProp(syslog_element, (xmlChar *)JALP_XML_MESSAGE_ID, xml_message_id);
	}
	if (syslog->entry) {
		xmlNodePtr tmp = xmlNewChild(syslog_element, NULL,(xmlChar *)JALP_XML_ENTRY, NULL);
		xmlAddChild(tmp,xmlNewCDataBlock(NULL, (xmlChar*)syslog->entry, strlen(syslog->entry)));
	}
	if (syslog->sd_head) {
		struct jalp_structured_data *curr = syslog->sd_head;
		while (curr) {
			xmlNodePtr tmp = NULL;
			ret = jalp_structured_data_to_elem(curr, syslog_element, &tmp);
			if (ret != JAL_OK) {
				goto cleanup;
			}
			curr = curr->next;
		}
	}
	*new_elem = syslog_element;
	return JAL_OK;

cleanup:
	if (syslog_element) {
		xmlFreeNode(syslog_element);
	}
	return ret;
}

