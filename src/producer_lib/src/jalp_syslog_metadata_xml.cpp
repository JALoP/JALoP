/**
 * @file jalp_syslog_metadata_xml.cpp This file defines functions to handle
 * converting syslog metadata to XML.
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

#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLDateTime.hpp>

#include <sys/types.h>
#include <unistd.h>

#include <jalop/jalp_context.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_syslog_metadata.h>
#include "jal_asprintf_internal.h"
#include "jal_alloc.h"
#include "jalp_context_internal.h"
#include "jalp_structured_data_xml.hpp"
#include "jalp_syslog_metadata_xml.hpp"
#include "jal_xml_utils.hpp"

XERCES_CPP_NAMESPACE_USE
static const XMLCh JALP_XML_SYSLOG[] = {
	chLatin_S, chLatin_y, chLatin_s, chLatin_l, chLatin_o, chLatin_g, chNull };
static const XMLCh JALP_XML_ENTRY[] = {
	chLatin_E, chLatin_n, chLatin_t, chLatin_r, chLatin_y, chNull };
static const XMLCh JALP_XML_FACILITY[] = {
	chLatin_F, chLatin_a, chLatin_c, chLatin_i, chLatin_l, chLatin_i, chLatin_t, chLatin_y, chNull };
static const XMLCh JALP_XML_APPLICATION_NAME[] = {
	chLatin_A, chLatin_p, chLatin_p, chLatin_l, chLatin_i, chLatin_c, chLatin_a, chLatin_t, chLatin_i, chLatin_o,
	chLatin_n, chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };
static const XMLCh JALP_XML_SEVERITY[] = {
	chLatin_S, chLatin_e, chLatin_v, chLatin_e, chLatin_r, chLatin_i, chLatin_t, chLatin_y, chNull };
static const XMLCh JALP_XML_TIMESTAMP[] = {
	chLatin_T, chLatin_i, chLatin_m, chLatin_e, chLatin_s, chLatin_t, chLatin_a, chLatin_m, chLatin_p, chNull };
static const XMLCh JALP_XML_HOSTNAME[] = {
	chLatin_H, chLatin_o, chLatin_s, chLatin_t, chLatin_n, chLatin_a, chLatin_m, chLatin_e, chNull };
static const XMLCh JALP_XML_PROCESS_ID[] = {
	chLatin_P, chLatin_r, chLatin_o, chLatin_c, chLatin_e, chLatin_s, chLatin_s, chLatin_I, chLatin_D, chNull };
static const XMLCh JALP_XML_MESSAGE_ID[] = {
	chLatin_M, chLatin_e, chLatin_s, chLatin_s, chLatin_a, chLatin_g, chLatin_e, chLatin_I, chLatin_D, chNull };

enum jal_status jalp_syslog_metadata_to_elem(const struct jalp_syslog_metadata *syslog,
					const struct jalp_context_t *ctx,
					DOMDocument *doc,
					DOMElement **new_elem)
{
	if (!syslog || !ctx || !doc || !new_elem || *new_elem) {
		return JAL_E_XML_CONVERSION;
	}
	enum jal_status ret;
	XMLCh *namespace_uri = XMLString::transcode(JAL_APP_META_TYPES_NAMESPACE_URI);
	DOMElement *syslog_element = doc->createElementNS(namespace_uri, JALP_XML_SYSLOG);
	char *proc_id_str = NULL;
	pid_t pid = getpid();
	jal_asprintf(&proc_id_str, "%" PRIdMAX, (intmax_t)pid);
	XMLCh *xml_procid = XMLString::transcode(proc_id_str);
	syslog_element->setAttribute(JALP_XML_PROCESS_ID, xml_procid);
	free(proc_id_str);
	XMLString::release(&xml_procid);
	if (ctx->hostname) {
		XMLCh *xml_hostname = XMLString::transcode(ctx->hostname);
		syslog_element->setAttribute(JALP_XML_HOSTNAME, xml_hostname);
		XMLString::release(&xml_hostname);
	}
	if (ctx->app_name) {
		XMLCh *xml_appname = XMLString::transcode(ctx->app_name);
		syslog_element->setAttribute(JALP_XML_APPLICATION_NAME, xml_appname);
		XMLString::release(&xml_appname);
	}
	if (syslog->facility >= 0 && syslog->facility <= 23) {
		char *facility = NULL;
		jal_asprintf(&facility, "%d", syslog->facility);
		XMLCh *xml_facility = XMLString::transcode(facility);
		syslog_element->setAttribute(JALP_XML_FACILITY, xml_facility);
		free(facility);
		XMLString::release(&xml_facility);
	} else if (syslog->facility < -1 || syslog->facility > 23) {
		ret = JAL_E_INVAL_SYSLOG_METADATA;
		goto cleanup;
	}
	if (syslog->severity >= 0 && syslog->severity <= 7) {
		char *severity = NULL;
		jal_asprintf(&severity, "%d", syslog->severity);
		XMLCh *xml_severity = XMLString::transcode(severity);
		syslog_element->setAttribute(JALP_XML_SEVERITY, xml_severity);
		free(severity);
		XMLString::release(&xml_severity);
	} else if (syslog->severity < -1 || syslog->severity > 7) {
		ret = JAL_E_INVAL_SYSLOG_METADATA;
		goto cleanup;
	}
	if (syslog->timestamp) {
		XMLCh *xml_timestamp = XMLString::transcode(syslog->timestamp);
		try {
			XMLDateTime dt(xml_timestamp);
			dt.parseDateTime();
		} catch(...) {
			XMLString::release(&xml_timestamp);
			ret = JAL_E_INVAL_TIMESTAMP;
			goto cleanup;
		}
		syslog_element->setAttribute(JALP_XML_TIMESTAMP, xml_timestamp);
		XMLString::release(&xml_timestamp);
	} else {
		char *ftime = jal_get_timestamp();
		XMLCh *xml_timestamp = XMLString::transcode(ftime);
		syslog_element->setAttribute(JALP_XML_TIMESTAMP, xml_timestamp);
		free(ftime);
		XMLString::release(&xml_timestamp);
	}
	if (syslog->message_id) {
		XMLCh *xml_message_id = XMLString::transcode(syslog->message_id);
		syslog_element->setAttribute(JALP_XML_MESSAGE_ID, xml_message_id);
		XMLString::release(&xml_message_id);
	}
	if (syslog->entry) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_ENTRY);
		syslog_element->appendChild(tmp);
		XMLCh *xml_entry = XMLString::transcode(syslog->entry);
		tmp->setTextContent(xml_entry);
		XMLString::release(&xml_entry);
	}
	XMLString::release(&namespace_uri);
	if (syslog->sd_head) {
		DOMElement *tmp = NULL;
		struct jalp_structured_data *curr = syslog->sd_head;
		while (curr) {
			ret = jalp_structured_data_to_elem(curr, doc, &tmp);
			if (ret != JAL_OK) {
				goto cleanup;
			}
			syslog_element->appendChild(tmp);
			tmp = NULL;
			curr = curr->next;
		}
	}
	*new_elem = syslog_element;
	return JAL_OK;

cleanup:
	XMLString::release(&namespace_uri);
	if (syslog_element) {
		syslog_element->release();
	}
	return ret;
}
