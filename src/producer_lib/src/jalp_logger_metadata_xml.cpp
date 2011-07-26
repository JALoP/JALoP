/**
 * @file jalp_logger_metadata_xml.cpp This file defines functions to handle
 * converting logger metadata to XML.
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

#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_logger_metadata.h>
#include "jalp_context_internal.h"
#include "jalp_log_severity_xml.hpp"
#include "jalp_structured_data_xml.hpp"
#include "jalp_stack_frame_xml.hpp"
#include "jalp_logger_metadata_xml.hpp"
#include "jal_xml_utils.hpp"
#include "jal_asprintf_internal.h"
#include "jal_alloc.h"

static const XMLCh JALP_XML_LOGGER[] = {
	chLatin_L, chLatin_o, chLatin_g, chLatin_g,
	chLatin_e, chLatin_r, chNull };
static const XMLCh JALP_XML_LOGGER_NAME[] = {
	chLatin_L, chLatin_o, chLatin_g, chLatin_g,
	chLatin_e, chLatin_r, chLatin_N, chLatin_a,
	chLatin_m, chLatin_e, chNull };
static const XMLCh JALP_XML_TIMESTAMP[] = {
	chLatin_T, chLatin_i, chLatin_m, chLatin_e,
	chLatin_s, chLatin_t, chLatin_a, chLatin_m,
	chLatin_p, chNull };
static const XMLCh JALP_XML_HOSTNAME[] = {
	chLatin_H, chLatin_o, chLatin_s, chLatin_t,
	chLatin_n, chLatin_a, chLatin_m, chLatin_e,
	chNull };
static const XMLCh JALP_XML_APPLICATION_NAME[] = {
	chLatin_A, chLatin_p, chLatin_p, chLatin_l,
	chLatin_i, chLatin_c, chLatin_a, chLatin_t,
	chLatin_i, chLatin_o, chLatin_n, chLatin_N,
	chLatin_a, chLatin_m, chLatin_e, chNull };
static const XMLCh JALP_XML_PROCESS_ID[] = {
	chLatin_P, chLatin_r, chLatin_o, chLatin_c,
	chLatin_e, chLatin_s, chLatin_s, chLatin_I,
	chLatin_D, chNull };
static const XMLCh JALP_XML_THREAD_ID[] = {
	chLatin_T, chLatin_h, chLatin_r, chLatin_e,
	chLatin_a, chLatin_d, chLatin_I, chLatin_D,
	chNull };
static const XMLCh JALP_XML_MESSAGE[] = {
	chLatin_M, chLatin_e, chLatin_s, chLatin_s,
	chLatin_a, chLatin_g, chLatin_e, chNull };
static const XMLCh JALP_XML_LOCATION[] = {
	chLatin_L, chLatin_o, chLatin_c, chLatin_a,
	chLatin_t, chLatin_i, chLatin_o, chLatin_n,
	chNull };
static const XMLCh JALP_XML_NESTED_DIAGNOSTIC_CTX[] = {
	chLatin_N, chLatin_e, chLatin_s, chLatin_t,
	chLatin_e, chLatin_d, chLatin_D, chLatin_i,
	chLatin_a, chLatin_g, chLatin_n, chLatin_o,
	chLatin_s, chLatin_t, chLatin_i, chLatin_c,
	chLatin_C, chLatin_o, chLatin_n, chLatin_t,
	chLatin_e, chLatin_x, chLatin_t, chNull };
static const XMLCh JALP_XML_MAPPED_DIAGNOSTIC_CTX[] = {
	chLatin_M, chLatin_a, chLatin_p, chLatin_p,
	chLatin_e, chLatin_d, chLatin_D, chLatin_i,
	chLatin_a, chLatin_g, chLatin_n, chLatin_o,
	chLatin_s, chLatin_t, chLatin_i, chLatin_c,
	chLatin_C, chLatin_o, chLatin_n, chLatin_t,
	chLatin_e, chLatin_x, chLatin_t, chNull };

XERCES_CPP_NAMESPACE_USE

enum jal_status jalp_logger_metadata_to_elem(const struct jalp_logger_metadata *logmeta,
					const struct jalp_context_t *ctx,
					DOMDocument *doc,
					DOMElement **new_elem)
{
	if (!logmeta || !ctx || !doc || !new_elem || *new_elem) {
		return JAL_E_XML_CONVERSION;
	}

	enum jal_status ret;
	char *proc_id_str;
	pid_t pid;
	DOMElement *xml_pid;
	XMLCh *xml_process_id;
	XMLCh *namespace_uri = XMLString::transcode(JALP_APP_META_TYPES_NAMESPACE_URI);
	DOMElement *logger_metadata_element = doc->createElementNS(namespace_uri, JALP_XML_LOGGER);

	if (logmeta->logger_name) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_LOGGER_NAME);
		logger_metadata_element->appendChild(tmp);
		XMLCh *xml_logger_name = XMLString::transcode(logmeta->logger_name);
		tmp->setTextContent(xml_logger_name);
		XMLString::release(&xml_logger_name);
	}
	if (logmeta->severity) {
		DOMElement *tmp = NULL;
		ret = jalp_log_severity_to_elem(logmeta->severity, doc, &tmp);
		if (ret != JAL_OK) {
			goto cleanup;
		}
		logger_metadata_element->appendChild(tmp);
	}
	if (logmeta->timestamp) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_TIMESTAMP);
		logger_metadata_element->appendChild(tmp);
		XMLCh *xml_timestamp = XMLString::transcode(logmeta->timestamp);
		try {
			XMLDateTime dt(xml_timestamp);
			dt.parseDateTime();
		} catch (...) {
			XMLString::release(&xml_timestamp);
			ret = JAL_E_INVAL_TIMESTAMP;
			goto cleanup;
		}
		tmp->setTextContent(xml_timestamp);
		XMLString::release(&xml_timestamp);
	} else {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_TIMESTAMP);
		logger_metadata_element->appendChild(tmp);
		char *ftime = jal_get_timestamp();
		XMLCh *xml_timestamp = XMLString::transcode(ftime);
		tmp->setTextContent(xml_timestamp);
		free(ftime);
		XMLString::release(&xml_timestamp);
	}
	if (ctx->hostname) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_HOSTNAME);
		logger_metadata_element->appendChild(tmp);
		XMLCh *xml_hostname = XMLString::transcode(ctx->hostname);
		tmp->setTextContent(xml_hostname);
		XMLString::release(&xml_hostname);
	}
	if (ctx->app_name) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_APPLICATION_NAME);
		logger_metadata_element->appendChild(tmp);
		XMLCh *xml_app_name = XMLString::transcode(ctx->app_name);
		tmp->setTextContent(xml_app_name);
		XMLString::release(&xml_app_name);
	}
	pid = getpid();
	xml_pid = doc->createElementNS(namespace_uri, JALP_XML_PROCESS_ID);
	logger_metadata_element->appendChild(xml_pid);
	jal_asprintf(&proc_id_str, "%d", (intmax_t)pid);
	xml_process_id = XMLString::transcode(proc_id_str);
	xml_pid->setTextContent(xml_process_id);
	free(proc_id_str);
	XMLString::release(&xml_process_id);
	if (logmeta->threadId) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_THREAD_ID);
		logger_metadata_element->appendChild(tmp);
		XMLCh *xml_thread_id = XMLString::transcode(logmeta->threadId);
		tmp->setTextContent(xml_thread_id);
		XMLString::release(&xml_thread_id);
	}
	if (logmeta->message) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_MESSAGE);
		logger_metadata_element->appendChild(tmp);
		XMLCh *xml_message = XMLString::transcode(logmeta->message);
		tmp->setTextContent(xml_message);
		XMLString::release(&xml_message);
	}
	if (logmeta->stack) {
		DOMElement *loc_element = doc->createElementNS(namespace_uri, JALP_XML_LOCATION);
		struct jalp_stack_frame *curr = logmeta->stack;
		while (curr) {
			DOMElement *tmp = NULL;
			ret = jalp_stack_frame_to_elem(curr, doc, &tmp);
			if (ret != JAL_OK) {
				loc_element->release();
				goto cleanup;
			}
			loc_element->appendChild(tmp);
			curr = curr->next;
		}
		logger_metadata_element->appendChild(loc_element);
	}
	if (logmeta->nested_diagnostic_context) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_NESTED_DIAGNOSTIC_CTX);
		logger_metadata_element->appendChild(tmp);
		XMLCh *xml_nested_ctx = XMLString::transcode(logmeta->nested_diagnostic_context);
		tmp->setTextContent(xml_nested_ctx);
		XMLString::release(&xml_nested_ctx);
	}
	if (logmeta->mapped_diagnostic_context) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_MAPPED_DIAGNOSTIC_CTX);
		logger_metadata_element->appendChild(tmp);
		XMLCh *xml_mapped_ctx = XMLString::transcode(logmeta->mapped_diagnostic_context);
		tmp->setTextContent(xml_mapped_ctx);
		XMLString::release(&xml_mapped_ctx);
	}
	XMLString::release(&namespace_uri);
	if (logmeta->sd) {
		DOMElement *tmp = NULL;
		struct jalp_structured_data *curr = logmeta->sd;
		while (curr) {
			ret = jalp_structured_data_to_elem(curr, doc, &tmp);
			if (ret != JAL_OK) {
				goto cleanup;
			}
			logger_metadata_element->appendChild(tmp);
			tmp = NULL;
			curr = curr->next;
		}
	}
	*new_elem = logger_metadata_element;

	return JAL_OK;

cleanup:
	XMLString::release(&namespace_uri);
	if (logger_metadata_element) {
		logger_metadata_element->release();
	}
	return ret;
}
