/**
 * @file jalp_logger_metadata_xml.c This file defines functions to handle
 * converting logger metadata to XML.
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

#include <libxml/tree.h>

#include <sys/types.h>
#include <unistd.h>

#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_logger_metadata.h>
#include "jalp_context_internal.h"
#include "jalp_log_severity_xml.h"
#include "jalp_structured_data_xml.h"
#include "jalp_stack_frame_xml.h"
#include "jalp_logger_metadata_xml.h"
#include "jal_xml_utils.h"
#include "jal_asprintf_internal.h"
#include "jal_alloc.h"

#define JALP_XML_LOGGER "Logger"
#define JALP_XML_LOGGER_NAME "LoggerName"
#define JALP_XML_TIMESTAMP "Timestamp"
#define JALP_XML_HOSTNAME "Hostname"
#define JALP_XML_APPLICATION_NAME "ApplicationName"
#define JALP_XML_PROCESS_ID "ProcessID"
#define JALP_XML_THREAD_ID "ThreadID"
#define JALP_XML_MESSAGE "Message"
#define JALP_XML_LOCATION "Location"
#define JALP_XML_NESTED_DIAGNOSTIC_CTX "NestedDiagnosticContext"
#define JALP_XML_MAPPED_DIAGNOSTIC_CTX "MappedDiagnosticContext"

enum jal_status jalp_logger_metadata_to_elem(
		const struct jalp_logger_metadata *logmeta,
		const struct jalp_context_t *ctx,
		xmlDocPtr doc,
		xmlNodePtr *new_elem)
{
	if (!logmeta || !ctx || !doc || !new_elem || *new_elem) {
		return JAL_E_XML_CONVERSION;
	}

	enum jal_status ret;
	char *proc_id_str;
	pid_t pid;
	xmlChar *namespace_uri = (xmlChar *)JAL_APP_META_TYPES_NAMESPACE_URI;
	xmlNodePtr logger_metadata_element = xmlNewDocNode(doc, NULL,
								(xmlChar *)JALP_XML_LOGGER,
								NULL);
	xmlNsPtr ns = xmlNewNs(logger_metadata_element, namespace_uri, NULL);
	xmlSetNs(logger_metadata_element, ns);

	if (logmeta->logger_name) {
		xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_LOGGER_NAME,
				(xmlChar *)logmeta->logger_name);
	}
	if (logmeta->severity) {
		xmlNodePtr tmp = NULL;
		ret = jalp_log_severity_to_elem(logmeta->severity, doc, &tmp);
		if (ret != JAL_OK) {
			goto cleanup;
		}
		xmlAddChild(logger_metadata_element, tmp);
	}
	if (logmeta->timestamp) {
		xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_TIMESTAMP,
				(xmlChar *)logmeta->timestamp);
	} else {
		char *ftime = jal_get_timestamp();
		xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_TIMESTAMP,
				(xmlChar *)ftime);
		free(ftime);
	}
	if (ctx->hostname) {
		xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_HOSTNAME,
				(xmlChar *)ctx->hostname);
	}
	if (ctx->app_name) {
		xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_APPLICATION_NAME,
				(xmlChar *)ctx->app_name);
	}
	pid = getpid();
	jal_asprintf(&proc_id_str, "%d", (intmax_t)pid);
	xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_PROCESS_ID,
				(xmlChar *)proc_id_str);
	free(proc_id_str);

	if (logmeta->threadId) {
		xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_THREAD_ID,
				(xmlChar *)logmeta->threadId);
	}
	if (logmeta->message) {
		xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_MESSAGE,
				(xmlChar *)logmeta->message);
	}
	if (logmeta->stack) {
		struct jalp_stack_frame *curr = logmeta->stack;
		xmlNodePtr loc_element = xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_LOCATION,
				NULL);
		while (curr) {
			xmlNodePtr tmp = NULL;
			ret = jalp_stack_frame_to_elem(curr, doc, &tmp);
			if (ret != JAL_OK) {
				xmlFreeNode(loc_element);
				goto cleanup;
			}
			xmlAddChild(loc_element, tmp);
			curr = curr->next;
		}
	}
	if (logmeta->nested_diagnostic_context) {
		xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_NESTED_DIAGNOSTIC_CTX,
				(xmlChar *)logmeta->nested_diagnostic_context);
	}
	if (logmeta->mapped_diagnostic_context) {
		xmlNewChild(logger_metadata_element, NULL,
				(xmlChar *)JALP_XML_MAPPED_DIAGNOSTIC_CTX,
				(xmlChar *)logmeta->mapped_diagnostic_context);
	}
	if (logmeta->sd) {
		struct jalp_structured_data *curr = logmeta->sd;
		while (curr) {
			xmlNodePtr tmp = NULL;
			ret = jalp_structured_data_to_elem(curr, doc, &tmp);
			if (ret != JAL_OK) {
				goto cleanup;
			}
			xmlAddChild(logger_metadata_element, tmp);
			curr = curr->next;
		}
	}
	*new_elem = logger_metadata_element;

	return JAL_OK;

cleanup:
	if (logger_metadata_element) {
		xmlFreeNode(logger_metadata_element);
	}
	return ret;
}
