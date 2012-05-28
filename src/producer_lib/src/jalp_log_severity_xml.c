/**
 * @file jalp_log_severity_xml.c This file defines functions to deal with
 * converting log severity metadata to XML.
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

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_logger_metadata.h>
#include <jalop/jal_status.h>
#include "jalp_log_severity_xml.h"
#include "jal_asprintf_internal.h"

#define JALP_XML_SEVERITY "Severity"
#define JALP_XML_NAME "Name"

enum jal_status jalp_log_severity_to_elem(
		const struct jalp_log_severity * severity,
		xmlDocPtr doc,
		xmlNodePtr *elem)
{

	/* null checks on args */
	if((!doc) || (!severity) || !elem || (*elem)) {
		return JAL_E_XML_CONVERSION;
	}

	const xmlChar *jal_ns = (xmlChar *)JAL_APP_META_TYPES_NAMESPACE_URI;
	char *level_val_str;
	jal_asprintf(&level_val_str, "%d", severity->level_val);
	const xmlChar *xml_level_val = (xmlChar *) level_val_str;

	/* Create the severity Element/Node */
	xmlNodePtr severity_elt = xmlNewDocNode(doc, NULL,
						(xmlChar *)JALP_XML_SEVERITY, NULL);
	xmlNsPtr ns = xmlNewNs(severity_elt, jal_ns, NULL);
	xmlSetNs(severity_elt, ns);

	/* add the level_str field to the severity Element/Node */
	if (severity->level_str) {
		xmlChar *xml_level_str = (xmlChar *)severity->level_str;
		xmlSetProp(severity_elt, (xmlChar *)JALP_XML_NAME, xml_level_str);
	}

	xmlNodeAddContent(severity_elt, xml_level_val);

	free(level_val_str);

	*elem = severity_elt;

	return JAL_OK;
}

