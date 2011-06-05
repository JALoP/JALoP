/**
 * @file jalp_log_severity_xml.cpp This file defines functions to deal with
 * converting log severity metadata to XML.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as be$
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

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_logger_metadata.h>
#include "jalp_log_severity_xml.hpp"
#include "jal_asprintf_internal.h"

#define JALP_XML_SEVERITY "Severity"
#define JALP_XML_NAME "Name"

XERCES_CPP_NAMESPACE_USE

DOMElement *jalp_log_severity_to_elem(const struct jalp_log_severity * severity, DOMDocument *doc)
{

	/* null checks on args */
	if((!doc) || (!severity)) {
		return NULL;
	}

	XMLCh *namespace_uri = XMLString::transcode(JALP_APP_META_TYPES_NAMESPACE_URI);
	XMLCh *xml_severity = XMLString::transcode(JALP_XML_SEVERITY);
	XMLCh *xml_severity_name = XMLString::transcode(JALP_XML_NAME);
	char * level_val_str;
	jal_asprintf(&level_val_str, "%d", severity->level_val);
	XMLCh *xml_level_val = XMLString::transcode(level_val_str);

	/* create the severity DOMElement */
	DOMElement *severity_elt;
	severity_elt = doc->createElementNS(namespace_uri, xml_severity);

	/* add the level_str field to the severity DOMElement */
	if(severity->level_str) {
		XMLCh *xml_level_str = XMLString::transcode(severity->level_str);
		severity_elt->setAttribute(xml_severity_name, xml_level_str);
		XMLString::release(&xml_level_str);
	}

	/* add the level_val field to the severity DOMElement */
	DOMText *val = doc->createTextNode(xml_level_val);
	severity_elt->appendChild(val);


	free(level_val_str);
	XMLString::release(&namespace_uri);
	XMLString::release(&xml_severity);
	XMLString::release(&xml_severity_name);
	XMLString::release(&xml_level_val);
	return severity_elt;

}
