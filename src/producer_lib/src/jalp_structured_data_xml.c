 
/**
 * @file jalp_structured_data_xml.c This file defines functions to handle
 * converting structured data to XML.
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

#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_structured_data.h>
#include "jalp_param_xml.h"
#include "jalp_structured_data_xml.h"

#define JALP_XML_STRUCTURED_DATA "StructuredData"
#define JALP_XML_SD_ID "SD_ID"
#define JALP_XML_FIELD "Field"
#define JALP_XML_KEY "Key"

enum jal_status jalp_structured_data_to_elem(const struct jalp_structured_data *sd,
						xmlDocPtr doc,
						xmlNodePtr *new_elem)
{
	if (!sd || !doc || !new_elem || *new_elem) {
		return JAL_E_XML_CONVERSION;
	}
	if (!sd->sd_id) {
		return JAL_E_INVAL_STRUCTURED_DATA;
	}
	enum jal_status ret;
	const xmlChar *jal_ns = (xmlChar *)JAL_APP_META_TYPES_NAMESPACE_URI;
	const xmlChar *xml_sd_id = (xmlChar *)sd->sd_id;

	xmlNodePtr sd_element = xmlNewDocNode(doc, NULL,
					(xmlChar *)JALP_XML_STRUCTURED_DATA, NULL);
	xmlSetProp(sd_element, (xmlChar *)JALP_XML_SD_ID, xml_sd_id);
	xmlNsPtr ns = xmlNewNs(sd_element, jal_ns, NULL);
	xmlSetNs(sd_element, ns);
	if (sd->param_list) {
		struct jalp_param *curr = sd->param_list;
		while (curr) {
			xmlNodePtr tmp = NULL;
			ret = jalp_param_to_elem(curr,
				(xmlChar *)JALP_XML_FIELD,
				(xmlChar *)JALP_XML_KEY,
				doc, &tmp);
			if (JAL_OK != ret) {
				return ret;
			}
			xmlAddChild(sd_element, tmp);
			curr = curr->next;
		}
	} else {
		xmlFreeNode(sd_element);
		return JAL_E_INVAL_STRUCTURED_DATA;
	}
	*new_elem = sd_element;
	return JAL_OK;
}
