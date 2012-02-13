/**
 * @file jalpx_param_xml.c This file defines functions to handle
 * converting param list metadata to XML.
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

#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_structured_data.h>
#include "jalpx_param_xml.h"

enum jal_status jalpx_param_to_elem(const struct jalp_param *param,
				const xmlChar *elem_name,
				const xmlChar *attr_name,
				xmlDocPtr doc,
				xmlNodePtr *elem)
{
	if (!param || !elem_name || !attr_name || !doc) {
		return JAL_E_XML_CONVERSION;
	}

	if (!param->key) {
		return JAL_E_INVAL_PARAM;
	}

	const xmlChar *xml_attr_val = (xmlChar *) param->key;

	xmlNodePtr new_elem = xmlNewDocNode(doc, NULL, elem_name, NULL);
	xmlSetProp(new_elem, attr_name, xml_attr_val);
	xmlNsPtr ns = xmlNewNs(new_elem, (xmlChar *) JAL_APP_META_TYPES_NAMESPACE_URI, NULL);
	xmlSetNs(new_elem, ns);

	if (param->value) {
		xmlChar *xml_elem_val = (xmlChar *)param->value;
		xmlNodeAddContent(new_elem, xml_elem_val);
	}
	*elem = new_elem;

	return JAL_OK;
}

