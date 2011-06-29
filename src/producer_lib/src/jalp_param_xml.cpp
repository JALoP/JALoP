/**
 * @file jalp_param_xml.cpp This file defines functions to handle
 * converting param list metadata to XML.
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

#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_structured_data.h>
#include "jalp_param_xml.hpp"

XERCES_CPP_NAMESPACE_USE

enum jal_status jalp_param_to_elem(const struct jalp_param *param,
				const XMLCh *elem_name,
				const XMLCh *attr_name,
				DOMDocument *doc,
				DOMElement **elem)
{
	if (!param || !elem_name || !attr_name || !elem || *elem || !doc) {
		return JAL_E_XML_CONVERSION;
	}

	if (!param->key) {
		return JAL_E_INVAL_PARAM;
	}

	XMLCh *namespace_uri = XMLString::transcode(JALP_APP_META_TYPES_NAMESPACE_URI);
	XMLCh *xml_attr_val = XMLString::transcode(param->key);
	XMLCh *xml_elem_val;
	DOMElement *new_elem;
	new_elem = doc->createElementNS(namespace_uri, elem_name);
	new_elem->setAttribute(attr_name, xml_attr_val);

	if (param->value) {
		xml_elem_val = XMLString::transcode(param->value);
		DOMText *val = doc->createTextNode(xml_elem_val);
		new_elem->appendChild(val);
		XMLString::release(&xml_elem_val);
	}

	XMLString::release(&namespace_uri);
	XMLString::release(&xml_attr_val);

	*elem = new_elem;

	return JAL_OK;
}
