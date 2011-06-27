/**
 * @file jalp_structured_data_xml.cpp This file defines functions to handle
 * converting structured data to XML.
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

#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_structured_data.h>
#include "jalp_param_xml.hpp"
#include "jalp_structured_data_xml.hpp"

XERCES_CPP_NAMESPACE_USE
static const XMLCh JALP_XML_STRUCTURED_DATA[] = {
	chLatin_S, chLatin_t, chLatin_r, chLatin_u, chLatin_c, 
	chLatin_t, chLatin_u, chLatin_r, chLatin_e, chLatin_d,
	chLatin_D, chLatin_a, chLatin_t, chLatin_a, chNull };
static const XMLCh JALP_XML_SD_ID[] = {
	chLatin_S, chLatin_D, chUnderscore, chLatin_I, chLatin_D, 
	chNull };
static const XMLCh JALP_XML_FIELD[] = {
	chLatin_F, chLatin_i, chLatin_e, chLatin_l, chLatin_d,
	chNull };
static const XMLCh JALP_XML_KEY[] = {
	chLatin_K, chLatin_e, chLatin_y, chNull };

enum jal_status jalp_structured_data_to_elem(const struct jalp_structured_data *sd,
						DOMDocument *doc,
						DOMElement **new_elem)
{
	if (!sd || !doc || !new_elem || *new_elem) {
		return JAL_E_XML_CONVERSION;
	}
	if (!sd->sd_id) {
		return JAL_E_INVAL_STRUCTURED_DATA;
	}
	enum jal_status ret;
	XMLCh *namespace_uri = XMLString::transcode(JALP_APP_META_TYPES_NAMESPACE_URI);
	XMLCh *xml_sd_id = XMLString::transcode(sd->sd_id);
	DOMElement *sd_element = doc->createElementNS(namespace_uri, JALP_XML_STRUCTURED_DATA);
	sd_element->setAttribute(JALP_XML_SD_ID, xml_sd_id);
	XMLString::release(&namespace_uri);
	XMLString::release(&xml_sd_id);
	if (sd->param_list) {
		struct jalp_param *curr = sd->param_list;
		while (curr) {
			DOMElement *tmp = NULL;
			ret = jalp_param_to_elem(curr, JALP_XML_FIELD, JALP_XML_KEY, doc, &tmp);
			if (ret != JAL_OK) {
				return ret;
			}
			sd_element->appendChild(tmp);
			curr = curr->next;
		}
	} else {
		return JAL_E_INVAL_STRUCTURED_DATA;
	}
	*new_elem = sd_element;
	return JAL_OK;
}
