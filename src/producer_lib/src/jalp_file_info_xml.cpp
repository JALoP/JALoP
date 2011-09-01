/**
 * @file jalp_file_info_xml.cpp This file defines functions to deal with
 * converting the jalp_file_info struct to XML.
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

#include <inttypes.h>
#include <xercesc/dom/DOM.hpp>

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jal_status.h>
#include "jalp_content_type_xml.hpp"
#include "jalp_file_info_xml.hpp"
#include "jal_asprintf_internal.h"

XERCES_CPP_NAMESPACE_USE

static const XMLCh JALP_XML_FILE_INFO[] = {
	chLatin_F, chLatin_i, chLatin_l, chLatin_e, chLatin_I, chLatin_n, chLatin_f, chLatin_o, chNull };
static const XMLCh JALP_XML_FILE_NAME[] = {
	chLatin_F, chLatin_i, chLatin_l, chLatin_e, chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };
static const XMLCh JALP_XML_ORIGINAL_SIZE[] = {
	chLatin_O, chLatin_r, chLatin_i, chLatin_g, chLatin_i, chLatin_n, chLatin_a, chLatin_l,
	chLatin_S, chLatin_i, chLatin_z, chLatin_e, chNull };
static const XMLCh JALP_XML_SIZE[] = {
	chLatin_S, chLatin_i, chLatin_z, chLatin_e, chNull };
static const XMLCh JALP_XML_THREAT_LEVEL[] = {
	chLatin_T, chLatin_h, chLatin_r, chLatin_e, chLatin_a, chLatin_t, chLatin_L, chLatin_e,
	chLatin_v, chLatin_e, chLatin_l, chNull };
static const XMLCh JALP_XML_THREAT_UNKNOWN[] = {
	chLatin_u, chLatin_n, chLatin_k, chLatin_n, chLatin_o, chLatin_w, chLatin_n, chNull };
static const XMLCh JALP_XML_THREAT_SAFE[] = {
	chLatin_s, chLatin_a, chLatin_f, chLatin_e, chNull };
static const XMLCh JALP_XML_THREAT_MALICIOIUS[] = {
	chLatin_m, chLatin_a, chLatin_l, chLatin_i, chLatin_c, chLatin_i, chLatin_o, chLatin_u,
	chLatin_s, chNull };

enum jal_status jalp_file_info_to_elem(const struct jalp_file_info * file_info, DOMDocument *doc, DOMElement **elem)
{
	if (!file_info || !doc || !elem || *elem) {
		return JAL_E_XML_CONVERSION;
	}

	if (!file_info->filename) {
		return JAL_E_INVAL_FILE_INFO;
	}

	XMLCh *namespace_uri = XMLString::transcode(JAL_APP_META_TYPES_NAMESPACE_URI);
	DOMElement *file_info_elt = doc->createElementNS(namespace_uri, JALP_XML_FILE_INFO);
	XMLCh *xml_original_size;
	XMLCh *xml_size;
	XMLCh *xml_file_name;

	enum jal_status ret = JAL_OK;

	/* append the content type element */
	if (file_info->content_type) {
		DOMElement *content_type_elt = NULL;
		ret = jalp_content_type_to_elem(file_info->content_type, doc, &content_type_elt);
		if (ret != JAL_OK) {
			goto err_out;
		}
		file_info_elt->appendChild(content_type_elt);
	}

	/* add file name attribute */
	xml_file_name = XMLString::transcode(file_info->filename);
	file_info_elt->setAttribute(JALP_XML_FILE_NAME, xml_file_name);
	XMLString::release(&xml_file_name);

	/* add original size attribute */
	char * str_original_size;
	jal_asprintf(&str_original_size, "%" PRIu64, file_info->original_size);
	xml_original_size = XMLString::transcode(str_original_size);
	free(str_original_size);
	file_info_elt->setAttribute(JALP_XML_ORIGINAL_SIZE, xml_original_size);
	XMLString::release(&xml_original_size);

	/* add size attribute */
	char * str_size;
	jal_asprintf(&str_size, "%" PRIu64, file_info->size);
	xml_size = XMLString::transcode(str_size);
	free(str_size);
	file_info_elt->setAttribute(JALP_XML_SIZE, xml_size);
	XMLString::release(&xml_size);

	/* add threat level attribute */
	switch (file_info->threat_level) {
		case (JAL_THREAT_UNKNOWN):
			file_info_elt->setAttribute(JALP_XML_THREAT_LEVEL, JALP_XML_THREAT_UNKNOWN);
			break;
		case (JAL_THREAT_SAFE):
			file_info_elt->setAttribute(JALP_XML_THREAT_LEVEL, JALP_XML_THREAT_SAFE);
			break;
		case (JAL_THREAT_MALICIOUS):
			file_info_elt->setAttribute(JALP_XML_THREAT_LEVEL, JALP_XML_THREAT_MALICIOIUS);
			break;
		default:
			ret = JAL_E_INVAL_FILE_INFO;
			goto err_out;
	}

	XMLString::release(&namespace_uri);

	*elem = file_info_elt;

	return JAL_OK;

err_out:
	XMLString::release(&namespace_uri);

	return ret;
}
