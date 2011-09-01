/**
 * @file jalp_content_type_xml.cpp This file defines functions to deal with
 * converting the jalp_content_type struct to XML.
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

#include <string.h>

#include <xercesc/dom/DOM.hpp>

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_logger_metadata.h>
#include <jalop/jalp_journal_metadata.h>
#include "jal_asprintf_internal.h"
#include "jalp_param_xml.hpp"
#include "jalp_content_type_xml.hpp"

static const XMLCh JALP_XML_CONTENT_TYPE[] = {
	chLatin_C, chLatin_o, chLatin_n, chLatin_t, chLatin_e, chLatin_n, chLatin_t,
	chDash, chLatin_T, chLatin_y, chLatin_p, chLatin_e, chNull };
static const XMLCh JALP_XML_PARAMETER[] = {
	chLatin_P, chLatin_a, chLatin_r, chLatin_a, chLatin_m, chLatin_e, chLatin_t,
	chLatin_e, chLatin_r, chNull };
static const XMLCh JALP_XML_PARAMETER_ATTR_NAME[] = {
	chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };
static const XMLCh JALP_XML_MEDIATYPE[] = {
	chLatin_M, chLatin_e, chLatin_d, chLatin_i, chLatin_a, chLatin_T, chLatin_y,
	chLatin_p, chLatin_e, chNull };
static const XMLCh JALP_XML_SUBTYPE[] = {
	chLatin_S, chLatin_u, chLatin_b, chLatin_T, chLatin_y, chLatin_p, chLatin_e, chNull };

static const XMLCh JALP_XML_MEDIATYPE_APPLICATION [] = {
	chLatin_a, chLatin_p, chLatin_p, chLatin_l, chLatin_i, chLatin_c, chLatin_a,
	chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull };
static const XMLCh JALP_XML_MEDIATYPE_AUDIO [] = {
	chLatin_a, chLatin_u, chLatin_d, chLatin_i, chLatin_o, chNull };
static const XMLCh JALP_XML_MEDIATYPE_EXAMPLE [] = {
	chLatin_e, chLatin_x, chLatin_a, chLatin_m, chLatin_p, chLatin_l, chLatin_e, chNull };
static const XMLCh JALP_XML_MEDIATYPE_IMAGE [] = {
	chLatin_i, chLatin_m, chLatin_a, chLatin_g, chLatin_e, chNull };
static const XMLCh JALP_XML_MEDIATYPE_MESSAGE [] = {
	chLatin_m, chLatin_e, chLatin_s, chLatin_s, chLatin_a, chLatin_g, chLatin_e, chNull };
static const XMLCh JALP_XML_MEDIATYPE_MODEL [] = {
	chLatin_m, chLatin_o, chLatin_d, chLatin_e, chLatin_l, chNull };
static const XMLCh JALP_XML_MEDIATYPE_TEXT [] = {
	chLatin_t, chLatin_e, chLatin_x, chLatin_t, chNull };
static const XMLCh JALP_XML_MEDIATYPE_VIDEO [] = {
	chLatin_v, chLatin_i, chLatin_d, chLatin_e, chLatin_o, chNull };

enum jal_status jalp_content_type_to_elem(const struct jalp_content_type * content_type, DOMDocument *doc, DOMElement **elem)
{
	if ((!doc) || (!content_type) || !elem || *elem) {
		return JAL_E_XML_CONVERSION;
	}

	if (!content_type->subtype ) {
		return JAL_E_INVAL_CONTENT_TYPE;
	}

	XMLCh *namespace_uri = XMLString::transcode(JAL_APP_META_TYPES_NAMESPACE_URI);

	XMLCh *xml_val_subtype;

	enum jal_status ret;

	/* create the content_type element */
	DOMElement *content_type_elt;
	content_type_elt = doc->createElementNS(namespace_uri, JALP_XML_CONTENT_TYPE);


	/* append jalp_params */
	struct jalp_param *param_curr = content_type->params;
	DOMElement *param_curr_elt_p = NULL;
	while (param_curr) {
		ret = jalp_param_to_elem(param_curr, JALP_XML_PARAMETER, JALP_XML_PARAMETER_ATTR_NAME, doc, &param_curr_elt_p);
		if (ret == JAL_OK) {
			content_type_elt->appendChild(param_curr_elt_p);
			param_curr = param_curr->next;
			param_curr_elt_p = NULL;
		}
		else {
			XMLString::release(&namespace_uri);
			return ret;
		}
	}


	/* set media type attribute */
	switch (content_type->media_type) {

		case (JALP_MT_APPLICATION):
			content_type_elt->setAttribute(JALP_XML_MEDIATYPE, JALP_XML_MEDIATYPE_APPLICATION);
			break;
		case (JALP_MT_AUDIO):
			content_type_elt->setAttribute(JALP_XML_MEDIATYPE, JALP_XML_MEDIATYPE_AUDIO);
			break;
		case (JALP_MT_EXAMPLE):
			content_type_elt->setAttribute(JALP_XML_MEDIATYPE, JALP_XML_MEDIATYPE_EXAMPLE);
			break;
		case (JALP_MT_IMAGE):
			content_type_elt->setAttribute(JALP_XML_MEDIATYPE, JALP_XML_MEDIATYPE_IMAGE);
			break;
		case (JALP_MT_MESSAGE):
			content_type_elt->setAttribute(JALP_XML_MEDIATYPE, JALP_XML_MEDIATYPE_MESSAGE);
			break;
		case (JALP_MT_MODEL):
			content_type_elt->setAttribute(JALP_XML_MEDIATYPE, JALP_XML_MEDIATYPE_MODEL);
			break;
		case (JALP_MT_TEXT):
			content_type_elt->setAttribute(JALP_XML_MEDIATYPE, JALP_XML_MEDIATYPE_TEXT);
			break;
		case (JALP_MT_VIDEO):
			content_type_elt->setAttribute(JALP_XML_MEDIATYPE, JALP_XML_MEDIATYPE_VIDEO);
			break;
		default:
			XMLString::release(&namespace_uri);
			return JAL_E_INVAL_CONTENT_TYPE;

	}

	/* set subtype attribute */
	xml_val_subtype = XMLString::transcode(content_type->subtype);
	content_type_elt->setAttribute(JALP_XML_SUBTYPE, xml_val_subtype);

	XMLString::release(&namespace_uri);
	XMLString::release(&xml_val_subtype);

	*elem = content_type_elt;

	return JAL_OK;
}
