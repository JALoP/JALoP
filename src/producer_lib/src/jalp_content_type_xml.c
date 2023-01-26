/**
 * @file jalp_content_type_xml.c This file defines functions to deal with
 * converting the jalp_content_type struct to XML.
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

#include <string.h>

#include <libxml/tree.h>

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_logger_metadata.h>
#include <jalop/jalp_journal_metadata.h>
#include "jal_asprintf_internal.h"
#include "jalp_param_xml.h"
#include "jalp_content_type_xml.h"

#define JALP_XML_CONTENT_TYPE "Content-Type"
#define JALP_XML_PARAMETER "Parameter"
#define JALP_XML_PARAMETER_ATTR_NAME "Name"
#define JALP_XML_MEDIATYPE "MediaType"
#define JALP_XML_SUBTYPE "SubType"
#define JALP_XML_MEDIATYPE_APPLICATION "application"
#define JALP_XML_MEDIATYPE_AUDIO "audio"
#define JALP_XML_MEDIATYPE_EXAMPLE "example"
#define JALP_XML_MEDIATYPE_IMAGE "image"
#define JALP_XML_MEDIATYPE_MESSAGE "message"
#define JALP_XML_MEDIATYPE_MODEL "model"
#define JALP_XML_MEDIATYPE_TEXT "text"
#define JALP_XML_MEDIATYPE_VIDEO "video"

enum jal_status jalp_content_type_to_elem(
		const struct jalp_content_type * content_type,
		xmlNodePtr parent,
		xmlNodePtr *elem)
{
	if ((!parent) || (!content_type) || !elem || *elem) {
		return JAL_E_XML_CONVERSION;
	}

	if (!content_type->subtype ) {
		return JAL_E_INVAL_CONTENT_TYPE;
	}

	xmlChar *xml_val_subtype;
	enum jal_status ret;

	/* Create the content_type element */
	xmlNodePtr content_type_elt = xmlNewChild(parent, NULL,
						(xmlChar *)JALP_XML_CONTENT_TYPE,
						NULL);

	/* Append jalp_params */
	struct jalp_param *param_curr = content_type->params;
	while (param_curr) {
		xmlNodePtr param_curr_elt_p = NULL;
		ret = jalp_param_to_elem(
				param_curr,
				(xmlChar *)JALP_XML_PARAMETER,
				(xmlChar *)JALP_XML_PARAMETER_ATTR_NAME,
				content_type_elt,
				&param_curr_elt_p);
		if (JAL_OK == ret) {
			xmlAddChild(content_type_elt, param_curr_elt_p);
			param_curr = param_curr->next;
		}
		else {
			xmlFreeNode(content_type_elt);
			xmlFreeNode(param_curr_elt_p);
			return ret;
		}
	}

	/* Set media type attribute */
	switch (content_type->media_type) {

		case (JALP_MT_APPLICATION):
			xmlSetProp(
				content_type_elt,
				(xmlChar *) JALP_XML_MEDIATYPE,
				(xmlChar *) JALP_XML_MEDIATYPE_APPLICATION);
			break;
		case (JALP_MT_AUDIO):
			xmlSetProp(
				content_type_elt,
				(xmlChar *) JALP_XML_MEDIATYPE,
				(xmlChar *) JALP_XML_MEDIATYPE_AUDIO);
			break;
		case (JALP_MT_EXAMPLE):
			xmlSetProp(
				content_type_elt,
				(xmlChar *) JALP_XML_MEDIATYPE,
				(xmlChar *) JALP_XML_MEDIATYPE_EXAMPLE);
			break;
		case (JALP_MT_IMAGE):
			xmlSetProp(
				content_type_elt,
				(xmlChar *) JALP_XML_MEDIATYPE,
				(xmlChar *) JALP_XML_MEDIATYPE_IMAGE);
			break;
		case (JALP_MT_MESSAGE):
			xmlSetProp(
				content_type_elt,
				(xmlChar *) JALP_XML_MEDIATYPE,
				(xmlChar *) JALP_XML_MEDIATYPE_MESSAGE);
			break;
		case (JALP_MT_MODEL):
			xmlSetProp(
				content_type_elt,
				(xmlChar *) JALP_XML_MEDIATYPE,
				(xmlChar *) JALP_XML_MEDIATYPE_MODEL);
			break;
		case (JALP_MT_TEXT):
			xmlSetProp(
				content_type_elt,
				(xmlChar *) JALP_XML_MEDIATYPE,
				(xmlChar *) JALP_XML_MEDIATYPE_TEXT);
			break;
		case (JALP_MT_VIDEO):
			xmlSetProp(
				content_type_elt,
				(xmlChar *) JALP_XML_MEDIATYPE,
				(xmlChar *) JALP_XML_MEDIATYPE_VIDEO);
			break;
		default:
			xmlFreeNode(content_type_elt);
			return JAL_E_INVAL_CONTENT_TYPE;
	}

	/* Set subtype attribute */
	xml_val_subtype = (xmlChar *)content_type->subtype;
	xmlSetProp(
		content_type_elt,
		(xmlChar *) JALP_XML_SUBTYPE,
		(xmlChar *) xml_val_subtype);

	*elem = content_type_elt;

	return JAL_OK;
}

