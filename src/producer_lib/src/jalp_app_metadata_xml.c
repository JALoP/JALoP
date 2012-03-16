/**
 * @file jalp_app_metadata_xml.c This file defines functions to deal with
 * converting jalp_app_metadata to a DOMDocument.
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

#include <uuid/uuid.h>

#include <libxml/tree.h>

#include <jalop/jalp_app_metadata.h>
#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>
#include "jalp_app_metadata_xml.h"
#include "jal_xml_utils.h"
#include "jal_asprintf_internal.h"
#include "jalp_syslog_metadata_xml.h"
#include "jalp_logger_metadata_xml.h"
#include "jalp_journal_metadata_xml.h"

#define JAL_UUID_STR_LEN 36

static const char *UUIDDASH = "UUID-";

#define XML_CORE "Core"
#define APPLICATIONMETADATA "ApplicationMetadata"
#define EVENTID "EventID"
#define CUSTOM "Custom"
#define	JID "JID"

enum jal_status jalp_app_metadata_to_elem(
		struct jalp_app_metadata *app_meta,
		const struct jalp_context_t *ctx,
		xmlDocPtr doc,
		xmlNodePtr *elem)
{
	if(!app_meta || !ctx || !doc || !elem || *elem) {
		return JAL_E_XML_CONVERSION;
	}

	enum jal_status ret = JAL_OK;

	uuid_t jid;
	char str_jid[JAL_UUID_STR_LEN + 1];
	char *ncname_jid;
	xmlChar *xml_jid;


	xmlChar *namespace_uri = (xmlChar *)JAL_APP_META_TYPES_NAMESPACE_URI;

	xmlNodePtr app_meta_elem = xmlNewDocNode(doc, NULL,
					(xmlChar *)APPLICATIONMETADATA, NULL);
	xmlNsPtr ns = xmlNewNs(app_meta_elem, namespace_uri, NULL);
	xmlSetNs(app_meta_elem, ns);

	if (app_meta->event_id) {
		xmlNewChild(app_meta_elem, NULL,
				(xmlChar *)EVENTID,
				(xmlChar *)app_meta->event_id);
	}

	xmlNodePtr syslog_elem = NULL;
	xmlNodePtr logger_elem = NULL;
	xmlNodePtr custom_elem = NULL;

	switch(app_meta->type) {

		case(JALP_METADATA_SYSLOG):
			ret = jalp_syslog_metadata_to_elem(app_meta->sys, ctx, doc, &syslog_elem);
			if (ret != JAL_OK) {
				goto err_out;
			}
			xmlAddChild(app_meta_elem, syslog_elem);
			break;
		case(JALP_METADATA_LOGGER):
			ret = jalp_logger_metadata_to_elem(app_meta->log, ctx, doc, &logger_elem);
			if (ret != JAL_OK) {
				goto err_out;
			}
			xmlAddChild(app_meta_elem, logger_elem);
			break;
		case(JALP_METADATA_CUSTOM):
			custom_elem = xmlNewChild(
						app_meta_elem,
						NULL,
						(xmlChar *)CUSTOM,
						NULL);
			ret = jal_parse_xml_snippet(&custom_elem, app_meta->custom);
			if (ret != JAL_OK) {
				goto err_out;
			}
			break;
		case(JALP_METADATA_NONE):
			//adds an empty custom element in this case
			xmlNewChild(app_meta_elem, NULL,
				(xmlChar *)CUSTOM,
				NULL);
			break;
		default:
			ret = JAL_E_INVAL_APP_METADATA;
			goto err_out;
	}

	if (app_meta->file_metadata) {
		xmlNodePtr journal_metadata_elem = NULL;
		ret = jalp_journal_metadata_to_elem(app_meta->file_metadata, doc, &journal_metadata_elem);
		if (ret != JAL_OK) {
			goto err_out;
		}
		xmlAddChild(app_meta_elem, journal_metadata_elem);
	}


	// Add the JID attribute
	uuid_generate(jid);
	uuid_unparse(jid, str_jid);
	jal_asprintf(&ncname_jid, "%s%s", UUIDDASH, str_jid);
	xml_jid = (xmlChar *)ncname_jid;
	xmlSetProp(app_meta_elem, (xmlChar *)JID, xml_jid);
	xmlAttrPtr attr = xmlHasProp(app_meta_elem, (xmlChar *)JID);
	if (!attr || !attr->children) {
		return JAL_E_INVAL;
	}
	xmlAddID(NULL, doc, (xmlChar *)xml_jid, attr);
	free(ncname_jid);

	*elem = app_meta_elem;

	return JAL_OK;

err_out:
	xmlFreeNodeList(app_meta_elem);
	return ret;
}
