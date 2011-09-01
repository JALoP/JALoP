/**
 * @file jalp_app_metadata_xml.cpp This file defines functions to deal with
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

#include <xercesc/dom/DOM.hpp>
#include <uuid/uuid.h>

#include <jalop/jalp_app_metadata.h>
#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>
#include "jalp_app_metadata_xml.hpp"
#include "jal_xml_utils.hpp"
#include "jal_asprintf_internal.h"
#include "jalp_syslog_metadata_xml.hpp"
#include "jalp_logger_metadata_xml.hpp"
#include "jalp_journal_metadata_xml.hpp"

XERCES_CPP_NAMESPACE_USE


#define JAL_UUID_STR_LEN 36

static const XMLCh  XML_CORE[] = {
	chLatin_C, chLatin_o, chLatin_r, chLatin_e, chNull };

static const XMLCh APPLICATIONMETADATA[] = {
	chLatin_A, chLatin_p, chLatin_p, chLatin_l, chLatin_i, chLatin_c, chLatin_a,
	chLatin_t, chLatin_i, chLatin_o, chLatin_n, chLatin_M, chLatin_e, chLatin_t,
	chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a, chNull };
static const XMLCh EVENTID[] = {
	chLatin_E, chLatin_v, chLatin_e, chLatin_n, chLatin_t, chLatin_I, chLatin_D,
	chNull };
static const XMLCh CUSTOM[] = {
	chLatin_C, chLatin_u, chLatin_s, chLatin_t, chLatin_o, chLatin_m, chNull };
static const XMLCh JID[] = {
	chLatin_J, chLatin_I, chLatin_D, chNull };
static const char *UUIDDASH = "UUID-";

enum jal_status jalp_app_metadata_to_elem(struct jalp_app_metadata *app_meta,
		const struct jalp_context_t *ctx,
		DOMDocument *doc, DOMElement **elem)
{
	if(!app_meta || !ctx || !doc || !elem || *elem) {
		return JAL_E_XML_CONVERSION;
	}

	enum jal_status ret = JAL_OK;

	uuid_t jid;
	char str_jid[JAL_UUID_STR_LEN + 1];
	char *ncname_jid;
	XMLCh *xml_jid;


	XMLCh *namespace_uri = XMLString::transcode(JAL_APP_META_TYPES_NAMESPACE_URI);

	DOMElement *app_meta_elem = doc->createElementNS(namespace_uri, APPLICATIONMETADATA);

	if (app_meta->event_id) {
		DOMElement *event_id_elem = doc->createElementNS(namespace_uri, EVENTID);
		XMLCh *xml_event_id = XMLString::transcode(app_meta->event_id);
		event_id_elem->setTextContent(xml_event_id);
		XMLString::release(&xml_event_id);
		app_meta_elem->appendChild(event_id_elem);
	}

	DOMElement *syslog_elem = NULL;
	DOMElement *logger_elem = NULL;
	DOMElement *custom_elem = NULL;


	switch(app_meta->type) {

		case(JALP_METADATA_SYSLOG):
			ret = jalp_syslog_metadata_to_elem(app_meta->sys, ctx, doc, &syslog_elem);
			if (ret != JAL_OK) {
				goto err_out;
			}
			app_meta_elem->appendChild(syslog_elem);
			break;
		case(JALP_METADATA_LOGGER):
			ret = jalp_logger_metadata_to_elem(app_meta->log, ctx, doc, &logger_elem);
			if (ret != JAL_OK) {
				goto err_out;
			}
			app_meta_elem->appendChild(logger_elem);
			break;
		case(JALP_METADATA_CUSTOM):
			custom_elem = doc->createElementNS(namespace_uri, CUSTOM);
			ret = jal_parse_xml_snippet(custom_elem, app_meta->custom);
			if (ret != JAL_OK) {
				goto err_out;
			}
			app_meta_elem->appendChild(custom_elem);
			break;
		case(JALP_METADATA_NONE):
			//adds an empty custom element in this case
			custom_elem = doc->createElementNS(namespace_uri, CUSTOM);
			app_meta_elem->appendChild(custom_elem);
			break;
		default:
			ret = JAL_E_INVAL_APP_METADATA;
			goto err_out;
	}

	if (app_meta->file_metadata) {
		DOMElement *journal_metadata_elem = NULL;
		ret = jalp_journal_metadata_to_elem(app_meta->file_metadata, doc, &journal_metadata_elem);
		if (ret != JAL_OK) {
			goto err_out;
		}
		app_meta_elem->appendChild(journal_metadata_elem);
	}


	// Add the JID attribute
	uuid_generate(jid);
	uuid_unparse(jid, str_jid);
	jal_asprintf(&ncname_jid, "%s%s", UUIDDASH, str_jid);
	xml_jid = XMLString::transcode(ncname_jid);
	app_meta_elem->setAttribute(JID, xml_jid);
	app_meta_elem->setIdAttribute(JID, true);

	free(ncname_jid);
	XMLString::release(&namespace_uri);
	XMLString::release(&xml_jid);

	*elem = app_meta_elem;

	return JAL_OK;

err_out:
	XMLString::release(&namespace_uri);

	return ret;
}
