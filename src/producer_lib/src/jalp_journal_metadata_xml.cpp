/**
 * @file jalp_journal_metadata_xml.cpp This file defines functions to handle
 * converting journal metadata to XML.
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
#include <jalop/jalp_journal_metadata.h>
#include "jalp_file_info_xml.hpp"
#include "jalp_transform_xml.hpp"
#include "jalp_journal_metadata_xml.hpp"
#include "jal_asprintf_internal.h"

XERCES_CPP_NAMESPACE_USE
static const XMLCh JALP_XML_JOURNAL_META[] = {
	chLatin_J, chLatin_o, chLatin_u, chLatin_r, chLatin_n,
	chLatin_a, chLatin_l, chLatin_M, chLatin_e, chLatin_t,
	chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a,
	chNull };

static const XMLCh JALP_XML_TRANSFORMS[] = {
	chLatin_T, chLatin_r, chLatin_a, chLatin_n, chLatin_s,
	chLatin_f, chLatin_o, chLatin_r, chLatin_m, chLatin_s,
	chNull };

enum jal_status jalp_journal_metadata_to_elem(const struct jalp_journal_metadata *journal,
					DOMDocument *doc,
					DOMElement **new_elem)
{
	if (!journal || !doc || !new_elem || *new_elem) {
		return JAL_E_XML_CONVERSION;
	}

	enum jal_status ret;
	XMLCh *namespace_uri = XMLString::transcode(JAL_APP_META_TYPES_NAMESPACE_URI);
	DOMElement *jmeta_element = doc->createElementNS(namespace_uri, JALP_XML_JOURNAL_META);

	if (journal->file_info) {
		DOMElement *tmp = NULL;
		ret = jalp_file_info_to_elem(journal->file_info, doc, &tmp);
		if (ret != JAL_OK) {
			goto cleanup;
		}
		jmeta_element->appendChild(tmp);
	} else {
		ret = JAL_E_INVAL_FILE_INFO;
		goto cleanup;
	}

	if (journal->transforms) {
		DOMElement *trans_element = doc->createElementNS(namespace_uri, JALP_XML_TRANSFORMS);
		struct jalp_transform *curr = journal->transforms;
		while (curr) {
			DOMElement *tmp = NULL;
			ret = jalp_transform_to_elem(curr, doc, &tmp);
			if (ret != JAL_OK) {
				trans_element->release();
				goto cleanup;
			}
			trans_element->appendChild(tmp);
			curr = curr->next;
		}
		jmeta_element->appendChild(trans_element);
	}

	XMLString::release(&namespace_uri);

	*new_elem = jmeta_element;

	return JAL_OK;

cleanup:
	XMLString::release(&namespace_uri);
	if (jmeta_element) {
		jmeta_element->release();
	}
	return ret;
}
