/**
 * @file jalp_journal_metadata_xml.c This file defines functions to handle
 * converting journal metadata to XML.
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
#include <jalop/jalp_journal_metadata.h>
#include "jalp_file_info_xml.h"
#include "jalp_transform_xml.h"
#include "jalp_journal_metadata_xml.h"
#include "jal_asprintf_internal.h"

#define JALP_XML_JOURNAL_META "JournalMetadata"
#define JALP_XML_TRANSFORMS "Transforms"

enum jal_status jalp_journal_metadata_to_elem(
		const struct jalp_journal_metadata *journal,
		xmlNodePtr doc,
		xmlNodePtr *new_elem)
{
	if (!journal || !doc || !new_elem || *new_elem) {
		return JAL_E_XML_CONVERSION;
	}

	enum jal_status ret;
	xmlNodePtr jmeta_element = xmlNewChild(doc, NULL,
					(xmlChar *)JALP_XML_JOURNAL_META, NULL);

	if (journal->file_info) {
		xmlNodePtr tmp = NULL;
		ret = jalp_file_info_to_elem(journal->file_info, jmeta_element, &tmp);
		if (ret != JAL_OK) {
			goto cleanup;
		}
	} else {
		ret = JAL_E_INVAL_FILE_INFO;
		goto cleanup;
	}

	if (journal->transforms) {
		struct jalp_transform *curr = journal->transforms;
		xmlNodePtr trans_element = xmlNewChild(jmeta_element, NULL,
				(xmlChar *)JALP_XML_TRANSFORMS,
				NULL);
		while (curr) {
			xmlNodePtr tmp = NULL;
			ret = jalp_transform_to_elem(curr, doc, &tmp);
			if (ret != JAL_OK) {
				xmlFreeNode(trans_element);
				goto cleanup;
			}
			xmlAddChild(trans_element, tmp);
			curr = curr->next;
		}
	}

	*new_elem = jmeta_element;

	return JAL_OK;

cleanup:
	if (jmeta_element) {
		xmlFreeNode(jmeta_element);
	}
	return ret;
}
