/**
 * @file jalp_file_info_xml.c This file defines functions to deal with
 * converting the jalp_file_info struct to XML.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below
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

#include <inttypes.h>

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jal_status.h>
#include "jalp_content_type_xml.h"
#include "jalp_file_info_xml.h"
#include "jal_asprintf_internal.h"

#define JALP_XML_FILE_INFO "FileInfo"
#define JALP_XML_FILE_NAME "FileName"
#define JALP_XML_ORIGINAL_SIZE "OriginalSize"
#define JALP_XML_SIZE "Size"
#define JALP_XML_THREAT_LEVEL "ThreatLevel"
#define JALP_XML_THREAT_UNKNOWN "unknown"
#define JALP_XML_THREAT_SAFE "safe"
#define JALP_XML_THREAT_MALICIOUS "malicious"

enum jal_status jalp_file_info_to_elem(
		const struct jalp_file_info * file_info,
		xmlNodePtr parent,
		xmlNodePtr *elem)
{
	if (!file_info || !parent || !elem || *elem) {
		return JAL_E_XML_CONVERSION;
	}

	if (!file_info->filename) {
		return JAL_E_INVAL_FILE_INFO;
	}

	xmlChar *xml_original_size;
	xmlChar *xml_size;
	xmlChar *xml_file_name;

	xmlNodePtr file_info_elt = xmlNewChild(parent, NULL,
					(xmlChar *)JALP_XML_FILE_INFO,
					NULL);

	enum jal_status ret = JAL_OK;

	/* append the content type element */
	if (file_info->content_type) {
		xmlNodePtr content_type_elt = NULL;
		ret = jalp_content_type_to_elem(file_info->content_type, file_info_elt, &content_type_elt);
		if (ret != JAL_OK) {
			goto err_out;
		}
	}

	/* add file name attribute */
	xml_file_name = (xmlChar *)file_info->filename;
	xmlSetProp(file_info_elt, (xmlChar *)JALP_XML_FILE_NAME, xml_file_name);

	/* add original size attribute */
	char *str_original_size;
	jal_asprintf(&str_original_size, "%" PRIu64, file_info->original_size);
	xml_original_size = (xmlChar *)str_original_size;
	xmlSetProp(file_info_elt, (xmlChar *)JALP_XML_ORIGINAL_SIZE, xml_original_size);
	free(str_original_size);

	/* add size attribute */
	char *str_size;
	jal_asprintf(&str_size, "%" PRIu64, file_info->size);
	xml_size = (xmlChar *)str_size;
	xmlSetProp(file_info_elt, (xmlChar *)JALP_XML_SIZE, xml_size);
	free(str_size);

	/* add threat level attribute */
	switch (file_info->threat_level) {
		case (JAL_THREAT_UNKNOWN):
			xmlSetProp(file_info_elt,
				(xmlChar *)JALP_XML_THREAT_LEVEL,
				(xmlChar *)JALP_XML_THREAT_UNKNOWN);
			break;
		case (JAL_THREAT_SAFE):
			xmlSetProp(file_info_elt,
				(xmlChar *)JALP_XML_THREAT_LEVEL,
				(xmlChar *)JALP_XML_THREAT_SAFE);
			break;
		case (JAL_THREAT_MALICIOUS):
			xmlSetProp(file_info_elt,
				(xmlChar *)JALP_XML_THREAT_LEVEL,
				(xmlChar *)JALP_XML_THREAT_MALICIOUS);
			break;
		default:
			ret = JAL_E_INVAL_FILE_INFO;
			goto err_out;
	}

	*elem = file_info_elt;

	return JAL_OK;

err_out:

	return ret;
}
