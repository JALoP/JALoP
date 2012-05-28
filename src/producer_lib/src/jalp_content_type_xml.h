 /**
 * @file jalp_content_type_xml.h This file defines functions to deal with
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

#ifndef _JALP_CONTENT_TYPE_XML_H_
#define _JALP_CONTENT_TYPE_XML_H_

#include <libxml/tree.h>

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_journal_metadata.h>
#include "jal_asprintf_internal.h"
#include "jalp_param_xml.h"

/**
 * Convert a jalp_content_type struct to a xmlDocPtr element
 * for use with the libxml2 library.
 *
 * @param[in] content_type The jalp_content_type struct to convert.
 * @param[in] doc The xmlDocPtr to create the xmlNodePtr from. Maintains the same namespace.
 * @param[out] elem A pointer to hold the created xmlNodePtr.
 * @return JAL_OK on success, JAL_E_INVAL if the jalp_content_type struct has issues,
 *   or else JAL_E_XML_CONVERSION on failure.
 */
enum jal_status jalp_content_type_to_elem(
		const struct jalp_content_type * content_type,
		xmlDocPtr doc,
		xmlNodePtr *elem);

#endif //_JALP_CONTENT_TYPE_XML_H_
