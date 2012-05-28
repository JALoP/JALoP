/**
 * @file jalp_journal_metadata_xml.h This file defines functions to handle
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
#ifndef _JALP_JOURNAL_METADATA_XML_H_
#define _JALP_JOURNAL_METADATA_XML_H_

#include <libxml/tree.h>

#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jalp_journal_metadata.h>

/**
 * Convert a jalp_journal_metadata struct to a xmlDocPtr element
 * for use with the libxml2 library.
 *
 * @param[in] journal The jalp_journal_metadata struct to convert.
 * @param[in] doc The xmlDocPtr to create the xmlNodePtr from.
 * Maintains the same namespace.
 * @param[out] new_elem The xmlNodePtr that holds the new element.
 *
 * @return JAL_OK on success, JAL_E_INVAL_* for invalid structs, 
 * and JAL_E_XML_CONVERSION otherwise.
 */
enum jal_status jalp_journal_metadata_to_elem(
		const struct jalp_journal_metadata *journal,
		xmlDocPtr doc,
		xmlNodePtr *new_elem);

#endif //_JALP_JOURNAL_METADATA_XML_H_

