/**
 * @file jalp_file_info_xml.hpp This file defines functions to deal with
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

#include <xercesc/dom/DOM.hpp>

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jal_status.h>

#ifndef _JALP_FILE_INFO_XML_HPP_
#define _JALP_FILE_INFO_XML_HPP_

XERCES_CPP_NAMESPACE_USE

/**
 * Convert a jalp_file_info struct to a DOMDocument element
 * for use with the Xerces XML library.
 *
 * @param[in] file_info The jalp_file_info struct to convert.
 * @param[in] doc The DOMDocument to create the DOMElement from. Maintains the same namespace
 * @param[out] elem A pointer to hold the created DOMElement.
 * @return JAL_OK on success, JAL_E_XML_CONVERSION on failure.
 */
enum jal_status jalp_file_info_to_elem(const struct jalp_file_info * file_info, DOMDocument *doc, DOMElement **elem);

#endif //_JALP_FILE_INFO_XML_HPP_
