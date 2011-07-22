/**
 * @file jalp_log_severity_xml.hpp This file defines functions to deal with
 * converting log severity metadata to XML.
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
#ifndef _JALP_LOG_SEVERITY_XML_HPP_
#define _JALP_LOG_SEVERITY_XML_HPP_

#include <xercesc/dom/DOM.hpp>

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_logger_metadata.h>

XERCES_CPP_NAMESPACE_USE

/**
 * Convert a jalp_log_severity struct to a DOMDocument element
 * for use with the Xerces XML library.
 *
 * @param[in] severity The jalp_log_severity struct to convert.
 * @param[in] doc The DOMDocument to create the DOMElement from. Maintains the same namespace
 * @param[out] elem The DOMElement that holds the newly created element.
 * @return JAL_OK on success, JAL_E_XML_CONVERSION otherwise
 */
enum jal_status jalp_log_severity_to_elem(const struct jalp_log_severity * severity, DOMDocument *doc, DOMElement **elem);

#endif //_JALP_LOG_SEVERITY_XML_HPP_
