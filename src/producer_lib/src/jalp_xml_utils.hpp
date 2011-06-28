/**
 * @file jalp_xml_utils.hpp This file defines helper fucntions for dealing with
 * createing/reading XML data.
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
#ifndef _JALP_XML_UITILS_HPPP_
#define _JALP_XML_UITILS_HPPP_

#include <jalop/jal_status.h>
#include <xercesc/dom/DOMElement.hpp>


XERCES_CPP_NAMESPACE_USE
/**
 * Helper function to parse an xml snippet.
 *
 * @param[in] ctx_node A node to use as the parent of elements encountered during the parse.
 * @param[in] snippet a snippet of XML. The contents will be added to \pctx_node.
 * @return JAL_OK on success or JAL_E_XML_PARSE if there was an error parsing the
 * snippet.
 */
enum jal_status parse_xml_snippet(DOMElement *ctx_node, const char *snippet);

#endif // _JALP_XML_UITILS_HPPP_
