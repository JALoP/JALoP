/**
 * @file jalp_stack_frame_xml.h This file defines functions to deal with
 * converting jalp_stack_frame to XML.
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
#ifndef _JALP_STACK_FRAME_XML_H_
#define _JALP_STACK_FRAME_XML_H_

#include <libxml/tree.h>

#include <jalop/jalp_logger_metadata.h>
#include <jalop/jal_status.h>

/**
 * Convert a single jalp_stack_frame struct to a DOMDocument element.
 *
 * regardless of the number of elements in the list pointed to by
 * \pstack_frame, this function will only create the XML for a  single stack
 * frame. To generate the output for the complete list, you must iterate over
 * the list pointed to by \pstack_frame and call jalp_stack_frame_to_elem for
 * each element. On success, \pnew_elem will be set to the newly created 
 * DOMElement and JAL_OK is returned.
 *
 * @param[in] stack_frame The jalp_stack_frame struct to convert.
 * @param[in] doc The DOMDocument to create the DOMElement from.
 * @param[out] new_elem An address that will get set to a newly created element.
 *             If \p*new_elem is non-null, it is treated as an error and 
 *             JAL_E_XML_CONVERSION is returned
 * @return 
 *  - JAL_OK on success
 *  - JAL_E_XML_CONVERSION if an error occurs
 */
enum jal_status jalp_stack_frame_to_elem(
		const struct jalp_stack_frame *stack_frame,
		xmlNodePtr doc,
		xmlNodePtr *new_elem);

#endif //_JALP_STACK_FRAME_XML_H_

