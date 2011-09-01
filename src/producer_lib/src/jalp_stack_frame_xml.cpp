/**
 * @file jalp_stack_frame_xml.cpp This file defines functions to deal with
 * converting stack frame structures to XML.
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

#include <inttypes.h>
#include <xercesc/dom/DOM.hpp>

#include <jalop/jalp_logger_metadata.h>
#include <jalop/jal_namespaces.h>
#include "jalp_stack_frame_xml.hpp"
#include "jal_asprintf_internal.h"

XERCES_CPP_NAMESPACE_USE
static const XMLCh JALP_XML_LINE_NUMBER[] = {
        chLatin_L, chLatin_i, chLatin_n, chLatin_e, chLatin_N, chLatin_u, chLatin_m, chLatin_b, chLatin_e, chLatin_r,
        chNull };
static const XMLCh JALP_XML_CLASS_NAME[] = {
        chLatin_C, chLatin_l, chLatin_a, chLatin_s, chLatin_s, chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };
static const XMLCh JALP_XML_FILE_NAME[] = {
        chLatin_F, chLatin_i, chLatin_l, chLatin_e, chLatin_N, chLatin_a, chLatin_m, chLatin_e, chNull };
static const XMLCh JALP_XML_DEPTH[] = {
        chLatin_D, chLatin_e, chLatin_p, chLatin_t, chLatin_h, chNull };
static const XMLCh JALP_XML_METHOD_NAME[] = {
        chLatin_M, chLatin_e, chLatin_t, chLatin_h, chLatin_o, chLatin_d, chLatin_N, chLatin_a, chLatin_m, chLatin_e,
        chNull };
static const XMLCh JALP_XML_CALLER_NAME[] = {
        chLatin_C, chLatin_a, chLatin_l, chLatin_l, chLatin_e, chLatin_r, chLatin_N, chLatin_a, chLatin_m, chLatin_e,
        chNull };
static const XMLCh JALP_XML_STACK_FRAME[] = {
        chLatin_S, chLatin_t, chLatin_a, chLatin_c, chLatin_k, chLatin_F, chLatin_r, chLatin_a, chLatin_m, chLatin_e,
        chNull };

enum jal_status jalp_stack_frame_to_elem(const struct jalp_stack_frame *stack_frame, DOMDocument *doc, DOMElement **new_elem)
{
	if (!stack_frame || !doc || !new_elem || *new_elem) {
		return JAL_E_XML_CONVERSION;
	}
	XMLCh *namespace_uri = XMLString::transcode(JAL_APP_META_TYPES_NAMESPACE_URI);
	DOMElement *stack_frame_element = doc->createElementNS(namespace_uri, JALP_XML_STACK_FRAME);
	if (stack_frame->caller_name) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_CALLER_NAME);
		stack_frame_element->appendChild(tmp);
		XMLCh *xml_caller_name = XMLString::transcode(stack_frame->caller_name);
		tmp->setTextContent(xml_caller_name);
		XMLString::release(&xml_caller_name);
	}
	if (stack_frame->file_name) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_FILE_NAME);
		stack_frame_element->appendChild(tmp);
		XMLCh *xml_file_name = XMLString::transcode(stack_frame->file_name);
		tmp->setTextContent(xml_file_name);
		XMLString::release(&xml_file_name);
	}
	if (stack_frame->line_number != 0) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_LINE_NUMBER);
		stack_frame_element->appendChild(tmp);
		char *c_line_number = NULL;
		jal_asprintf(&c_line_number,  "%" PRIu64, stack_frame->line_number);
		XMLCh *xml_line_number = XMLString::transcode(c_line_number);
		tmp->setTextContent(xml_line_number);
		XMLString::release(&xml_line_number);
		free(c_line_number);
	}
	if (stack_frame->class_name) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_CLASS_NAME);
		stack_frame_element->appendChild(tmp);
		XMLCh *xml_class_name = XMLString::transcode(stack_frame->class_name);
		tmp->setTextContent(xml_class_name);
		XMLString::release(&xml_class_name);
	}
	if (stack_frame->method_name) {
		DOMElement *tmp = doc->createElementNS(namespace_uri, JALP_XML_METHOD_NAME);
		stack_frame_element->appendChild(tmp);
		XMLCh *xml_method_name = XMLString::transcode(stack_frame->method_name);
		tmp->setTextContent(xml_method_name);
		XMLString::release(&xml_method_name);
	}
	if (stack_frame->depth >= 0) {
		char *c_depth = NULL;
		jal_asprintf(&c_depth, "%d", stack_frame->depth);
		XMLCh *xml_depth = XMLString::transcode(c_depth);
		stack_frame_element->setAttribute(JALP_XML_DEPTH, xml_depth);
		free(c_depth);
		XMLString::release(&xml_depth);
	}
	XMLString::release(&namespace_uri);
	*new_elem = stack_frame_element;
	return JAL_OK;
}
