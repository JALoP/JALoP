/**
 * @file jalp_stack_frame_xml.c This file defines functions to deal with
 * converting stack frame structures to XML.
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

#include <inttypes.h>
#include <libxml/tree.h>

#include <jalop/jalp_logger_metadata.h>
#include <jalop/jal_namespaces.h>
#include "jalp_stack_frame_xml.h"
#include "jal_asprintf_internal.h"

#define JALP_XML_LINE_NUMBER "LineNumber"
#define JALP_XML_CLASS_NAME "ClassName"
#define JALP_XML_FILE_NAME "FileName"
#define JALP_XML_DEPTH "Depth"
#define JALP_XML_METHOD_NAME "MethodName"
#define JALP_XML_CALLER_NAME "CallerName"
#define JALP_XML_STACK_FRAME "StackFrame"

enum jal_status jalp_stack_frame_to_elem(
		const struct jalp_stack_frame *stack_frame,
		xmlNodePtr parent,
		xmlNodePtr *new_elem)
{
	if (!stack_frame || !parent || *new_elem) {
		return JAL_E_XML_CONVERSION;
	}
	xmlNodePtr stack_frame_element = xmlNewChild(parent, NULL,
							(xmlChar *)JALP_XML_STACK_FRAME,
							NULL);

	if (stack_frame->caller_name) {
		xmlNewChild(stack_frame_element, NULL,
				(xmlChar *)JALP_XML_CALLER_NAME,
				(xmlChar *)stack_frame->caller_name);
	}
	if (stack_frame->file_name) {
		xmlNewChild(stack_frame_element, NULL,
				(xmlChar *)JALP_XML_FILE_NAME,
				(xmlChar *)stack_frame->file_name);
	}
	if (stack_frame->line_number != 0) {
		char *c_line_number = NULL;
		jal_asprintf(&c_line_number,  "%" PRIu64, stack_frame->line_number);

		xmlNewChild(stack_frame_element, NULL,
				(xmlChar *)JALP_XML_LINE_NUMBER,
				(xmlChar *)c_line_number);

		free(c_line_number);
	}
	if (stack_frame->class_name) {
		xmlNewChild(stack_frame_element, NULL,
				(xmlChar *)JALP_XML_CLASS_NAME,
				(xmlChar *)stack_frame->class_name);
	}
	if (stack_frame->method_name) {
		xmlNewChild(stack_frame_element, NULL,
				(xmlChar *)JALP_XML_METHOD_NAME,
				(xmlChar *)stack_frame->method_name);
	}
	if (stack_frame->depth >= 0) {
		char *c_depth = NULL;
		jal_asprintf(&c_depth, "%d", stack_frame->depth);
		xmlChar *xml_depth = (xmlChar *)c_depth;
		xmlSetProp(stack_frame_element, (xmlChar *)JALP_XML_DEPTH, xml_depth);
		free(c_depth);
	}
	*new_elem = stack_frame_element;
	return JAL_OK;
}

