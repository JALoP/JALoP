/**
 * @file jalp_xml_validate.h 
 *
 * @section LICENSE
 *
 * Copyright (C) 2022 The National Security Agency (NSA)
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
#ifndef JALXMLVALIDATE_H
#define JALXMLVALIDATE_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <libxml/xmlschemastypes.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

#include <jalop/jal_status.h>
#include "jalp_context_internal.h"

// function to validate an XML document against a specific schema
enum jal_status jalp_validate_xml(
	jalp_context *jalp_ctx, 
	xmlDocPtr doc, 
	const char *xsdFileName);

#endif
