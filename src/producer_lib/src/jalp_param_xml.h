 /**
 * @file jalp_param_xml.h This file defines functions to handle
 * converting param list metadata to XML.
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
#ifndef _JALP_PARAM_XML_H_
#define _JALP_PARAM_XML_H_

#include <libxml/tree.h>

#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>

/**
 * Convert a jalp_param struct to a xmlDocPtr element for use with
 * the LibXml2 library.
 *
 * @param[in] param The jalp_param struct to convert.
 * @param[in] elem_name The name of the created element.
 * @param[in] attr_name The attribute name of the created element.
 * @param[in] parent The xmlNodePtr to create the xmlNodePtr as a child of. Maintains the same namespace.
 * @param[out] elem The xmlNodePtr that holds the newly created element.
 * 
 * @return JAL_OK on success, JAL_E_INVAL_PARAM if the param's key is not defined, and 
 * JAL_E_XML_CONVERSION otherwise.
 */
enum jal_status jalp_param_to_elem(const struct jalp_param *param,
				const xmlChar *elem_name,
				const xmlChar *attr_name,
				xmlNodePtr parent,
				xmlNodePtr *elem);

#endif //_JALP_PARAM_XML_H_
