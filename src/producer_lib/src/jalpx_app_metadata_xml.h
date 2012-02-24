/**
 * @file jalpx_app_metadata_xml.h This file defines functions to deal with
 * converting jalp_app_metadata to a DOMDocument.
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

#ifndef _JALPX_APP_METADATA_XML_H_
#define _JALPX_APP_METADATA_XML_H_

#include <libxml/tree.h>

#include <jalop/jalp_app_metadata.h>
#include <jalop/jal_status.h>
#include "jalp_context_internal.h"

/**
 * Convert jalp_app_metadata struct into a Xerces DOMDocument
 *
 * @param[in] app_meta The struct to convert
 * @param[in] ctx The jalp_context
 * @param[in] doc A pointer to the DOMDocument to use in creating the element
 * @param[out] elem A pointer to hold the created element. Should point to NULL.
 * @return JAL_OK on success, JAL_E_XML_CONVERSION on failure.
 * will also return JAL_E_INVAL_APP_METADATA if given an invalid jalp_app_metadata as input.
*/
enum jal_status jalpx_app_metadata_to_elem(
		struct jalp_app_metadata *app_meta,
		const struct jalp_context_t *ctx,
		xmlDocPtr doc,
		xmlNodePtr *elem);

#endif //_JALPX_APP_METADATA_XML_H_
