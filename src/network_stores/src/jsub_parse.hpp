/**
 * @file jsub_parse.hpp This file contains functions to parse and
 * validate xml for the jalop local store.
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

#ifndef _JSUB_PARSE_HPP_
#define _JSUB_PARSE_HPP_

#define JAL_XML_APP_META_SCHEMA "applicationMetadata.xsd"
#define JAL_XML_APP_META_TYPES_SCHEMA "applicationMetadataTypes.xsd"
#define JAL_XML_SYS_META_SCHEMA "systemMetadata.xsd"
#define JAL_XML_DSIG_SCHEMA  "xmldsig-core-schema.xsd"
#define JAL_XML_SCHEMA_DTD "XMLSchema.dtd"
#define JAL_XML_AUDIT_SCHEMA "cee-cls-xml-event.xsd"

#include <xercesc/dom/DOM.hpp>
#include <openssl/pem.h>

XERCES_CPP_NAMESPACE_USE

/**
 * parse and validate the application metadata
 *
 * @param[in] buf A buffer containing the xml data to parse
 * @param[in] size The size of the buffer
 * @param[in] schemas_root The root path where the schemas are located
 * @param[out] doc A pointer to hold the parsed document
 * @param[in] debug A flag for printing debug messages
 */
int jsub_parse_app_metadata(void *buf, size_t size, char* schemas_root, DOMDocument **doc, int debug);

/**
 * parse and validate the audit_data
 *
 * @param[in] buf A buffer containing the xml data to parse
 * @param[in] size The size of the buffer
 * @param[in] schemas_root The root path where the schemas are located
 * @param[out] doc A pointer to hold the parsed document
 * @param[in] debug A flag for printing debug messages
 */
int jsub_parse_audit(void *buf, size_t size, char *schemas_root, DOMDocument **doc, int debug);

/**
 * parse and validate the audit_data
 *
 * @param[in] buf A buffer containing the xml data to parse
 * @param[in] size The size of the buffer
 * @param[in] schemas_root The root path where the schemas are located
 * @param[out] doc A pointer to hold the parsed document
 * @param[in] debug A flag for printing debug messages
 */
int jsub_parse_sys_metadata(void *buf, size_t size, char *schemas_root, DOMDocument **doc, int debug);

/**
* Prints a DOMDocument \p doc to a file as indicated by \p file_path.
*
* @param[in] doc The document to write to file \p file_path.
* @param[in] file_path The path to the file to create.
*/
void jsub_doc_to_file(DOMDocument *doc, char *file_path);

/**
* Constructs the full path using the schema root and schema file name.
*
* @param[out] dest The full path to the schema file
* @param[in] schemas_root The root path where the schemas are located
* @param[in] schema The name of the schema file
*/
void jsub_get_schema_path(
		char **dest,
		const char *schemas_root,
		const char *schema);

#endif //_JSUB_PARSE_HPP_

