/**
 * @file jalls_xml_utils.hpp This file contains functions to parse and
 * validate xml for the jalop local store.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#ifndef _JALLS_XML_UTILS_HPP_
#define _JALLS_XML_UTILS_HPP_

#define JALLS_XML_APP_META_SCHEMA "applicationMetadata.xsd"
#define JALLS_XML_APP_META_TYPES_SCHEMA "applicationMetadataTypes.xsd"
#define JALLS_XML_SYS_META_SCHEMA "systemMetadata.xsd"
#define JALLS_XML_DSIG_SCHEMA  "xmldsig-core-schema.xsd"
#define JALLS_XML_SCHEMA_DTD "XMLSchema.dtd"
#define JALLS_XML_AUDIT_SCHEMA "cee-cls-xml-event.xsd"

#include <openssl/pem.h>

#include <jalop/jal_status.h>

/**
 * Helper function to create a properly formatted XML DateTime timestamp.
 *
 * @return formatted timestamp string
 */
char *jalls_get_timestamp();

#endif //_JALLS_XML_UTILS_HPP_
