/**
 * @file jal_namespaces.h This file defines namespace uri's for use by jal
 * xml document functions.
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
#ifndef _JAL_NAMESPACES_H_
#define _JAL_NAMESPACES_H_

#ifdef __cplusplus
extern "C" {
#endif

#define JAL_APP_META_NAMESPACE_URI "http://www.dod.mil/jalop-1.0/applicationMetadata"
#define JAL_APP_META_TYPES_NAMESPACE_URI "http://www.dod.mil/jalop-1.0/applicationMetadataTypes"
#define JAL_XMLDSIG_URI "http://www.w3.org/2000/09/xmldsig#"
#define JAL_SYS_META_NAMESPACE_URI "http://www.dod.mil/jalop-1.0/systemMetadata"
#define JAL_PAYLOAD_URI "jalop:payload"

#ifdef __cplusplus
}
#endif

#endif //_JAL_NAMESPACES_H_
