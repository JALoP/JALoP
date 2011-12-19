/**
 * @file jalls_system_metadata_xml.hpp This file defines functions to deal with
 * creating system metadata DOMDocuments.
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

#ifndef _JSUB_SYSTEM_METADATA_XML_HPP_
#define _JSUB_SYSTEM_METADATA_XML_HPP_

#include <xercesc/dom/DOM.hpp>
#include <openssl/pem.h>
#include <uuid/uuid.h>

#ifdef __HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include <unistd.h>

#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>

//#include "jalls_handler.h"

XERCES_CPP_NAMESPACE_USE

//#ifdef __cplusplus
//extern "C" {
//#endif


enum jsub_data_type {
        JSUB_JOURNAL,
        JSUB_AUDIT,
        JSUB_LOG,
};

/**
 * Create a system metadata DOMElement for use with the jal local store, in accordance with
 * the JALRecordType xml schema.
 *
 * Will generate the timestamp, and use the given key and cert to generate a signature.
 *
 * @param[in] data_type the type of record sent.
 * @param[in] record_id The JAL Record ID.
 * @param[in] hostname The machine that generated the JAL data.
 * @param[in] host_uuid A UUID associated with the host.
 * @param[in] app_pid The process ID of the application that submitted the JAL data to the JAL local store.
 * @param[in] user_fd The fd for the application that created that submitted the JAL data.
 * @param[in] key The private key to use in signing the document.
 * @param[in] cert The public cert to use in signing the document.
 * @param[out] A pointer to hold the created DOMDocument.
 *
 * @return -1 on failure, 0 on success.
 */
int jsub_create_system_metadata(enum jsub_data_type data_type, const char *hostname, const char *host_uuid,
	int user_fd, pid_t app_pid, uid_t app_uid, DOMDocument **doc);

//#ifdef __cplusplus
//}
//#endif

#endif //_JSUB_SYSTEM_METADATA_XML_HPP_
