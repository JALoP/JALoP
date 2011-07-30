/**
 * @file jaldb_xml_doc_storage.hpp This file defines a back-end helper
 * function for the storage of data in the appropriate Berkeley DB XML document
 * containers.
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

#ifndef _JALDB_XML_DOC_STORAGE_HPP_
#define _JALDB_XML_DOC_STORAGE_HPP_

#include "jaldb_context.hpp"

/**
 * Stores system metadata, application metadata, and audit records in the
 * appropriate Berkeley DB XML document containers.
 * @param[in] buf The data (XML document) to store.
 * @param[in] buf_size The size (in bytes) of the data to store.
 * @param[in] container The path of the container to which to store the data.
 * @param[in] mgr The DB XML manager that handles storing of the data.
 */
void jaldb_store_data(
	uint8_t *buf,
	size_t buf_size,
	const char *container,
	XmlManager *mgr);

#endif // _JALDB_XML_DOC_STORAGE_HPP_
