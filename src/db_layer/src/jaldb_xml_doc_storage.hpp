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

#include <xercesc/dom/DOMDocument.hpp>
#include <dbxml/XmlManager.hpp>
#include <dbxml/XmlContainer.hpp>
#include <dbxml/XmlTransaction.hpp>

#include "jaldb_status.h"

/**
 * Stores system metadata, application metadata, and audit records in the
 * appropriate Berkeley DB XML document containers.
 * @param[in] txn An object used for transaction protection.
 * @param[in] uc The update context to use
 * @param[in] container The container to which to store the data.
 * @param[in] doc The DbXml Document to associate with. Any metadata should
 * @param[in] doc_name The name to use for the document
 * @param[in] dom_doc The document containing the data.
 *
 * @return
 *  - JALDB_OK if the function succeeds or a JAL error code if the function
 * fails.
 */
enum jaldb_status jaldb_put_document_as_dom(
	DbXml::XmlTransaction &txn,
	DbXml::XmlUpdateContext &uc,
	DbXml::XmlContainer &container,
	DbXml::XmlDocument &doc,
	std::string &doc_name,
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *dom_doc);

#endif // _JALDB_XML_DOC_STORAGE_HPP_
