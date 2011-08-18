/**
 * @file jaldb_xml_doc_storage.cpp This file implements a back-end helper function
 * for the storage of data in appropriate Berkeley DB XML document containers
 * (for system metadata, application metadata, and audit records).
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

#include "jaldb_dom_to_event_writer.hpp"
#include "jaldb_xml_doc_storage.hpp"
#include <dbxml/XmlDocument.hpp>

using namespace std;
using namespace DbXml;
XERCES_CPP_NAMESPACE_USE

enum jaldb_status jaldb_put_document_as_dom(
	XmlTransaction &txn,
	XmlUpdateContext &uc,
	XmlContainer &container,
	XmlDocument &doc,
	std::string &doc_name,
	const DOMDocument *dom_doc)
{
	if (doc_name.length() == 0 || !dom_doc) {
		return JALDB_E_INVAL;
	}

	doc.setName(doc_name);
	XmlEventWriter &writer = container.putDocumentAsEventWriter(
		txn, doc, uc, 0);

	DOMToEventWriter dom_to_event_writer(writer, dom_doc);
	dom_to_event_writer.start();

	return JALDB_OK;
}
