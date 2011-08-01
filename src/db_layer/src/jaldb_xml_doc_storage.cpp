/**
 * @file jaldb_xml_doc_storage.cpp This file implements a back-end helper
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

#include <sstream>
#include "jaldb_context.hpp"
#include "jaldb_xml_doc_storage.hpp"

using namespace std;

void jaldb_store_data(
	uint8_t *buf,
	size_t buf_size,
	const char *container,
	XmlManager *mgr)
{
	try {
		string contPath = container;

		XmlContainer cont;

		if (!mgr->existsContainer(contPath)) {
			cont = mgr->createContainer(contPath);
		}
		else {
			cont = mgr->openContainer(contPath);
		}

		size_t numberOfDocs = cont.getNumDocuments();

		numberOfDocs++;

		stringstream ss;
		ss << (int)(numberOfDocs);
		string serialId = ss.str();

		XmlUpdateContext uc = mgr->createUpdateContext();

		string buffer = (char *)(buf);

		cont.putDocument(serialId, buffer, uc);
	}
	catch (XmlException &e) {
		cout << "Exception: " << e.what() << endl;
	}
}
