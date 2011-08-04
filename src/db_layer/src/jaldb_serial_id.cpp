/**
 * @file jaldb_serial_id.cpp Implementation of utilties dealing with serial ids.
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

#include "jaldb_serial_id.hpp"
#include "jaldb_strings.h"
#include <dbxml/XmlContainer.hpp>
#include <dbxml/XmlTransaction.hpp>
#include <dbxml/XmlValue.hpp>
#include <cstring>

using namespace std;
using namespace DbXml;

enum jaldb_status jaldb_get_next_serial_id(XmlTransaction &txn, XmlUpdateContext &uc,
		XmlContainer &container, string &sid)
{
	XmlManager manager =  container.getManager();
	XmlDocument serial_doc =
		container.getDocument(txn, JALDB_SERIAL_ID_DOC_NAME, DB_RMW);
	XmlValue val;
	// assume the 'next' serial ID always exists in the database.
	if (serial_doc.getMetaData(JALDB_NS, JALDB_SERIAL_ID_NAME, val)) {
		if (val.getType() != XmlValue::STRING) {
			return JALDB_E_CORRUPTED;
		}
		string val_str = val.asString();
		jaldb_increment_serial_id(val_str);
		XmlValue new_val(XmlValue::STRING, val_str);
		serial_doc.setMetaData(JALDB_NS, JALDB_SERIAL_ID_NAME, new_val);
		container.updateDocument(txn, serial_doc, uc);
		sid = val.asString();
		return JALDB_OK;
	}
	return JALDB_E_CORRUPTED;
}
void jaldb_increment_serial_id(string &sid)
{
	int inc = 1;
	int idx;
	for (idx = sid.length() - 1; (inc == 1 && idx >= 0); idx--) {
		inc = 0;
		switch (sid[idx]) {
		case '9':
			sid[idx] = 'A';
			break;
		case 'Z':
			sid[idx] = 'a';
			break;
		case 'z':
			sid[idx] = '0';
			inc = 1;
			break;
		default:
			sid[idx] += 1;
		}
	}
	if (inc) {
		sid.insert(0, 1, '1');
	}
}
