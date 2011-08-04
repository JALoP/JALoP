/**
 * @file jaldb_serial_id.hpp This file deals with serial ids for the DB Layer.
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

#ifndef _JALDB_SERIAL_ID_HPP_
#define _JALDB_SERIAL_ID_HPP_

#include <dbxml/DbXml.hpp>
#include <string>

#include "jaldb_status.h"
/**
 * Obtain the next serial ID from a container and update the value in the
 * database.
 *
 * @param[in] txn A transaction to associate with the modification.
 * @param[in] uc The update context to use.
 * @param[in] container The container that tracks the serial ID. It must have a
 * document name JALDB_SERIAL_ID_DOC_NAME.
 * @param[out] sid On success, this will contain the next serial ID.
 * @return
 *  - JALDB_OK on success
 *  - JALDB_E_CORRUPTED if there is a problem in the database.
 *
 * This function does not perform any exception handling. The caller must
 * handle exceptions as appropriate.
 */
enum jaldb_status jaldb_get_next_serial_id(DbXml::XmlTransaction &txn,
		DbXml::XmlUpdateContext &uc,
		DbXml::XmlContainer &container,
		std::string &sid);

/**
 * Internal helper function that increments a serial ID.
 * @param sid[in,out] The serial ID to increment;
 */
void jaldb_increment_serial_id(std::string &sid);

#endif // _JALDB_SERIAL_ID_HPP_
