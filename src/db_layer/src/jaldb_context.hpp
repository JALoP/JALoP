/**
 * @file jaldb_context.hpp This file provides the DB context structure and
 * constants for use by the DB Layer.
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

#ifndef _JALDB_CONTEXT_HPP_
#define _JALDB_CONTEXT_HPP_

#include <dbxml/DbXml.hpp>
#include "jaldb_context.h"
#include <xercesc/dom/DOMDocument.hpp>

using namespace DbXml;

struct jaldb_context_t {
	XmlManager *manager; //<! The manager associated with the context.
	char *journal_root; //<! The journal record root path.
	char *schemas_root; //<! The schemas root path.
};

#endif // _JALDB_CONTEXT_HPP_
