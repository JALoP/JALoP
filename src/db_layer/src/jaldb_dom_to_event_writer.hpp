/**
 * @file jaldb_dom_to_event_writer.hpp This file defines a class which walks a
 * Xerces-C DOMDocument, pushing events to XmlEventWriter in order to construct
 * a document.
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

#ifndef _JALDB_DOM_TO_EVENT_WRITER_HPP_
#define _JALDB_DOM_TO_EVENT_WRITER_HPP_

#include <xercesc/dom/DOMDocument.hpp>
#include <dbxml/XmlEventWriter.hpp>

class DOMToEventWriter
{
public:
	DOMToEventWriter(DbXml::XmlEventWriter &writer, const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *dom_doc);
	~DOMToEventWriter();
	void start();
private:
	/**
	 * Call the appropriate functions the writer to begin a particular
	 * node.
	 *
	 * For DOMElement nodes, this will also write out all the attributes.
	 *
	 * @param [in] node The node to output.
	 *
	 * @return true if the node has children, false otherwise.
	 */
	bool open_node(const XERCES_CPP_NAMESPACE_QUALIFIER DOMNode *node);
	/**
	 * Call the appropriate functions on the writer to write the end of a
	 * particular node
	 *
	 * @param [in] node The node to output.
	 */
	void close_node(const XERCES_CPP_NAMESPACE_QUALIFIER DOMNode *node);

	DbXml::XmlEventWriter &writer;
	const XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *doc;
};

#endif // _JALDB_DOM_TO_EVENT_WRITER_HPP_
