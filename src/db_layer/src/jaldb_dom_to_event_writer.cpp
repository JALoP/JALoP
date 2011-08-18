/**
 * @file jaldb_dom_to_event_writer.cpp This file implements a class which walks a
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

#include <sstream>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/util/XMLException.hpp>
#include <xercesc/util/XMLUni.hpp>
#include <xercesc/framework/MemBufFormatTarget.hpp>
#include "jaldb_dom_to_event_writer.hpp"

XERCES_CPP_NAMESPACE_USE
using namespace std;
using namespace DbXml;

/**
 * Helper class for converting XMLCh strings for use by DbXml
 */
class FromXmlCh
{
public:
	FromXmlCh(const XMLCh *src)
	{
		if (src && *src) {
			string = XMLString::transcode(src);
		}
		else {
			string = NULL;
		}
	}

	~FromXmlCh()
	{
		XMLString::release(&string);
	}

	const unsigned char *str() const
	{
		return (const unsigned char *)(string);
	}
	operator const unsigned char *() {
		return str();
	}
private:
	char *string;
};

DOMToEventWriter::DOMToEventWriter(XmlEventWriter &a_writer, const DOMDocument *a_doc):
	writer(a_writer),
	doc(a_doc)
{
	// do nothing
}

DOMToEventWriter::~DOMToEventWriter()
{
	writer.close();
}

void DOMToEventWriter::start()
{
	if (!doc) {
		return;
	}

	const DOMNode *cur = doc;
	bool opening_nodes = true;
	while (cur != NULL) {
		if (opening_nodes) {
			if (open_node(cur)) {
				cur = cur->getFirstChild();
				continue;
			}
		} else {
			close_node(cur);
		}
		if (cur->getNextSibling()) {
			cur = cur->getNextSibling();
			opening_nodes = true;
			continue;
		}
		opening_nodes = false;
		cur = cur->getParentNode();
	}
}

bool DOMToEventWriter::open_node(const DOMNode *node)
{
	bool has_children = false;
	switch (node->getNodeType()) {
	case DOMNode::DOCUMENT_NODE:
		has_children = node->hasChildNodes();
		writer.writeStartDocument(
			(const unsigned char *)"1.0",
			(const unsigned char *)"UTF-8",
			(const unsigned char *)"no");
		break;
	case DOMNode::ELEMENT_NODE: {
		has_children = node->hasChildNodes();
		DOMNamedNodeMap *attrs = node->getAttributes();
		if (node->getLocalName()) {
			writer.writeStartElement(
				FromXmlCh(node->getLocalName()),
				FromXmlCh(node->getPrefix()),
				FromXmlCh(node->getNamespaceURI()),
				attrs->getLength(),
				!has_children);
		} else {
			writer.writeStartElement(
				FromXmlCh(node->getNodeName()),
				FromXmlCh(node->getPrefix()),
				FromXmlCh(node->getNamespaceURI()),
				attrs->getLength(),
				!has_children);
		}
		for(unsigned int i = 0; i < attrs->getLength(); ++i) {
			DOMNode *attr = attrs->item(i);
			if (attr->getLocalName()) {
				writer.writeAttribute(
					FromXmlCh(attr->getLocalName()),
					FromXmlCh(attr->getPrefix()),
					FromXmlCh(attr->getNamespaceURI()),
					FromXmlCh(attr->getNodeValue()),
					true);
			} else {
				writer.writeAttribute(
					FromXmlCh(attr->getNodeName()),
					FromXmlCh(attr->getPrefix()),
					FromXmlCh(attr->getNamespaceURI()),
					FromXmlCh(attr->getNodeValue()),
					true);
			}
		}
		break;
	}
	case DOMNode::TEXT_NODE:
		writer.writeText(
			XmlEventReader::Characters,
			FromXmlCh(node->getNodeValue()).str(),
			0);
		break;
	case DOMNode::CDATA_SECTION_NODE:
		writer.writeText(
			XmlEventReader::CDATA,
			FromXmlCh(node->getNodeValue()).str(),
			0);
		break;
	case DOMNode::COMMENT_NODE:
		writer.writeText(
			XmlEventReader::Comment,
			FromXmlCh(node->getNodeValue()),
			0);
		break;
	case DOMNode::PROCESSING_INSTRUCTION_NODE:
		writer.writeProcessingInstruction(
			FromXmlCh(node->getNodeName()),
			FromXmlCh(node->getNodeValue()));
		break;
	case DOMNode::DOCUMENT_TYPE_NODE: {
		ostringstream os;
		const DOMDocumentType *dtd = dynamic_cast<const DOMDocumentType*>(node);
		os << "<!DOCTYPE " << FromXmlCh(dtd->getName());
		if (dtd->getPublicId()) {
			os << " PUBLIC \"" << FromXmlCh(dtd->getPublicId()) << '"';
		}
		if (dtd->getSystemId()) {
			os << " SYSTEM \"" << FromXmlCh(dtd->getSystemId()) << '"';
		}
		if (dtd->getInternalSubset()) {
			os << " [" << FromXmlCh(dtd->getInternalSubset()) << "]";
		}
		os << ">";
		writer.writeDTD((const unsigned char*) os.str().c_str(), os.str().length());
		break;
	}
	case DOMNode::ENTITY_REFERENCE_NODE: {
		// Entity references do not get visiting again when heading
		// back up the tree, so must write the end portion here
		FromXmlCh name(node->getNodeName());
		writer.writeStartEntity(name, false);
		writer.writeEndEntity(name);
		break;
	}
	case DOMNode::ATTRIBUTE_NODE:
	// fall through attributes are handled directly by the DOMElement they
	// belong to.
	default:
		DOMNode::NodeType nt = node->getNodeType();
		throw(nt);
	}
	return has_children;
}

void DOMToEventWriter::close_node(const DOMNode *node)
{
	switch (node->getNodeType()) {
	case DOMNode::DOCUMENT_NODE:
		writer.writeEndDocument();
		break;
	case DOMNode::ELEMENT_NODE:
		if (node->hasChildNodes()) {
			writer.writeEndElement(
				FromXmlCh(node->getLocalName()),
				FromXmlCh(node->getPrefix()),
				FromXmlCh(node->getNamespaceURI()));
		}
		break;
	case DOMNode::TEXT_NODE:
	case DOMNode::CDATA_SECTION_NODE:
	case DOMNode::COMMENT_NODE:
	case DOMNode::PROCESSING_INSTRUCTION_NODE:
	case DOMNode::ENTITY_REFERENCE_NODE:
		break;
	case DOMNode::ATTRIBUTE_NODE:
		// attributes are handled
	default:
		throw("Hierarchy Exception for close");
		break;
	}
}

