/**
 * @file test_jaldb_dom_to_event_writer.cpp This file contains a function to
 * test the class which walks a Xerces-C DOMDocument and pushes events to
 * XmlEventWriter in order to construct a document.
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

// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// C++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif

extern "C" {
#include <test-dept.h>
}

#include <dirent.h>
#include <db.h>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/util/PanicHandler.hpp>
#include "xml_test_utils.hpp"
#include "jaldb_context.h"
#include "jaldb_context.hpp"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "jaldb_xml_doc_storage.hpp"
XERCES_CPP_NAMESPACE_USE

#define OTHER_DB_ROOT "./testdb/"
#define OTHER_SCHEMAS_ROOT "./schemas/"
#define VALID_TEST_XML_DOC "./test-input/domwriter.xml"
#define INVALID_TEST_XML_DOC "./test-input/invalid_input.xml"
#define EMPTY_TEST_XML_DOC "./test-input/no_input.xml"

using namespace DbXml;

class MyHandler: public PanicHandler
{
	__attribute__((noreturn)) void panic(xercesc_3_1::PanicHandler::PanicReasons)
	{
		abort();
	}
};

class ErrorHandler: public DOMErrorHandler
{
public:
	ErrorHandler()
	:
	failed(false)
	{
	}
	virtual bool handleError(const DOMError &e)
	{
		bool failure = !(e.getSeverity() == DOMError::DOM_SEVERITY_WARNING);
		if (failure) {
			failed = true;
		}
		char *msg = XMLString::transcode(e.getMessage());
		XMLString::release(&msg);
		return !failed;
	}
	bool failed;
};

static DOMDocument *dom_doc = NULL;
static DOMLSParser *parser = NULL;
static DOMImplementation *impl = NULL;
static DOMConfiguration *config = NULL;
static ErrorHandler err_handler;
jaldb_context *context = NULL;

extern "C" void setup()
{
	XMLPlatformUtils::Initialize();
	struct dirent *d;
	DIR *dir;
	char buf[256];
	dir = opendir(OTHER_DB_ROOT);
	while ((d = readdir(dir)) != NULL) {
		sprintf(buf, "%s/%s", OTHER_DB_ROOT, d->d_name);
		remove(buf);
	}
	int ret_val;
	ret_val = closedir(dir);
	impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	parser = impl->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	config = parser->getDomConfig();
	config->setParameter(XMLUni::fgDOMDatatypeNormalization, true);
	config->setParameter(XMLUni::fgDOMErrorHandler, &err_handler);
	config->setParameter(XMLUni::fgDOMEntities, true);
	config->setParameter(XMLUni::fgDOMNamespaces, true);
	config->setParameter(XMLUni::fgDOMValidate, false);
	config->setParameter(XMLUni::fgXercesSchema, false);
	config->setParameter(XMLUni::fgXercesSchemaFullChecking, false);
	config->setParameter(XMLUni::fgXercesUseCachedGrammarInParse, true);
	config->setParameter(XMLUni::fgXercesCacheGrammarFromParse, false);
	config->setParameter(XMLUni::fgXercesLoadSchema, false);
	config->setParameter(XMLUni::fgXercesHandleMultipleImports, true);
	config->setParameter(XMLUni::fgXercesUserAdoptsDOMDocument, false);
	context = jaldb_context_create();
	jaldb_context_init(context, OTHER_DB_ROOT, OTHER_SCHEMAS_ROOT, 1);
}

extern "C" void teardown()
{
	dom_doc = NULL;
	parser = NULL;
	impl = NULL;
	config = NULL;
	jaldb_context_destroy(&context);
	XMLPlatformUtils::Terminate();
}

extern "C" void test_error_handler_does_not_fail()
{
	assert_true(!err_handler.failed);
}

extern "C" void test_dom_to_event_writer_inserts_dom_doc()
{
	dom_doc = parser->parseURI(VALID_TEST_XML_DOC);
	assert_true(dom_doc != NULL);

	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext update_ctx = context->manager->createUpdateContext();
	XmlContainer cont = *(context->audit_sys_cont);
	XmlDocument document = context->manager->createDocument();
	std::string doc_name("doc_name");
	enum jaldb_status ret;
	ret = jaldb_put_document_as_dom(txn, update_ctx, cont, document, doc_name, dom_doc);
	txn.commit();
	assert_equals(JALDB_OK, ret);
}

extern "C" void test_put_document_as_dom_fails_with_invalid_document()
{
	enum jaldb_status ret = JALDB_E_INVAL;
	XmlTransaction txn = context->manager->createTransaction();
	try {
		dom_doc = parser->parseURI(INVALID_TEST_XML_DOC);
		XmlUpdateContext update_ctx = context->manager->createUpdateContext();
		XmlContainer cont = *(context->audit_app_cont);
		XmlDocument document = context->manager->createDocument();
		std::string doc_name("doc_name");
		ret = jaldb_put_document_as_dom(
			txn, update_ctx, cont, document, doc_name, dom_doc);
		txn.commit();
	}
	catch (XmlException &e) {
		txn.abort();
		ret = JALDB_E_INVAL;
	}

	assert_equals(JALDB_OK, ret);
}

extern "C" void test_put_document_as_dom_fails_with_empty_document()
{
	enum jaldb_status ret = JALDB_E_INVAL;
	XmlTransaction txn = context->manager->createTransaction();
	try {
		dom_doc = parser->parseURI(EMPTY_TEST_XML_DOC);
		XmlUpdateContext update_ctx = context->manager->createUpdateContext();
		XmlContainer cont = *(context->audit_cont);
		XmlDocument document = context->manager->createDocument();
		std::string doc_name("doc_name");
		ret = jaldb_put_document_as_dom(
			txn, update_ctx, cont, document, doc_name, dom_doc);
		txn.commit();
	}
	catch (XmlException &e) {
		txn.abort();
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_put_document_as_dom_fails_with_invalid_input()
{
	dom_doc = parser->parseURI(VALID_TEST_XML_DOC);
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext update_ctx = context->manager->createUpdateContext();
	XmlContainer cont = *(context->audit_sys_cont);
	XmlDocument document = context->manager->createDocument();
	std::string doc_name("");
	enum jaldb_status ret;
	ret = jaldb_put_document_as_dom(txn, update_ctx, cont, document, doc_name, dom_doc);
	assert_equals(JALDB_E_INVAL, ret);

	doc_name = "doc_name";
	ret = jaldb_put_document_as_dom(txn, update_ctx, cont, document, doc_name, NULL);
	assert_equals(JALDB_E_INVAL, ret);
}
