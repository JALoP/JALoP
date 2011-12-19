/**
* @file test_jaldb_xml_doc_storage.cpp This file contains a function to
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

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/PlatformUtils.hpp>
#include <dbxml/XmlDocument.hpp>
#include <dbxml/XmlContainer.hpp>
#include <dbxml/DbXml.hpp>
#include "xml_test_utils.hpp"
#include "jaldb_context.h"
#include "jaldb_context.hpp"
#include "jaldb_strings.h"
#include "jaldb_utils.h"
#include "jaldb_xml_doc_storage.hpp"

#define OTHER_DB_ROOT "./testdb/"
#define OTHER_SCHEMAS_ROOT "./schemas/"
#define TEST_XML_DOC "./test-input/domwriter.xml"
#define EMPTY_TEST_XML_DOC "./test-input/no_input.xml"

using namespace DbXml;
XERCES_CPP_NAMESPACE_USE

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
			return !failed;
		}
		bool failed;
};

static DOMLSParser *parser = NULL;
static DOMDocument *domdoc = NULL;
static ErrorHandler err_handler;
static jaldb_context *context = NULL;

void print_xml_exception(XmlException e);

extern "C" void setup()
{
	XMLPlatformUtils::Initialize();
	struct stat st;
	if (stat(OTHER_DB_ROOT, &st) != 0) {
		int status;
		status = mkdir(OTHER_DB_ROOT, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}
	else {
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
	}
	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	parser = impl->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	DOMConfiguration *config = parser->getDomConfig();
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
	jaldb_context_init(context, OTHER_DB_ROOT, OTHER_SCHEMAS_ROOT, 1, 0);
}

extern "C" void teardown()
{
	delete parser;
	parser = NULL;
	domdoc = NULL;
	jaldb_context_destroy(&context);
	XMLPlatformUtils::Terminate();
}

extern "C" void test_jaldb_get_document_works()
{
	// Insert a test document
	domdoc = parser->parseURI(TEST_XML_DOC);
	assert_true(domdoc != NULL);
	
	assert_false(err_handler.failed);
	
	XmlTransaction transaction = context->manager->createTransaction();
	XmlUpdateContext update_ctx = context->manager->createUpdateContext();
	XmlContainer cont = *(context->audit_sys_cont);
	XmlDocument document = context->manager->createDocument();
	std::string docname("docname");
	enum jaldb_status ret;
	ret = jaldb_put_document_as_dom(transaction, update_ctx, cont, document, docname, domdoc);
	transaction.commit();
	assert_equals(JALDB_OK, ret);

	// Retrieve the document
	XmlTransaction txn = context->manager->createTransaction();
	XmlDocument doc;
	ret = jaldb_get_document(txn, &cont, docname, &doc);
	assert_equals(JALDB_OK, ret);
	assert_equals(doc, document);
}

extern "C" void test_jaldb_get_document_fails_bad_input()
{
	enum jaldb_status ret;
	XmlTransaction txn = context->manager->createTransaction();
	XmlDocument doc = context->manager->createDocument();
	XmlContainer cont = *(context->audit_sys_cont);
	std::string docname("docname");
	std::string invalid_docname("");
	
	ret = jaldb_get_document(txn, &cont, docname, NULL);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_get_document(txn, NULL, docname, &doc);
	assert_equals(JALDB_E_INVAL, ret);

	ret = jaldb_get_document(txn, &cont, invalid_docname, &doc);
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_get_document_fails_doc_not_found()
{
	enum jaldb_status ret;
	XmlTransaction txn = context->manager->createTransaction();
	XmlDocument doc;
	XmlContainer cont = *(context->audit_sys_cont);
	std::string docname("DNE");
	try {
		ret = jaldb_get_document(txn, &cont, docname, &doc);
	} catch (XmlException &e) {
		ret = JALDB_E_INVAL;
	}
	
	assert_equals(JALDB_E_NOT_FOUND, ret);
}

extern "C" void test_jaldb_save_document_works()
{
	enum jaldb_status ret;
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlDocument docA = context->manager->createDocument();
	XmlDocument docB;
	XmlContainer cont = *(context->audit_sys_cont);
	std::string docname("test_save_doc_works");
	try {
		ret = jaldb_save_document(txn, uc, cont, docA, docname);
		txn.commit();
	} catch (XmlException &e) {
		txn.abort();
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);
	docB = cont.getDocument(docname);
	assert_equals(docA, docB);
}

extern "C" void test_jaldb_save_document_fails_bad_input()
{
	enum jaldb_status ret;
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlDocument docA = context->manager->createDocument();
	XmlContainer cont = *(context->audit_sys_cont);
	std::string docname("");
	try {
		ret = jaldb_save_document(txn, uc, cont, docA, docname);
		txn.commit();
	} catch (XmlException &e) {
		txn.abort();
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_E_INVAL, ret);
}

extern "C" void test_jaldb_save_document_fails_duplicate()
{
	enum jaldb_status ret;
	u_int32_t txnFlags = DB_READ_COMMITTED;
	XmlTransaction txn = context->manager->createTransaction(txnFlags);
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlDocument docA = context->manager->createDocument();
	XmlDocument docB = context->manager->createDocument();
	XmlContainer cont = *(context->audit_sys_cont);
	std::string docname("save_document_fails_duplicate");
	try {
		ret = jaldb_save_document(txn, uc, cont, docA, docname);
		txn.commit();
	} catch (XmlException &e) {
		txn.abort();
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);
	XmlTransaction txn2 = context->manager->createTransaction(txnFlags);
	try {
		ret = jaldb_save_document(txn2, uc, cont, docB, docname);
		txn2.commit();
	} catch (XmlException &e) {
		txn2.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_E_SID, ret);
}

extern "C" void test_jaldb_remove_document_works()
{
	// Insert a test document
	domdoc = parser->parseURI(TEST_XML_DOC);
	assert_true(domdoc != NULL);
	assert_false(err_handler.failed);

	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlContainer cont = *(context->audit_sys_cont);
	XmlDocument doc = context->manager->createDocument();
	XmlDocument docB;
	XmlDocument docC;
	std::string docname("test_remove_document_works");
	enum jaldb_status ret;
	ret = jaldb_put_document_as_dom(txn, uc,
			cont, doc, docname, domdoc);
	assert_equals(JALDB_OK, ret);
	
	docB = cont.getDocument(txn, docname, 0);
	try {
		//ret = jaldb_remove_document(txn, uc,
		//	cont, docB, docname);
		ret = jaldb_remove_document(txn, uc,
			cont, docname);
	} catch (XmlException &e) {
		txn.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_OK, ret);
	txn.commit();

	XmlTransaction txn2 = context->manager->createTransaction();
	try {
		docC = cont.getDocument(txn2, docname, 0);
		txn2.commit();
	} catch (XmlException &e){
		txn2.abort();
		if (e.getExceptionCode()
			== XmlException::DOCUMENT_NOT_FOUND) {
			ret = JALDB_E_NOT_FOUND;
		}
		else {
			ret = JALDB_E_INVAL;
		}
	}
	assert_equals(JALDB_E_NOT_FOUND, ret);
}

extern "C" void test_jaldb_remove_document_fails_bad_input()
{
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlContainer cont = *(context->audit_sys_cont);
	XmlDocument doc = context->manager->createDocument();
	std::string docname("");
	enum jaldb_status ret;
	//ret = jaldb_remove_document(txn, uc,
	//	cont, doc, docname);
	ret = jaldb_remove_document(txn, uc,
		cont, docname);
	assert_equals(JALDB_E_INVAL, ret);
	txn.commit();
}

extern "C" void test_jaldb_remove_document_fails_not_found()
{
	XmlTransaction txn = context->manager->createTransaction();
	XmlUpdateContext uc = context->manager->createUpdateContext();
	XmlContainer cont = *(context->audit_sys_cont);
	XmlDocument doc = context->manager->createDocument();
	std::string docname("doc_not_there");
	enum jaldb_status ret;
	try {
		//ret = jaldb_remove_document(txn, uc,
		//	cont, doc, docname);
		ret = jaldb_remove_document(txn, uc,
			cont, docname);
	} catch (XmlException &e) {
		txn.abort();
		print_xml_exception(e);
		ret = JALDB_E_INVAL;
	}
	assert_equals(JALDB_E_NOT_FOUND, ret);
	txn.commit();
}

// Use for debugging exceptions
void print_xml_exception(XmlException e)
{
	switch (e.getExceptionCode()) {
		case XmlException::DATABASE_ERROR:
			printf("DATABASE_ERROR\n");
			break;
		case XmlException::INDEXER_PARSER_ERROR:
			printf("INDEXER_PARSER_ERROR\n");
			break;
		case XmlException::UNIQUE_ERROR:
			printf("UNIQUE_ERROR\n");
			break;
		case XmlException::CONTAINER_CLOSED:
			printf("CONTAINER_CLOSED\n");
			break;
		case XmlException::CONTAINER_EXISTS:
			printf("CONTAINER_EXISTS\n");
			break;
		case XmlException::CONTAINER_NOT_FOUND:
			printf("CONTAINER_NOT_FOUND\n");
			break;
		case XmlException::CONTAINER_OPEN:
			printf("CONTAINER_OPEN\n");
			break;
		case XmlException::DOCUMENT_NOT_FOUND:
			printf("DOCUMENT_NOT_FOUND\n");
			break;
		case XmlException::EVENT_ERROR:
			printf("EVENT_ERROR\n");
			break;
		case XmlException::INTERNAL_ERROR:
			printf("INTERNAL_ERROR\n");
			break;
		case XmlException::INVALID_VALUE:
			printf("INVALID_VALUE\n");
			break;
		case XmlException::LAZY_EVALUATION:
			printf("LAZY_EVALUATION\n");
			break;
		case XmlException::NO_MEMORY_ERROR:
			printf("NO_MEMORY_ERROR\n");
			break;
		case XmlException::NULL_POINTER:
			printf("NULL_POINTER\n");
			break;
		case XmlException::OPERATION_INTERRUPTED:
			printf("OPERATION_INTERRUPTED\n");
			break;
		case XmlException::OPERATION_TIMEOUT:
			printf("OPERATION_TIMEOUT\n");
			break;
		case XmlException::TRANSACTION_ERROR:
			printf("TRANSACTION_ERROR\n");
			break;
		case XmlException::UNKNOWN_INDEX:
			printf("UNKNOWN_INDEX\n");
			break;
		default:
			printf("UNKNOWN!\n");
	}
}
