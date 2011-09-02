/**
 * @file test_jaldb_main.cpp This file contains functions to test the DB Layer.
 *
 *@section LICENSE
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

#include <iostream>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/util/PanicHandler.hpp>
#include <jalop/jal_status.h>
#include "xml_test_utils.hpp"
#include "jaldb_context.hpp"
#include "jaldb_xml_doc_storage.hpp"
#include "xml_test_utils.hpp"
using namespace std;
using namespace DbXml;
XERCES_CPP_NAMESPACE_USE

class MyHandler: public PanicHandler {
	__attribute__((noreturn)) void panic(xercesc_3_1::PanicHandler::PanicReasons) {
		abort();
	}
};

class ErrorHandler: public DOMErrorHandler
{
public:
	ErrorHandler(): failed(false)
	{
		// do nothing
	}
	virtual bool handleError(const DOMError& e)
	{
		bool failure = !(e.getSeverity() == DOMError::DOM_SEVERITY_WARNING);
		if (failure) {
			failed = true;
		}
		char *msg = XMLString::transcode(e.getMessage());
		const char *level = failure ? "ERROR: " : "WARNING: ";
		cout << level << msg << endl;
		XMLString::release(&msg);
		return !failed;

	}
	bool failed;
};

int main()
{
	XMLPlatformUtils::Initialize();

	XmlManager mgr;

	DOMDocument *smd = NULL;

	DOMLSParser *parser = NULL;
	DOMImplementation *impl = NULL;
	DOMConfiguration *conf = NULL;

	ErrorHandler eh;

	impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	parser = impl->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	conf = parser->getDomConfig();
	conf->setParameter(XMLUni::fgDOMDatatypeNormalization, true);
	conf->setParameter(XMLUni::fgDOMErrorHandler, &eh);
	conf->setParameter(XMLUni::fgDOMEntities, true);
	conf->setParameter(XMLUni::fgDOMNamespaces, true);
	conf->setParameter(XMLUni::fgDOMValidate, false);
	conf->setParameter(XMLUni::fgXercesSchema, false);
	conf->setParameter(XMLUni::fgXercesSchemaFullChecking, false);
	conf->setParameter(XMLUni::fgXercesUseCachedGrammarInParse, true);
	conf->setParameter(XMLUni::fgXercesCacheGrammarFromParse, false);
	//conf->setParameter(XMLUni::fgXercesCacheGrammarFromParse, true);
	conf->setParameter(XMLUni::fgXercesLoadSchema, false);
	conf->setParameter(XMLUni::fgXercesHandleMultipleImports, true);
	conf->setParameter(XMLUni::fgXercesUserAdoptsDOMDocument, false);
	smd = parser->parseURI("./test-input/domwriter.xml");

	if (eh.failed || smd == NULL) {
		cout << "failed to parse" << endl;
		return -1;
	}
	enum jaldb_status ret;

	jaldb_context *ctx = jaldb_context_create();
	ret = jaldb_context_init(ctx, "/home/pblack/db/", NULL, 1);

	std::string source = "123.45.65.0";
	std::string sid;
	std::string log = "blah blah blah";
	int db_err;
	ret = jaldb_insert_log_record(ctx, source, smd, smd, (uint8_t*) log.c_str(), log.length(), sid, &db_err);
	XmlTransaction txn = ctx->manager->createTransaction();
	XmlUpdateContext uc = ctx->manager->createUpdateContext();
	
	ret = jaldb_insert_log_record_helper(source, txn, *ctx->manager, uc, *ctx->log_sys_cont,
			*ctx->log_app_cont, ctx->log_dbp, smd, smd, 
			(uint8_t*) log.c_str(), log.length(), sid, &db_err);
	if (JALDB_OK != ret) {
		printf ("failed to put doc...");
	}

	jaldb_context_destroy(&ctx);

	return 0;
}
