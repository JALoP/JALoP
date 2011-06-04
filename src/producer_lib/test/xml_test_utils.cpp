#include <list>
#include <cstdio>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>

using namespace std;

// XMLCh version of "LS"
XERCES_CPP_NAMESPACE_USE
#include "xml_test_utils.hpp"
static const XMLCh LS[]  = {	chLatin_L,
				chLatin_S,
				chNull
			};
// XMLCh version of "Core"
extern const XMLCh  TEST_XML_CORE[] = {	chLatin_C,
				chLatin_o,
				chLatin_r,
				chLatin_e,
				chNull
			};

class MyErrorHandler: public DOMErrorHandler
{
public:
	MyErrorHandler(bool debug_in): debug(debug_in), failed(false) {
		// do nothing
	}
	virtual bool handleError(const DOMError& e)
	{
		bool failure = !(e.getSeverity() == DOMError::DOM_SEVERITY_WARNING);
		if (failure) {
			failed = true;
		}
		if (debug || failure) {
			DOMLocator *loc = e.getLocation();
			const char *severity = failure ? "error: " : "warning: ";
			char *message = XMLString::transcode(e.getMessage());
			char *uri = XMLString::transcode(loc->getURI());
			printf("%s: line %lld, col %lld\n\t %s%s\n", uri,
				(long long) loc->getLineNumber(),
				(long long) loc->getColumnNumber(),
				severity, message);
			XMLString::release(&message);
			XMLString::release(&uri);
		}
		// Return true to continue processing as if the error didn't
		// occur.
		return true;
	}
	bool debug;
	bool failed;
};
bool validate(DOMDocument *doc, const char *document_name, list<const char*>schemas, bool debug)
{
	MyErrorHandler eh(debug);
	bool ret = false;
	DOMDocument *parsed_doc = NULL;
	MemBufFormatTarget *xmldata = NULL;
	Wrapper4InputSource *lsInput = NULL;
	MemBufInputSource * inputSource = NULL;
	DOMLSParser *parser = NULL;
	DOMImplementation *impl = NULL;
	DOMConfiguration *conf = NULL;

	xmldata = xml_output(doc);
	if (xmldata == NULL) {
		goto out;
	}
	if (debug) {
		printf("%s\n%s\n", document_name, xmldata->getRawBuffer());
	}

	impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	parser = impl->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	conf = parser->getDomConfig();
	// perform normalization of elements, i.e. ignore any processing instructions or comments for the purposes of validation.
	//conf->setParameter(XMLUni::fgDOMDatatypeNormalization, true);
	// do not keep entity references in the doc
	//conf->setParameter(XMLUni::fgDOMEntities, false);
	// process namespaces
	conf->setParameter(XMLUni::fgDOMNamespaces, true);
	// Validate the document against
	conf->setParameter(XMLUni::fgDOMValidate, true);
	// Enable schema validation
	conf->setParameter(XMLUni::fgXercesSchema, true);
	// Enable schema validation
	conf->setParameter(XMLUni::fgXercesSchemaFullChecking, true);
	// Enable full checking
	conf->setParameter(XMLUni::fgXercesUseCachedGrammarInParse, true);
	// don't try and load unknown schemas
	conf->setParameter(XMLUni::fgXercesLoadSchema, false);
	// handle schemas that import types from more than one other schema
	conf->setParameter(XMLUni::fgXercesHandleMultipleImports, true);
	// Let the parser own the document
	conf->setParameter(XMLUni::fgXercesUserAdoptsDOMDocument, false);
	// Set the error handler so we can print info about errors.
	conf->setParameter(XMLUni::fgDOMErrorHandler, &eh);

	for (list<const char*>::iterator schema = schemas.begin(); schema != schemas.end(); schema++) {
		if (!parser->loadGrammar(*schema, Grammar::SchemaGrammarType, true)) {
			printf("failed to load schema: %s\n", *schema);
			goto out;
		} else {
			if (debug) {
				printf("loaded schema: %s\n", *schema);
			}
		}
	}
	inputSource = new MemBufInputSource(xmldata->getRawBuffer(),
					xmldata->getLen(),
					document_name,
					// Pass false here to prevent
					// MemBufInputSource from adopting the
					// buffer since it is owned by the
					// MemBufFormatTarget
					false);
	lsInput = new Wrapper4InputSource(inputSource);
	parsed_doc = parser->parse(lsInput);
	if (parsed_doc != NULL && !eh.failed) {
		ret = true;
	}
out:
	delete xmldata;
	delete parser;
	delete lsInput;
	return ret;

}

MemBufFormatTarget *xml_output(DOMDocument *doc)
{
	DOMImplementation *impl =
		DOMImplementationRegistry::getDOMImplementation(LS);

	DOMLSOutput *output = impl->createLSOutput();
	MemBufFormatTarget *byte_stream = new MemBufFormatTarget();

	DOMLSSerializer *serializer =
		dynamic_cast<DOMLSSerializer*>(impl->createLSSerializer());
	if (!serializer) {
		printf("Failed to create serializer\n");
		goto fail;
	}

	output->setByteStream(byte_stream);

	if (serializer->write(doc, output)) {
		goto out;
	}
	printf("Failed to serialize the doc\n");
fail:
	delete byte_stream;
	byte_stream = NULL;
out:
	delete output;
	delete serializer;
	return byte_stream;
}
