#include "jalp_xml_utils.hpp"
#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/XMLUri.hpp>
// these are for the parse function...
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>

XERCES_CPP_NAMESPACE_USE

const XMLCh JALP_XML_CORE[] = {
	chLatin_C, chLatin_o, chLatin_r, chLatin_e, chNull };


enum jal_status parse_xml_snippet(DOMElement *ctx_node, const char* snippet)
{
	Wrapper4InputSource *lsInput = NULL;
	MemBufInputSource * inputSource = NULL;
	DOMLSParser *parser = NULL;
	DOMImplementation *impl = NULL;
	DOMConfiguration *conf = NULL;

	if (!ctx_node) {
		return JAL_E_INVAL;
	}
	impl = DOMImplementationRegistry::getDOMImplementation(JALP_XML_CORE);
	parser = impl->createLSParser(DOMImplementationLS::MODE_SYNCHRONOUS, 0);
	conf = parser->getDomConfig();
	conf->setParameter(XMLUni::fgDOMEntities, false);
	conf->setParameter(XMLUni::fgDOMNamespaces, true);
	// don't validate (can't since building a snippet
	conf->setParameter(XMLUni::fgDOMValidate, false);
	// Enable schema validation
	conf->setParameter(XMLUni::fgXercesSchema, false);
	// Enable schema validation
	conf->setParameter(XMLUni::fgXercesSchemaFullChecking, false);
	// Enable full checking
	conf->setParameter(XMLUni::fgXercesUseCachedGrammarInParse, false);
	// don't try and load unknown schemas
	conf->setParameter(XMLUni::fgXercesLoadSchema, false);
	// take ownership of the doc
	conf->setParameter(XMLUni::fgXercesUserAdoptsDOMDocument, true);

	inputSource = new MemBufInputSource(reinterpret_cast<const XMLByte*>(snippet),
					strlen(snippet),
					(char*)NULL,
					false);
	lsInput = new Wrapper4InputSource(inputSource);
	DOMNode *child_node = parser->parseWithContext(lsInput, ctx_node, DOMLSParser::ACTION_REPLACE_CHILDREN);
	delete (parser);
	delete lsInput;
	return (child_node != NULL)? JAL_OK : JAL_E_XML_PARSE;
}
