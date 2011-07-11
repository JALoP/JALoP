#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/XMLUri.hpp>
// these are for the parse function...
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>

#include <string.h>
#include <time.h>

#include <jalop/jal_namespaces.h>
#include "jalp_xml_utils.hpp"
#include "jalp_base64_internal.h"
#include "jal_alloc.h"

XERCES_CPP_NAMESPACE_USE

static const XMLCh REFERENCE[] = {
	chLatin_R, chLatin_e, chLatin_f, chLatin_e, chLatin_r, chLatin_e, chLatin_n,
	chLatin_c, chLatin_e, chNull };
static const XMLCh DIGESTMETHOD[] = {
	chLatin_D, chLatin_i, chLatin_g, chLatin_e, chLatin_s, chLatin_t, chLatin_M,
	chLatin_e, chLatin_t, chLatin_h, chLatin_o, chLatin_d, chNull };
static const XMLCh ALGORITHM[] = {
	chLatin_A, chLatin_l, chLatin_g, chLatin_o, chLatin_r, chLatin_i, chLatin_t,
	chLatin_h, chLatin_m, chNull };
static const XMLCh DIGESTVALUE[] = {
	chLatin_D, chLatin_i, chLatin_g, chLatin_e, chLatin_s, chLatin_t, chLatin_V,
	chLatin_a, chLatin_l, chLatin_u, chLatin_e, chNull };
static const XMLCh URI[] = {
	chLatin_U, chLatin_R, chLatin_I, chNull };
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
	DOMNode *child_node = NULL;
	try {
		child_node = parser->parseWithContext(lsInput, ctx_node, DOMLSParser::ACTION_REPLACE_CHILDREN);
	} catch(...) {
		// do nothing
	}
	delete (parser);
	delete lsInput;
	return (child_node != NULL)? JAL_OK : JAL_E_XML_PARSE;
}

enum jal_status create_base64_element(DOMDocument *doc,
		const uint8_t *buffer,
		const size_t buf_len,
		const XMLCh *namespace_uri,
		const XMLCh *elm_name,
		DOMElement **new_elem)
{
	if (!doc || !buffer || (buf_len == 0) || !namespace_uri ||
		!elm_name || !new_elem || *new_elem) {
		return JAL_E_INVAL;
	}
	char *base64_val = NULL;
	XMLCh *xml_base64_val = NULL;

	base64_val = jalp_base64_enc(buffer, buf_len);
	if (!base64_val) {
		// this should never actually happen since the input is
		// non-zero in length.
		return JAL_E_INVAL;
	}

	xml_base64_val = XMLString::transcode(base64_val);

	DOMElement *elm = doc->createElementNS(namespace_uri, elm_name);
	elm->setTextContent(xml_base64_val);

	XMLString::release(&xml_base64_val);
	free(base64_val);
	*new_elem = elm;
	return JAL_OK;
}

// Returns a timestamp of the format YYYY-MM-DDTHH:MM:SS[+-]HH:MM
char *get_timestamp()
{
        char *ftime = (char*)jal_malloc(26);
        char *tz_offset = (char*)jal_malloc(7);
        time_t rawtime;
        struct tm *tm;
        time(&rawtime);
        tm = localtime(&rawtime);
        strftime(ftime, 26, "%Y-%m-%dT%H:%M:%S", tm);
	/* Timezone
	 * Inserts ':' into [+-]HHMM for [+-]HH:MM */
        strftime(tz_offset, 7, "%z", tm);
	tz_offset[6] = '\0';
        tz_offset[5] = tz_offset[4];
        tz_offset[4] = tz_offset[3];
        tz_offset[3] = ':';
        strcat(ftime, tz_offset);
	free(tz_offset);
        return ftime;

}

enum jal_status jal_create_reference_elem(char *reference_uri, char *digest_method,
		uint8_t *digest_buf, size_t len,
		DOMDocument *doc, DOMElement **elem)
{
	if(!doc || !elem || *elem || len <= 0 || !digest_method || !digest_buf) {
		return JAL_E_XML_CONVERSION;
	}

	XMLCh *namespace_uri = XMLString::transcode(JALP_XMLDSIG_URI);
	XMLCh *xml_reference_uri = XMLString::transcode(reference_uri);
	XMLCh *xml_digest_method = XMLString::transcode(digest_method);

	DOMElement *digestmethod_elem = doc->createElementNS(namespace_uri, DIGESTMETHOD);
	DOMElement *digestvalue_elem = NULL;
	DOMElement *reference_elem = doc->createElementNS(namespace_uri, REFERENCE);

	enum jal_status ret = JAL_OK;

	if(reference_uri) {
		if (!XMLUri::isValidURI(false, xml_reference_uri)) {
			ret = JAL_E_INVAL_URI;
			goto err_out;
		}
		reference_elem->setAttribute(URI, xml_reference_uri);
	}

	digestmethod_elem->setAttribute(ALGORITHM, xml_digest_method);

	ret = create_base64_element(doc, digest_buf, len, namespace_uri, DIGESTVALUE, &digestvalue_elem);
	if (ret != JAL_OK) {
		goto err_out;
	}

	reference_elem->appendChild(digestmethod_elem);
	reference_elem->appendChild(digestvalue_elem);

	*elem = reference_elem;

	XMLString::release(&namespace_uri);
	XMLString::release(&xml_reference_uri);
	XMLString::release(&xml_digest_method);

	return JAL_OK;

err_out:

	XMLString::release(&namespace_uri);
	XMLString::release(&xml_reference_uri);
	XMLString::release(&xml_digest_method);

	return ret;

}
