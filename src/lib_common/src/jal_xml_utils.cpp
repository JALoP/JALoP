/**
 * @file jal_xml_utils.cpp This file contains utility funtions for dealing
 * with XML.
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

#include <jalop/jal_namespaces.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/XMLUri.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/dom/DOMLSOutput.hpp>
#include <xercesc/framework/XMLFormatter.hpp>

#include <xsec/canon/XSECC14n20010315.hpp>

// XML-Security-C (XSEC)
#include <xsec/framework/XSECProvider.hpp>
#include <xsec/dsig/DSIGReference.hpp>
#include <xsec/dsig/DSIGKeyInfoX509.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>
#include <xsec/enc/XSCrypt/XSCryptCryptoBase64.hpp>
#include <xsec/framework/XSECException.hpp>

// Xalan
#ifndef XSEC_NO_XALAN
#include <xalanc/XalanTransformer/XalanTransformer.hpp>
XALAN_USING_XALAN(XalanTransformer)
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <string.h>
#include <time.h>

#include "jal_xml_utils.hpp"
#include "jal_error_callback_internal.h"
#include "jal_alloc.h"
#include "jal_bn2b64.hpp"
#include "jal_base64_internal.h"

XERCES_CPP_NAMESPACE_USE

static const XMLCh JAL_XML_LS[]  = {	chLatin_L,
				chLatin_S,
				chNull };

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
const XMLCh JAL_XML_CORE[] = {
	chLatin_C, chLatin_o, chLatin_r, chLatin_e, chNull };
static const XMLCh JAL_XML_TRANSFORMS[] = {
	chLatin_T, chLatin_r, chLatin_a, chLatin_n, chLatin_s, chLatin_f, chLatin_o, chLatin_r,
	chLatin_m, chLatin_s, chNull };
static const XMLCh JAL_XML_TRANSFORM[] = {
	chLatin_T, chLatin_r, chLatin_a, chLatin_n, chLatin_s, chLatin_f, chLatin_o, chLatin_r,
	chLatin_m, chNull };
static const XMLCh JAL_XML_ALGORITHM[] = {
	chLatin_A, chLatin_l, chLatin_g, chLatin_o, chLatin_r, chLatin_i, chLatin_t,
	chLatin_h, chLatin_m, chNull };
static const XMLCh JAL_XML_WITH_COMMENTS[] = {
	chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash, chForwardSlash,
	chLatin_w, chLatin_w, chLatin_w, chPeriod, chLatin_w, chDigit_3, chPeriod, chLatin_o,
	chLatin_r, chLatin_g, chForwardSlash, chDigit_2, chDigit_0, chDigit_0, chDigit_6,
	chForwardSlash, chDigit_1, chDigit_2, chForwardSlash, chLatin_x, chLatin_m,
	chLatin_l, chDash, chLatin_c, chDigit_1, chDigit_4, chLatin_n, chDigit_1, chDigit_1,
	chPound, chLatin_W, chLatin_i, chLatin_t, chLatin_h, chLatin_C, chLatin_o, chLatin_m,
	chLatin_m, chLatin_e, chLatin_n, chLatin_t, chLatin_s, chNull };

const XMLCh JAL_XML_DS[] = {
	chLatin_d, chLatin_s, chNull};

const XMLCh JAL_XML_XPOINTER_ID_BEG[] = {
	chPound, chLatin_x, chLatin_p,  chLatin_o, chLatin_i, chLatin_n,
	chLatin_t, chLatin_e, chLatin_r, chOpenParen, chLatin_i, chLatin_d,
	chOpenParen, chSingleQuote, chNull};
const XMLCh JAL_XML_XPOINTER_ID_END[] = {
	chSingleQuote, chCloseParen, chCloseParen, chNull};


enum jal_status jal_parse_xml_snippet(DOMElement *ctx_node, const char* snippet)
{
	Wrapper4InputSource *lsInput = NULL;
	MemBufInputSource * inputSource = NULL;
	DOMLSParser *parser = NULL;
	DOMImplementation *impl = NULL;
	DOMConfiguration *conf = NULL;

	if (!ctx_node) {
		return JAL_E_INVAL;
	}
	impl = DOMImplementationRegistry::getDOMImplementation(JAL_XML_CORE);
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

enum jal_status jal_create_base64_element(DOMDocument *doc,
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

	base64_val = jal_base64_enc(buffer, buf_len);
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
char *jal_get_timestamp()
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

enum jal_status jal_create_reference_elem(const char *reference_uri, const char *digest_method,
		uint8_t *digest_buf, size_t len,
		DOMDocument *doc, DOMElement **elem)
{
	if(!doc || !elem || *elem || len <= 0 || !digest_method || !digest_buf) {
		return JAL_E_XML_CONVERSION;
	}

	XMLCh *namespace_uri = XMLString::transcode(JAL_XMLDSIG_URI);
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

	ret = jal_create_base64_element(doc, digest_buf, len, namespace_uri, DIGESTVALUE, &digestvalue_elem);
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
enum jal_status jal_digest_xml_data(const struct jal_digest_ctx *dgst_ctx,
		DOMDocument *doc,
		uint8_t **digest_out,
		int *digest_len)
{
#define CANON_BUF_SIZE 512
	if (!dgst_ctx || !doc || !digest_out || *digest_out || !digest_len) {
		return JAL_E_INVAL;
	}
	if (!jal_digest_ctx_is_valid(dgst_ctx)) {
		return JAL_E_INVAL;
	}
	XSECC14n20010315 *canon = NULL;

	size_t dlen = dgst_ctx->len;
	uint8_t *dval = (uint8_t*)jal_malloc(dlen);
	void *instance = dgst_ctx->create();
	if (instance == NULL) {
		free(dval);
		jal_error_handler(JAL_E_NO_MEM);
	}
	enum jal_status ret = (enum jal_status) dgst_ctx->init(instance);
	if (ret != JAL_OK) {
		goto error_out;
	}

	canon = new XSECC14n20010315(doc);
	canon->setCommentsProcessing(true);
	canon->setUseNamespaceStack(true);
	canon->setInclusive11();

	unsigned char buffer[CANON_BUF_SIZE];
	doc->normalizeDocument();
	{
		xsecsize_t canon_bytes = canon->outputBuffer(buffer, CANON_BUF_SIZE);
		while (canon_bytes) {
			ret = (enum jal_status) dgst_ctx->update(instance, buffer, canon_bytes);
			if (ret != JAL_OK) {
				goto error_out;
			}
			canon_bytes = canon->outputBuffer(buffer, CANON_BUF_SIZE);
		}
	}
	ret = (enum jal_status) dgst_ctx->final(instance, dval, &dlen);
	if (ret != JAL_OK) {
		goto error_out;
	}
	goto out;
error_out:
	free(dval);
	dval = NULL;
out:
	*digest_out = dval;
	*digest_len = dlen;
	dgst_ctx->destroy(instance);
	delete canon;
	return ret;
}

enum jal_status jal_create_audit_transforms_elem(DOMDocument *doc, DOMElement **new_elem)
{
	if (!new_elem || *new_elem || !doc) {
		return JAL_E_XML_CONVERSION;
	}

	XMLCh *namespace_uri = XMLString::transcode(JAL_XMLDSIG_URI);

	DOMElement *out_elem;
	out_elem = doc->createElementNS(namespace_uri, JAL_XML_TRANSFORMS);

	DOMElement *transform_elem;
	transform_elem = doc->createElementNS(namespace_uri, JAL_XML_TRANSFORM);
	out_elem->appendChild(transform_elem);

	transform_elem->setAttribute(JAL_XML_ALGORITHM, JAL_XML_WITH_COMMENTS);

	XMLString::release(&namespace_uri);

	*new_elem = out_elem;

	return JAL_OK;
}
enum jal_status jal_xml_output(DOMDocument *doc, MemBufFormatTarget **buffer)
{
	enum jal_status ret;
	if (!doc || !buffer || *buffer) {
		return JAL_E_INVAL;
	}
	DOMImplementation *impl =
		DOMImplementationRegistry::getDOMImplementation(JAL_XML_LS);

	DOMLSOutput *output = impl->createLSOutput();
	MemBufFormatTarget *byte_stream = new MemBufFormatTarget();

	DOMLSSerializer *serializer =
		dynamic_cast<DOMLSSerializer*>(impl->createLSSerializer());
	if (!serializer) {
		ret = JAL_E_XML_CONVERSION;
		goto fail;
	}

	output->setByteStream(byte_stream);

	if (serializer->write(doc, output)) {
		ret = JAL_OK;
		goto out;
	}
	ret = JAL_E_XML_CONVERSION;
fail:
	delete byte_stream;
	byte_stream = NULL;
out:
	*buffer = byte_stream;
	delete output;
	delete serializer;
	return ret;
}


XMLCh *jal_BN2decXMLCh(BIGNUM *bn)
{
	char *buff = NULL;
	buff = BN_bn2dec(bn);
	XMLCh *xml_serial = XMLString::transcode((char *) buff);

	OPENSSL_free(buff);
	return xml_serial;
}

XMLCh *jal_get_xml_x509_name(X509_NAME *nm)
{
	BIO *bmem  = BIO_new(BIO_s_mem());
	BUF_MEM *bptr;
	char *buff = NULL;

	X509_NAME_print_ex(bmem, nm, 0, 0);
	BIO_get_mem_ptr(bmem, &bptr);

	size_t malloc_amount = bptr->length;
	buff = (char *) jal_malloc(malloc_amount + 1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = 0;

	XMLCh *xml_subject = XMLString::transcode(buff);

	BIO_free(bmem);
	free(buff);

	return xml_subject;
}

XMLCh *jal_get_xml_x509_serial(ASN1_INTEGER *i)
{
	BIGNUM *bn_buff = NULL;

	bn_buff = ASN1_INTEGER_to_BN(i, NULL);
	XMLCh *xml_serial = jal_BN2decXMLCh(bn_buff);

	BN_free(bn_buff);
	return xml_serial;
}

XMLCh *jal_get_xml_x509_cert(X509 *x509)
{
	unsigned char *buff = NULL;
	char *b64_buff = NULL;
	int len;

	len = i2d_X509(x509, &buff);
	if (len <= 0) {
		return NULL;
	}

	b64_buff = jal_base64_enc(buff, len);
	XMLCh *xml_cert = XMLString::transcode(b64_buff);

	free(b64_buff);
	OPENSSL_free(buff);

	return xml_cert;
}

enum jal_status jal_add_signature_block(RSA *rsa, X509 *x509, DOMDocument *doc,
		DOMElement *parent_element, DOMElement *last_element, const XMLCh *id)
{
	if (!doc || !parent_element || !rsa || !id) {
		return JAL_E_INVAL;
	}

	XSECProvider prov;
	DOMElement *sigNode = NULL;
	DSIGSignature *sig = NULL;

	RSA *new_rsa = RSAPrivateKey_dup(rsa);
	if (!new_rsa) {
		return JAL_E_INVAL;
	}

	// Create a signature object
	sig = prov.newSignature();
	sig->setDSIGNSPrefix(MAKE_UNICODE_STRING("ds"));

	// Use it to create a blank signature DOM structure from the doc
	sigNode = sig->createBlankSignature(doc, CANON_C14N_COM,
			SIGNATURE_RSA, HASH_SHA256);

	// Insert the signature DOM nodes into the doc
	parent_element->insertBefore(sigNode, last_element);

	XMLSize_t beg_len = XMLString::stringLen(JAL_XML_XPOINTER_ID_BEG);
	XMLSize_t end_len = XMLString::stringLen(JAL_XML_XPOINTER_ID_END);
	XMLSize_t id_len = XMLString::stringLen(id);

	XMLCh *reference_uri = (XMLCh *) jal_calloc(beg_len + id_len + end_len + 1, sizeof(XMLCh));
	XMLString::catString(reference_uri, JAL_XML_XPOINTER_ID_BEG);
	XMLString::catString(reference_uri, id);
	XMLString::catString(reference_uri, JAL_XML_XPOINTER_ID_END);

	// Create an envelope reference for the text to be signed
	DSIGReference *ref = sig->createReference(reference_uri, HASH_SHA256);

	free(reference_uri);
	ref->appendEnvelopedSignatureTransform();

	// append the rsa key info
	XMLCh *xml_rsa_modulus = jal_BN2b64(new_rsa->n);
	XMLCh *xml_rsa_exponent = jal_BN2b64(new_rsa->e);
	sig->appendRSAKeyValue(xml_rsa_modulus, xml_rsa_exponent);
	XMLString::release(&xml_rsa_modulus);
	XMLString::release(&xml_rsa_exponent);


	EVP_PKEY *pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, new_rsa);

	// set the signing key to use
	OpenSSLCryptoKeyRSA *rsaKey = new OpenSSLCryptoKeyRSA(pkey);
	sig->setSigningKey(rsaKey);

	// add certificate information, if available
	if (x509) {
		DSIGKeyInfoX509 *x509keyinfo = sig->appendX509Data();
		XMLCh *xml_subject = jal_get_xml_x509_name(X509_get_subject_name(x509));
		XMLCh *xml_issuer = jal_get_xml_x509_name(X509_get_issuer_name(x509));
		XMLCh *xml_serial = jal_get_xml_x509_serial(X509_get_serialNumber(x509));
		XMLCh *xml_cert = jal_get_xml_x509_cert(x509);

		x509keyinfo->setX509SubjectName(xml_subject);
		x509keyinfo->setX509IssuerSerial(xml_issuer, xml_serial);
		x509keyinfo->appendX509Certificate(xml_cert);

		XMLString::release(&xml_cert);
		XMLString::release(&xml_serial);
		XMLString::release(&xml_issuer);
		XMLString::release(&xml_subject);
	}

	// Document needs to be normalized before it is signed.
	doc->normalizeDocument();

	// Sign
	sig->sign();

	EVP_PKEY_free(pkey);

	return JAL_OK;
}
