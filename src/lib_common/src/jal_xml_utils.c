/**
 * @file jal_xml_utils.c This file contains utility funtions for dealing
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

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/uri.h>
#include <libxml/c14n.h>

#include <jalop/jal_namespaces.h>
#include <jalop/jal_status.h>
#include <jalop/jal_digest.h>

// XmlSecurity Library
#include <xmlsec/xmlsec.h>
#include <xmlsec/bn.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/templates.h>
#include <xmlsec/crypto.h>
#include <xmlsec/openssl/evp.h>
#include <xmlsec/x509.h>
#include <xmlsec/openssl/app.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

#include <string.h>
#include <time.h>

#include "jal_xml_utils.h"
#include "jal_error_callback_internal.h"
#include "jal_alloc.h"
#include "jal_base64_internal.h"

#define REFERENCE "Reference"
#define DIGESTMETHOD "DigestMethod"
#define ALGORITHM "Algorithm"
#define DIGESTVALUE "DigestValue"
#define URI "URI"
#define JAL_XML_CORE "Core"
#define JAL_XML_TRANSFORMS "Transforms"
#define JAL_XML_TRANSFORM "Transform"
#define JAL_XML_ALGORITHM "Algorithm"
#define JAL_XML_WITH_COMMENTS "http://www.w3.org/2006/12/xml-c14n11#WithComments"
#define JAL_XML_DS "ds"
#define JAL_XML_XPOINTER_ID_BEG "#xpointer(id('"
#define JAL_XML_XPOINTER_ID_END "'))"

enum jal_status jal_parse_xml_snippet(
		xmlNodePtr *ctx_node,
		const char *snippet)
{
	if (!ctx_node || !snippet) {
		return JAL_E_INVAL;
	}

	xmlDocPtr doc = xmlParseMemory(snippet, strlen(snippet));
	if (!doc) {
		return JAL_E_XML_PARSE;
	}
	if (*ctx_node) {
		xmlAddChild(*ctx_node, xmlDocGetRootElement(doc));
	}
	else {
		*ctx_node = xmlDocGetRootElement(doc);
	}
	return JAL_OK;
}

enum jal_status jal_create_base64_element(
		xmlDocPtr doc,
		const uint8_t *buffer,
		const size_t buf_len,
		const xmlChar *namespace_uri,
		const xmlChar *elm_name,
		xmlNodePtr *new_elem)
{
	if (!doc || !buffer || (buf_len == 0) || !namespace_uri ||
		!elm_name || !new_elem || *new_elem) {
		return JAL_E_INVAL;
	}
	char *base64_val = NULL;
	xmlChar *xml_base64_val = NULL;

	base64_val = jal_base64_enc(buffer, buf_len);
	if (!base64_val) {
		// this should never actually happen since the input is
		// non-zero in length.
		return JAL_E_INVAL;
	}

	xml_base64_val = (xmlChar *)base64_val;

	xmlNodePtr elm = xmlNewDocNode(doc, NULL, elm_name, NULL);
	xmlNsPtr ns = xmlNewNs(elm, namespace_uri, NULL);
	xmlSetNs(elm, ns);
	xmlNodeAddContent(elm, xml_base64_val);

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

enum jal_status jal_create_reference_elem(
		const char *reference_uri,
		const char *digest_method,
		uint8_t *digest_buf,
		uint64_t len,
		xmlDocPtr doc,
		xmlNodePtr *elem)
{
	if(!doc || !elem || *elem || len <= 0 || !digest_method || !digest_buf) {
		return JAL_E_XML_CONVERSION;
	}

	xmlChar *namespace_uri = (xmlChar *)JAL_XMLDSIG_URI;
	xmlChar *xml_reference_uri = (xmlChar *)reference_uri;
	xmlChar *xml_digest_method = (xmlChar *)digest_method;

	xmlNodePtr reference_elem = xmlNewDocNode(doc, NULL, (xmlChar *) REFERENCE, NULL);
	xmlNodePtr digestmethod_elem = NULL;
	xmlNodePtr digestvalue_elem = NULL;

	enum jal_status ret = JAL_OK;

	if(reference_uri) {
		xmlURIPtr ret_uri = NULL;
		ret_uri = xmlParseURI(reference_uri);
		if (!ret_uri) {
			ret = JAL_E_INVAL_URI;
			goto err_out;
		}
		xmlFreeURI(ret_uri);
		xmlSetProp(reference_elem, (xmlChar *) URI, xml_reference_uri);
	}

	ret = jal_create_base64_element(doc, digest_buf, len, namespace_uri,
					(xmlChar *)DIGESTVALUE, &digestvalue_elem);
	if (ret != JAL_OK) {
		goto err_out;
	}

	digestmethod_elem = xmlNewChild(reference_elem, NULL, (xmlChar *) DIGESTMETHOD, NULL);
	xmlSetProp(digestmethod_elem, (xmlChar *)ALGORITHM, xml_digest_method);

	xmlAddChild(reference_elem, digestvalue_elem);

	*elem = reference_elem;

	return JAL_OK;

err_out:
	xmlFreeNodeList(reference_elem);
	return ret;
}

enum jal_status jal_create_audit_transforms_elem(
		xmlDocPtr doc,
		xmlNodePtr *new_elem)
{
	if (!new_elem || *new_elem || !doc) {
		return JAL_E_XML_CONVERSION;
	}

	xmlChar *namespace_uri = (xmlChar *)JAL_XMLDSIG_URI;

	xmlNodePtr out_elem = xmlNewDocNode(doc, NULL, (xmlChar *) JAL_XML_TRANSFORMS, NULL);
	xmlNsPtr ns = xmlNewNs(out_elem, namespace_uri, NULL);
	xmlSetNs(out_elem, ns);

	xmlNodePtr transform_elem = xmlNewChild(
						out_elem, NULL,
						(xmlChar *) JAL_XML_TRANSFORM,
						NULL);

	xmlSetProp(transform_elem,
			(xmlChar *) JAL_XML_ALGORITHM, (xmlChar *) JAL_XML_WITH_COMMENTS);

	*new_elem = out_elem;

	return JAL_OK;
}

enum jal_status jal_xml_output(
		xmlDocPtr doc,
		xmlChar **buffer)
{
	if (!doc || !buffer || *buffer) {
		return JAL_E_INVAL;
	}

	xmlChar *xmlbuff = NULL;
	int buffersize;

	xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);

	*buffer = xmlbuff;

	return JAL_OK;
}

int jal_is_visible_callback(
		__attribute__((__unused__)) void *user_data,
		__attribute__((__unused__)) xmlNodePtr node,
		__attribute__((__unused__)) xmlNodePtr parent)
{
	return 1; // All nodes visible
}

enum jal_status jal_digest_xml_data(
		const struct jal_digest_ctx *dgst_ctx,
		xmlDocPtr doc,
		uint8_t **digest_out,
		int *digest_len)
{
#define JAL_XML_C14N_1_1 2

	if (!dgst_ctx || !doc || !digest_out || *digest_out || !digest_len) {
		return JAL_E_INVAL;
	}
	if (!jal_digest_ctx_is_valid(dgst_ctx)) {
		return JAL_E_INVAL;
	}

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

	xmlChar *doc_txt = NULL;

	int res = xmlC14NDocDumpMemory(
					doc,
					NULL,
					JAL_XML_C14N_1_1,
					NULL,
					1,
					&doc_txt);

	if (res < 0 ) {
		printf("ERROR!\n");
		ret = JAL_E_XML_CONVERSION;
		goto error_out;
	}

	ret = (enum jal_status) dgst_ctx->update(instance, (unsigned char *) doc_txt, strlen((char *) doc_txt));

	ret = (enum jal_status) dgst_ctx->final(instance, dval, &dlen);
	if (ret != JAL_OK) {
		goto error_out;
	}
	free(doc_txt);
	goto out;

error_out:
	free(dval);
	dval = NULL;
out:
	*digest_out = dval;
	*digest_len = dlen;
	dgst_ctx->destroy(instance);
	return ret;
}

xmlChar *jal_get_xml_x509_cert(X509 *x509)
{
	unsigned char *buff = NULL;
	char *b64_buff = NULL;
	int len;

	// Returns cert in DER format!!!
	len = i2d_X509(x509, &buff);
	if (len <= 0) {
		return NULL;
	}

	b64_buff = jal_base64_enc(buff, len);
	xmlChar *xml_cert = xmlCharStrdup(b64_buff);

	free(b64_buff);
	OPENSSL_free(buff);

	return xml_cert;
}

xmlChar *jal_BN2dec_xmlChar(BIGNUM *bn)
{
	char *buff = NULL;
	buff = BN_bn2dec(bn);
	xmlChar *xml_serial = (xmlChar *)buff;

	return xml_serial;
}

xmlChar *jal_get_xml_x509_name(X509_NAME *nm)
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

	xmlChar *xml_subject = (xmlChar *)buff;

	BIO_free(bmem);

	return xml_subject;
}

xmlChar *jal_get_xml_x509_serial(ASN1_INTEGER *i)
{
	BIGNUM *bn_buff = NULL;

	bn_buff = ASN1_INTEGER_to_BN(i, NULL);
	xmlChar *xml_serial = jal_BN2dec_xmlChar(bn_buff);

	BN_free(bn_buff);
	return xml_serial;
}

enum jal_status jal_add_signature_block(
		RSA *rsa,
		X509 *x509,
		xmlDocPtr doc,
		xmlNodePtr last,
		const char *id)
{
	if (!doc || !rsa || !id) {
		return JAL_E_INVAL;
	}

	xmlNodePtr signNode = NULL;
	xmlNodePtr refNode = NULL;
	xmlNodePtr keyInfoNode = NULL;
	xmlNodePtr x509DataNode = NULL;
	xmlNodePtr x509IssuerSerialNode = NULL;
	xmlSecDSigCtxPtr dsigCtx = NULL;

	RSA *new_rsa = RSAPrivateKey_dup(rsa);
	if (!new_rsa) {
		return JAL_E_INVAL;
	}

	enum jal_status ret = JAL_E_INVAL;

	signNode = xmlSecTmplSignatureCreate(
				doc,
				xmlSecTransformInclC14NWithCommentsId,
				xmlSecOpenSSLTransformRsaSha1Id,
				NULL);

	if (!signNode) {
		goto done;
	}

	if (last) {
		xmlAddPrevSibling(last, signNode);
	} else {
		xmlAddChild(xmlDocGetRootElement(doc), signNode);
	}

	int beg_len = xmlStrlen((xmlChar *)JAL_XML_XPOINTER_ID_BEG);
	int end_len = xmlStrlen((xmlChar *)JAL_XML_XPOINTER_ID_END);
	int id_len = xmlStrlen((xmlChar *)id);
	int ref_len = beg_len + id_len + end_len + 1;

	char *reference_uri = jal_calloc(ref_len, sizeof(xmlChar));
	strncat(reference_uri, JAL_XML_XPOINTER_ID_BEG, beg_len);
	strncat(reference_uri, id, id_len);
	strncat(reference_uri, JAL_XML_XPOINTER_ID_END, end_len);
	
	refNode = xmlSecTmplSignatureAddReference(signNode,
						xmlSecOpenSSLTransformSha256Id,
						NULL, // id
						(xmlChar *)reference_uri, // uri
						NULL);// type
	xmlFree(reference_uri);
	if (!refNode) {
		ret = JAL_E_INVAL;
		goto done;
	}

	if (!xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId)) {
		goto done;
	}
	
	keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
	if (!keyInfoNode) {
		goto done;
	}

	if (!xmlSecTmplKeyInfoAddKeyValue(keyInfoNode)) {
		goto done;
	}

	xmlSecKeyDataPtr pKeyData = NULL;
	pKeyData = xmlSecKeyDataCreate(xmlSecKeyDataRsaId);

	if (0 != xmlSecOpenSSLKeyDataRsaAdoptRsa(pKeyData, new_rsa)) {
		goto done;
	}

	xmlSecKeyPtr pSecKey = xmlSecKeyCreate();
	if (!pSecKey) {
		goto done;
	}
	
	if (0 != xmlSecKeySetValue(pSecKey, pKeyData)) {
		goto done;
	}

    	dsigCtx = xmlSecDSigCtxCreate(NULL);
    	if (!dsigCtx) {
		goto done;
    	}
	
	dsigCtx->signKey = pSecKey;

	// add certificate information, if available
	if (x509) {
		x509DataNode = xmlSecTmplKeyInfoAddX509Data(keyInfoNode);
		if (!x509DataNode) {
			goto done;
		}

		if (!xmlSecTmplX509DataAddSubjectName(x509DataNode)) {
			goto done;
		}

		x509IssuerSerialNode = xmlSecTmplX509DataAddIssuerSerial(x509DataNode);
		if (!x509IssuerSerialNode) {
			goto done;
		}

		if (!xmlSecTmplX509DataAddCertificate(x509DataNode)) {
			goto done;
		}

		BIO *bio = BIO_new(BIO_s_mem());
		PEM_write_bio_X509(bio, x509);
		if (0 > xmlSecOpenSSLAppKeyCertLoadBIO(dsigCtx->signKey,
						bio,
						xmlSecKeyDataFormatCertPem)) {
			goto done;
		}
		BIO_free(bio);
	}

	if (0 > xmlSecDSigCtxSign(dsigCtx, signNode)) {
		goto done;
	}

	ret = JAL_OK;
done:
	/* cleanup */
	if (dsigCtx != NULL) {
		xmlSecDSigCtxDestroy(dsigCtx);
	}

	return ret;
}
