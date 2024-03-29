/**
 * @file jal_xml_utils.h This file defines helper functions for dealing with
 * creating/reading XML data.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#ifndef _JALX_XML_UITLS_H_
#define _JALX_XML_UITLS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/jal_status.h>
#include <libxml/tree.h>
#include <unistd.h> // for size_t

// XmlSecurity Library
#include <xmlsec/bn.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <jalop/jal_digest.h>


/**
 * Helper function to parse an xml snippet.
 *
 * @param[in] ctx_node A node to use as the parent of elements encountered during the parse.
 * @param[in] snippet a snippet of XML. The contents will be added to \pctx_node.
 * @return JAL_OK on success or JAL_E_XML_PARSE if there was an error parsing the
 * snippet.
 */
enum jal_status jal_parse_xml_snippet(
		xmlNodePtr *ctx_node,
		const char *snippet);

/**
 * Helper function to base64 encode a buffer and create a new DOMElement.
 *
 * @param[in] doc The document to use when creating elements.
 * @param[in] buffer The byte buffer to base64 encode
 * @param[in] buf_len The length, in bytes, of the buffer
 * @param[in] namespace_uri The URI to use as the namespace of the new element.
 * @param[in] elm_name The name that should be given to the new element.
 * @param[in,out] new_elem Pointer that will be assigned to the newly created
 * DOMElement, This new DOMElement will have the name
 * \pelm_name, and the default namespace set to \p namespace_uri. The text
 * content of the new node will be the base64 encoded value of \p buffer.
 *
 * @return JAL_OK on error, or JAL_E_INVAL
 */
enum jal_status jal_create_base64_element(
		xmlDocPtr doc,
		const uint8_t *buffer,
		const size_t buf_len,
		const xmlChar *namespace_uri,
		const xmlChar *elm_name,
		xmlNodePtr *new_elem);

/**
 * Helper function to create a properly formatted XML DateTime timestamp.
 *
 * @return formatted timestamp string
 */
char *jal_get_timestamp();

/**
 * Creates Reference xmlNodePtr from uri, digest method, and digest buffer
 *
 * Does not deal with the transfrom child Element, this will be appended later by the caller.
 *
 * @param[in] reference_uri A uri for the reference
 * @param[in] digest_method A uri for the algorithm used in creating the digest.
 * @param[in] digest_buf A pointer to the generated digest.
 * @param[in] digest_len The length of the generated digest.
 * @param[in] doc A pointer to the xmlDocPtr to use in creating the element
 * @param[out] elem A pointer to hold the created element. Should point to NULL.
 * @return JAL_OK on success, JAL_E_XML_CONVERSION on failure.
*/
enum jal_status jal_create_reference_elem(
		const char *reference_uri,
		const char *digest_method,
		uint8_t *digest_buf,
		uint64_t len,
		xmlDocPtr doc,
		xmlNodePtr *elem);

/**
 * Helper function return a Transforms element.
 *
 * @param[in] doc The document to use when creating elements.
 * @param[in,out] new_elem Pointer that will be assigned to the newly created
 * Transforms element.
 *
 * @return JAL_OK,  or JAL_E_XML_CONVERSION on error
 */
enum jal_status jal_create_audit_transforms_elem(
		xmlDocPtr doc,
		xmlNodePtr *new_elem);

/**
 * Given a xmlDocPtr, write out the corresponding XML to a byte buffer.
 *
 * @param doc[in] The xmlDocPtr to serialize
 * @param buffer[out] The buffer that contains the serialized XML.
 * @return 
 *  - JAL_OK on success
 *  - JAL_E_INVAL if one of the arguments is invalid.
 */
enum jal_status jal_xml_output(
		xmlDocPtr doc,
		xmlChar **buffer,
		size_t *buffersize);

/**
 * Use the digest context \p dgst_ctx to generate a digest for the document
 * given by xml_buffer.
 *
 * @param dgst_ctx The digest method to use.
 * @param doc The xmlDocPtr to generate a digest for.
 * @param digest_out On success, this will be set to a newly allocated buffer
 * that contains the binary version of the digest. It is up to the caller to
 * release this memory with a call to free().
 * @param digest_len On success, this will be set to the length, in bytes, of
 * \pdigest_buffer.
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jal_digest_xml_data(
		const struct jal_digest_ctx *dgst_ctx,
		xmlDocPtr doc,
		uint8_t **digest_out,
		int *digest_len);

/**
 * Use the digest context \p dgst_ctx to generate a digest for the data
 * given in the buffer.
 *
 * @param dgst_ctx The digest method to use.
 * @param data The data to generate a digest for.
 * @param data_len The length of the data
 * @param digest_out On success, this will be set to a newly allocated buffer
 * that contains the binary version of the digest. It is up to the caller to
 * release this memory with a call to free().
 * @param digest_len On success, this will be set to the length, in bytes, of
 * \pdigest_buffer.
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jal_digest_arbitrary_data(
		const struct jal_digest_ctx *dgst_ctx,
		const uint8_t * const data,
		const int data_len,
		uint8_t **digest_out,
		int *digest_len);

/**
 * Convert an OpenSSL BIGNUM to a Libxml2 xmlChar pointer of the decimal representation
 * of the BIGNUM.
 *
 * @param[in] bn The BIGNUM to convert.
 *
 * @return xmlChar pointer to the decimal representation of the BIGNUM.  This needs
 * to be free'd with xmlFree.
 */

/**
 * Get the first non-text element child.
 *
 * @param[in] elem The element to retrieve the child from.
 *
 * @return non-text element child or NULL
 */
xmlNodePtr jal_get_first_element_child(xmlNodePtr elem);

/**
 * Add a signature block to a document.
 *
 * @param[in] rsa RSA key to use as a signing key.  This is required.
 * @param[in] x509 Certificate to use when signing.  This is not required
 * and could be passed in as NULL.
 * @param[in] doc The document to sign.
 * @param[in] last The element to add the signature before.  Pass in
 * NULL to have the signature element added as the last element under
 * parent_element.
 * @param[in] id The id to use in the Reference elements URI attribute.
 * This should be the id of the root node in the document.
 *
 * @return JAL_OK,  or JAL_E_INVAL on error
 */
enum jal_status jal_add_signature_block(
		RSA *rsa,
		X509 *x509,
		xmlDocPtr doc,
		xmlNodePtr last,
		const char *id);

/** @} */
#ifdef __cplusplus
}
#endif

#endif // _JALX_XML_UITILS_H_
