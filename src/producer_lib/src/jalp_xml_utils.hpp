/**
 * @file jalp_xml_utils.hpp This file defines helper fucntions for dealing with
 * createing/reading XML data.
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
#ifndef _JALP_XML_UITLS_HPP_
#define _JALP_XML_UITLS_HPP_

#include <jalop/jal_status.h>
#include <xercesc/dom/DOMElement.hpp>
#include <unistd.h> // for size_t


XERCES_CPP_NAMESPACE_USE
/**
 * Helper function to parse an xml snippet.
 *
 * @param[in] ctx_node A node to use as the parent of elements encountered during the parse.
 * @param[in] snippet a snippet of XML. The contents will be added to \pctx_node.
 * @return JAL_OK on success or JAL_E_XML_PARSE if there was an error parsing the
 * snippet.
 */
enum jal_status parse_xml_snippet(DOMElement *ctx_node, const char *snippet);

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
 * \pelm_name, and the default namespace set to \pnamespace_uri. The text
 * content of the new node will be the base64 encoded value of \pbuffer.
 *
 * @return JAL_OK on error, or JAL_E_INVAL
 */
enum jal_status create_base64_element(DOMDocument *doc,
		const uint8_t *buffer, const size_t buf_len,
		const XMLCh *namespace_uri, const XMLCh *elm_name,
		DOMElement **new_elem);

/**
 * Helper function to create a properly formatted XML DateTime timestamp.
 *
 * @return formatted timestamp string
 */
char *get_timestamp();

/**
 * Creates Reference DOMElement from uri, digest method, and digest buffer
 *
 * Does not deal with the transfrom child Element, this will be appended later by the caller.
 *
 * @param[in] reference_uri A uri for the reference
 * @param[in] digest_method A uri for the algorithm used in creating the digest.
 * @param[in] digest_buf A pointer to the generated digest.
 * @param[in] digest_len The length of the generated digest.
 * @param[in] doc A pointer to the DOMDocument to use in creating the element
 * @param[out] elem A pointer to hold the created element. Should point to NULL.
 * @return JAL_OK on success, JAL_E_XML_CONVERSION on failure.
*/
enum jal_status jal_create_reference_elem(char *reference_uri, char *digest_method,
		uint8_t *digest_buf, size_t len,
		DOMDocument *doc, DOMElement **elem);


/**
 * Use the digest context \pdgst_ctx to generate a digest for the document
 * given by xml_buffer.
 *
 * @param dgst_ctx The digest method to use.
 * @param doc The DOM Document to generate a digest for.
 * @param digest_out On success, this will be set to a newly allocated buffer
 * that contains the binary version of the digest. It is up to the caller to
 * release this memory with a call to free().
 * @param digest_len On success, this will be set to the length, in bytes, of
 * \pdigest_buffer.
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jal_digest_xml_data(const struct jal_digest_ctx *dgst_ctx,
		XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *doc,
		uint8_t **digest_out,
		int *digest_len);

/**
 * Helper function return a Transforms element.
 *
 * @param[in] doc The document to use when creating elements.
 * @param[in,out] new_elem Pointer that will be assigned to the newly created
 * Transforms element.
 *
 * @return JAL_OK,  or JAL_E_XML_CONVERSION on error
 */
enum jal_status jalp_create_audit_transforms_elem(DOMDocument *doc, DOMElement **new_elem);

#endif // JAL_XML_UTILS_HPP
