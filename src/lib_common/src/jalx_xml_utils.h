/**
 * @file jalx_xml_utils.h This file defines helper functions for dealing with
 * creating/reading XML data.
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
#ifndef _JALX_XML_UITLS_H_
#define _JALX_XML_UITLS_H_

#include <jalop/jal_status.h>
#include <libxml/tree.h>
#include <unistd.h> // for size_t

// XML-Security-C (XSEC)
//#include <xsec/framework/XSECProvider.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>


/**
 * Helper function to parse an xml snippet.
 *
 * @param[in] ctx_node A node to use as the parent of elements encountered during the parse.
 * @param[in] snippet a snippet of XML. The contents will be added to \pctx_node.
 * @return JAL_OK on success or JAL_E_XML_PARSE if there was an error parsing the
 * snippet.
 */
enum jal_status jalx_parse_xml_snippet(
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
enum jal_status jalx_create_base64_element(
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
char *jalx_get_timestamp();

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
enum jal_status jalx_create_reference_elem(
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
enum jal_status jalx_create_audit_transforms_elem(
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
enum jal_status jalx_xml_output(
		xmlDocPtr doc,
		xmlChar **buffer);

#endif // _JALX_XML_UITILS_H_

