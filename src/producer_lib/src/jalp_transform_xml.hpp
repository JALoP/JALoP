/**
 * @file jalp_transform_xml.hpp This file defines functions to deal with
 * converting a jalp_stransform struct to XML.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below
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
#ifndef _JALP_TRANSFORM_XML_HPP_
#define _JALP_TRANSFORM_XML_HPP_

#include <xercesc/dom/DOM.hpp>

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jal_status.h>


XERCES_CPP_NAMESPACE_USE

/**
 * Convert a jalp_transform struct to a DOMDocument element
 * for use with the Xerces XML library.
 *
 * @param[in] transform The jalp_transform struct to convert.
 * @param[in] doc The DOMDocument to create the DOMElement from. Maintains the same namespace
 * @param[out] out A pointer to store the new element in. This will get set
 * to NULL on error, otherwise a newly created element.
 * @return 
 *  - JAL_OK on success
 *  - JAL_E_XML_PARSE if there was a problem parsing the block of XML code.
 */
enum jal_status jalp_transform_to_elem(const struct jalp_transform *transform, DOMDocument *doc, DOMElement **out);
/**
 * Helper function to handle adding child elements 'custom' transform types.
 *
 * @param[in] transform_elm The DOMElement to add to.
 * @param[in] other_info Structure containing the uri and xml snippet to add
 * to \ptransform_elm
 * @return 
 * - JAL_OK On success
 * - JAL_E_XML_PARSE if there was an error parsing the XML snippet
 * - JAL_E_INVALID_URI If the field is not a valid uri.
 */
enum jal_status jalp_transform_to_elem_handle_custom(DOMElement *transform_elm, const jalp_transform_other_info *other_info);
/**
 * Helper function to add elements to a transform for the XOR transform. The
 * URI attribute of \ptransform_elm will be set to the URI for XOR and a child
 * element that contains the XOR key will be appended.
 * @param[in] doc The document to use when creating elements.
 * @param[in] transform_elm The transform element to add to for an XOR
 * transform.
 * @param[in] namespace_uri The URI to use as the namespace of the new element.
 * @param[in] enc_info An enc_info structure that must contain a key, but no
 * IV.
 * @return
 *  - JAL_E_INVALID_TRANSFORM if enc_info is NULL, does not contain a key, 
 *  contains an IV, or the IV
 *  - JAL_OK On success.
 *
 */
enum jal_status jalp_transform_to_elem_handle_xor(DOMDocument *doc, DOMElement *transform_elm, const XMLCh *namespace_uri, const jalp_transform_encryption_info *enc_info);
/**
 * Helper function to add elements to a transform for the XOR stransform.
 * @param[in] doc The document to use when creating elements.
 * @param[in] transform_elm The DOMElement to add to.
 * @param[in] namespace_uri The URI to use as the namespace of the new element.
 * @param[in] elm_name The name that should be given to the new element.
 * @param[in] algorithm The algorithm to set as the Algorithm attribute.
 * @param[in] key_size The size, in bytes of the AES key
 * @param[in] enc_info The enc_info to use for this element. If enc_info->key
 *                     is non-null, a "Key" element will be added to the 
 *                     \ptransform_elm. enc_info->vi is non-null, an "IV" 
 *                     element will be added to the \ptransform_elm.
 */
enum jal_status jalp_transform_to_elem_handle_aes(DOMDocument *doc, DOMElement *transform_elm, const XMLCh *namespace_uri, const XMLCh *elm_name, 
		const XMLCh* algorithm, const size_t key_size, const jalp_transform_encryption_info *enc_info);

#endif //_JALP_TRANSFORM_XML_HPP_
