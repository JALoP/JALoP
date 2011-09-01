/**
 * @file jalp_transform_xml.cpp This file defines functions to deal with
 * converting a jalp_transform struct to XML.
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

#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/XMLUri.hpp>

// these are for the parse function...
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jal_status.h>
#include "jalp_transform_xml.hpp"
#include "jal_asprintf_internal.h"
#include "jal_xml_utils.hpp"

XERCES_CPP_NAMESPACE_USE
static const XMLCh JALP_XML_AES256_URI[] = {
	chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash,
	chForwardSlash, chLatin_w, chLatin_w, chLatin_w, chPeriod, chLatin_w,
	chDigit_3, chPeriod, chLatin_o, chLatin_r, chLatin_g, chForwardSlash,
	chDigit_2, chDigit_0, chDigit_0, chDigit_1, chForwardSlash, chDigit_0,
	chDigit_4, chForwardSlash, chLatin_x, chLatin_m, chLatin_l, chLatin_e,
	chLatin_n, chLatin_c, chPound, chLatin_a, chLatin_e, chLatin_s,
	chDigit_2, chDigit_5, chDigit_6, chDash, chLatin_c, chLatin_b, chLatin_c,
	chNull };

static const XMLCh JALP_XML_AES256[] = {
	chLatin_A, chLatin_E, chLatin_S, chDigit_2, chDigit_5, chDigit_6,
	chNull };
static const XMLCh JALP_XML_XOR[] = {
	chLatin_X, chLatin_O, chLatin_R, chNull };
static const XMLCh JALP_XML_ALGORITHM[] = {
	chLatin_A, chLatin_l, chLatin_g, chLatin_o, chLatin_r, chLatin_i,
	chLatin_t, chLatin_h, chLatin_m, chNull };
static const XMLCh JALP_XML_TRANSFORM[] = {
	chLatin_T, chLatin_r, chLatin_a, chLatin_n, chLatin_s, chLatin_f,
	chLatin_o, chLatin_r, chLatin_m, chNull };
static const XMLCh JALP_XML_IV[] = {
	chLatin_I, chLatin_V, chNull };
static const XMLCh JALP_XML_AES128[] = {
	chLatin_A, chLatin_E, chLatin_S, chDigit_1, chDigit_2, chDigit_8,
	chNull };
static const XMLCh JALP_XML_XOR_URI[] = {
	chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash,
	chForwardSlash, chLatin_w, chLatin_w, chLatin_w, chPeriod, chLatin_d,
	chLatin_o, chLatin_d, chPeriod, chLatin_m, chLatin_i, chLatin_l,
	chForwardSlash, chLatin_a, chLatin_l, chLatin_g, chLatin_o, chLatin_r,
	chLatin_i, chLatin_t, chLatin_h, chLatin_m, chLatin_s, chForwardSlash,
	chLatin_e, chLatin_n, chLatin_c, chLatin_r, chLatin_y, chLatin_p,
	chLatin_t, chLatin_i, chLatin_o, chLatin_n, chPound, chLatin_x,
	chLatin_o, chLatin_r, chDigit_3, chDigit_2, chDash, chLatin_e,
	chLatin_c, chLatin_b, chNull };
static const XMLCh JALP_XML_AES192_URI[] = {
	chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash,
	chForwardSlash, chLatin_w, chLatin_w, chLatin_w, chPeriod, chLatin_w,
	chDigit_3, chPeriod, chLatin_o, chLatin_r, chLatin_g, chForwardSlash,
	chDigit_2, chDigit_0, chDigit_0, chDigit_1, chForwardSlash, chDigit_0,
	chDigit_4, chForwardSlash, chLatin_x, chLatin_m, chLatin_l, chLatin_e,
	chLatin_n, chLatin_c, chPound, chLatin_a, chLatin_e, chLatin_s,
	chDigit_1, chDigit_9, chDigit_2, chDash, chLatin_c, chLatin_b,
	chLatin_c, chNull };
static const XMLCh JALP_XML_DEFLATE_URI[] = {
	chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash,
	chForwardSlash, chLatin_w, chLatin_w, chLatin_w, chPeriod, chLatin_d,
	chLatin_o, chLatin_d, chPeriod, chLatin_m, chLatin_i, chLatin_l,
	chForwardSlash, chLatin_a, chLatin_l, chLatin_g, chLatin_o, chLatin_r,
	chLatin_i, chLatin_t, chLatin_h, chLatin_m, chLatin_s, chForwardSlash,
	chLatin_c, chLatin_o, chLatin_m, chLatin_p, chLatin_r, chLatin_e,
	chLatin_s, chLatin_s, chLatin_i, chLatin_o, chLatin_n, chPound,
	chLatin_d, chLatin_e, chLatin_f, chLatin_l, chLatin_a, chLatin_t,
	chLatin_e, chNull };
static const XMLCh JALP_XML_AES128_URI[] = {
	chLatin_h, chLatin_t, chLatin_t, chLatin_p, chColon, chForwardSlash,
	chForwardSlash, chLatin_w, chLatin_w, chLatin_w, chPeriod, chLatin_w,
	chDigit_3, chPeriod, chLatin_o, chLatin_r, chLatin_g, chForwardSlash,
	chDigit_2, chDigit_0, chDigit_0, chDigit_1, chForwardSlash, chDigit_0,
	chDigit_4, chForwardSlash, chLatin_x, chLatin_m, chLatin_l, chLatin_e,
	chLatin_n, chLatin_c, chPound, chLatin_a, chLatin_e, chLatin_s,
	chDigit_1, chDigit_2, chDigit_8, chDash, chLatin_c, chLatin_b,
	chLatin_c, chNull };
static const XMLCh JALP_XML_KEY[] = {
	chLatin_K, chLatin_e, chLatin_y, chNull };
static const XMLCh JALP_XML_AES192[] = {
	chLatin_A, chLatin_E, chLatin_S, chDigit_1, chDigit_9, chDigit_2,
	chNull };

enum jal_status jalp_transform_to_elem(const struct jalp_transform *transform,
		DOMDocument *doc,
		DOMElement **out)
{
	enum jal_status ret = JAL_E_INVAL_TRANSFORM;
	/* null checks on args */
	if((!doc) || (!transform) || (!out) || (*out)) {
		return JAL_E_XML_CONVERSION;
	}

	*out = NULL;
	XMLCh *namespace_uri =
		XMLString::transcode(JAL_APP_META_TYPES_NAMESPACE_URI);
	DOMElement *transform_elm =
		doc->createElementNS(namespace_uri, JALP_XML_TRANSFORM);

	switch (transform->type) {
	case JALP_TRANSFORM_OTHER:
		ret = jalp_transform_to_elem_handle_custom(transform_elm,
					transform->other_info);
		if (ret != JAL_OK) {
			goto error_out;
		}
		break;
	case JALP_TRANSFORM_XOR:
		ret = jalp_transform_to_elem_handle_xor(doc,
					transform_elm,
					namespace_uri,
					transform->enc_info);
		if (ret != JAL_OK) {
			goto error_out;
		}
		break;
	case JALP_TRANSFORM_AES128:
		ret = jalp_transform_to_elem_handle_aes(doc,
				transform_elm,
				namespace_uri,
				JALP_XML_AES128,
				JALP_XML_AES128_URI,
				JALP_TRANSFORM_AES128_KEYSIZE,
				transform->enc_info);
		if (ret != JAL_OK) {
			goto error_out;
		}
		break;
	case JALP_TRANSFORM_AES192:
		ret = jalp_transform_to_elem_handle_aes(doc,
				transform_elm,
				namespace_uri,
				JALP_XML_AES192,
				JALP_XML_AES192_URI,
				JALP_TRANSFORM_AES192_KEYSIZE,
				transform->enc_info);
		if (ret != JAL_OK) {
			goto error_out;
		}
		break;
	case JALP_TRANSFORM_AES256:
		ret = jalp_transform_to_elem_handle_aes(doc,
				transform_elm,namespace_uri,
				JALP_XML_AES256,
				JALP_XML_AES256_URI,
				JALP_TRANSFORM_AES256_KEYSIZE,
				transform->enc_info);
		if (ret != JAL_OK) {
			goto error_out;
		}
		break;
	case JALP_TRANSFORM_DEFLATE:
		transform_elm->setAttribute(JALP_XML_ALGORITHM,
				JALP_XML_DEFLATE_URI);
		break;
	default:
		goto error_out;
	}
	ret = JAL_OK;
	goto out;

error_out:
	if (transform_elm) {
		transform_elm->release();
	}
	transform_elm = NULL;
out:
	XMLString::release(&namespace_uri);
	*out = transform_elm;
	return ret;
}

enum jal_status jalp_transform_to_elem_handle_custom(DOMElement *transform_elm,
		const jalp_transform_other_info *other_info)
{
	XMLCh *xml_algorithm = NULL;
	enum jal_status ret = JAL_OK;
	if (!other_info || !other_info->uri) {
		ret = JAL_E_INVAL_TRANSFORM;
		goto out;
	}
	xml_algorithm = XMLString::transcode(other_info->uri);
	if (!XMLUri::isValidURI(false, xml_algorithm)) {
		ret = JAL_E_INVAL_URI;
		goto out;
	}
	transform_elm->setAttribute(JALP_XML_ALGORITHM, xml_algorithm);

	if (other_info->xml) {
		ret = jal_parse_xml_snippet(transform_elm, other_info->xml);
	}
out:
	XMLString::release(&xml_algorithm);
	return ret;
}
enum jal_status jalp_transform_to_elem_handle_xor(DOMDocument *doc,
		DOMElement *transform_elm,
		const XMLCh *namespace_uri,
		const jalp_transform_encryption_info *enc_info)
{
	enum jal_status ret = JAL_OK;
	// A key is required, but IV is disallowed.
	DOMElement *xor_elm = NULL;
	DOMElement *key_elm = NULL;
	if (!enc_info || !enc_info->key || enc_info->iv) {
		ret = JAL_E_INVAL_TRANSFORM;
		goto error_out;
	}
	ret = jal_create_base64_element(doc,
			enc_info->key,
			JALP_TRANSFORM_XOR_KEYSIZE,
			namespace_uri,
			JALP_XML_KEY,
			&key_elm);
	if (ret != JAL_OK) {
		ret = JAL_E_XML_CONVERSION;
		goto error_out;
	}

	xor_elm = doc->createElementNS(namespace_uri, JALP_XML_XOR);
	xor_elm->appendChild(key_elm);

	transform_elm->appendChild(xor_elm);
	transform_elm->setAttribute(JALP_XML_ALGORITHM, JALP_XML_XOR_URI);
	goto out;
error_out:
	if (xor_elm) {
		xor_elm->release();
	} else if (key_elm) {
		key_elm->release();
	}
out:
	return ret;
}
enum jal_status jalp_transform_to_elem_handle_aes(DOMDocument *doc,
		DOMElement *transform_elm,
		const XMLCh *namespace_uri,
		const XMLCh *node_name,
		const XMLCh* algorithm,
		const size_t key_size,
		const jalp_transform_encryption_info *enc_info)
{
	enum jal_status ret = JAL_OK;
	DOMElement *key_elm = NULL;
	DOMElement *iv_elm = NULL;
	DOMElement *aes_elm = NULL;
	if (enc_info) {
		if (enc_info->key) {
			ret = jal_create_base64_element(doc,
					enc_info->key,
					key_size,
					namespace_uri,
					JALP_XML_KEY,
					&key_elm);
			if (ret != JAL_OK) {
				ret = JAL_E_XML_CONVERSION;
				goto error_out;
			}
		}
		if (enc_info->iv) {
			ret = jal_create_base64_element(doc,
					enc_info->iv,
					JALP_TRANSFORM_AES_IVSIZE,
					namespace_uri,
					JALP_XML_IV,
					&iv_elm);
			if (ret != JAL_OK) {
				ret = JAL_E_XML_CONVERSION;
				goto error_out;
			}
		}
	}
	aes_elm = doc->createElementNS(namespace_uri, node_name);
	if (key_elm) {
		aes_elm->appendChild(key_elm);
	}
	if (iv_elm) {
		aes_elm->appendChild(iv_elm);
	}
	transform_elm->appendChild(aes_elm);
	transform_elm->setAttribute(JALP_XML_ALGORITHM, algorithm);
	goto out;
error_out:
	if (aes_elm) {
		aes_elm->release();
	} else {
		if (iv_elm) {
			iv_elm->release();
		}
		if (key_elm) {
			key_elm->release();
		}
	}
out:
	return ret;
}

