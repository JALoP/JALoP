/**
 * @file jalp_transform_xml.c This file defines functions to deal with
 * converting a jalp_transform struct to XML.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <libxml/uri.h>

#include <jalop/jal_namespaces.h>
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jal_status.h>
#include "jalp_transform_xml.h"
#include "jal_asprintf_internal.h"
#include "jal_xml_utils.h"

#define JALP_XML_AES256_URI "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
#define JALP_XML_AES256 "AES256"
#define JALP_XML_XOR "XOR"
#define JALP_XML_ALGORITHM "Algorithm"
#define JALP_XML_TRANSFORM "Transform"
#define JALP_XML_IV "IV"
#define JALP_XML_AES128 "AES128"
#define JALP_XML_XOR_URI "http://www.dod.mil/algorithms/encryption#xor32-ecb"
#define JALP_XML_AES192_URI "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
#define JALP_XML_DEFLATE_URI "http://www.dod.mil/algorithms/compression#deflate"
#define JALP_XML_AES128_URI "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
#define JALP_XML_KEY "Key"
#define JALP_XML_AES192 "AES192"

enum jal_status jalp_transform_to_elem(
		const struct jalp_transform *transform,
		xmlDocPtr doc,
		xmlNodePtr *out)
{
	enum jal_status ret = JAL_E_INVAL_TRANSFORM;
	/* null checks on args */
	if(!doc || !transform || !out || *out) {
		return JAL_E_XML_CONVERSION;
	}

	*out = NULL;
	xmlChar *namespace_uri = (xmlChar *)JAL_APP_META_TYPES_NAMESPACE_URI;
	xmlNodePtr transform_elm = xmlNewDocNode(doc, NULL,
						(xmlChar *)JALP_XML_TRANSFORM,
						NULL);
	xmlNsPtr ns = xmlNewNs(transform_elm, namespace_uri, NULL);
	xmlSetNs(transform_elm, ns);

	switch (transform->type) {
	case JALP_TRANSFORM_OTHER:
		ret = jalp_transform_to_elem_handle_custom(&transform_elm,
					transform->other_info);
		if (ret != JAL_OK) {
			goto error_out;
		}
		break;
	case JALP_TRANSFORM_XOR:
		ret = jalp_transform_to_elem_handle_xor(doc,
					&transform_elm,
					namespace_uri,
					transform->enc_info);
		if (ret != JAL_OK) {
			goto error_out;
		}
		break;
	case JALP_TRANSFORM_AES128:
		ret = jalp_transform_to_elem_handle_aes(doc,
				&transform_elm,
				namespace_uri,
				(xmlChar *)JALP_XML_AES128,
				(xmlChar *)JALP_XML_AES128_URI,
				JALP_TRANSFORM_AES128_KEYSIZE,
				transform->enc_info);
		if (ret != JAL_OK) {
			goto error_out;
		}
		break;
	case JALP_TRANSFORM_AES192:
		ret = jalp_transform_to_elem_handle_aes(doc,
				&transform_elm,
				namespace_uri,
				(xmlChar *)JALP_XML_AES192,
				(xmlChar *)JALP_XML_AES192_URI,
				JALP_TRANSFORM_AES192_KEYSIZE,
				transform->enc_info);
		if (ret != JAL_OK) {
			goto error_out;
		}
		break;
	case JALP_TRANSFORM_AES256:
		ret = jalp_transform_to_elem_handle_aes(doc,
				&transform_elm,
				namespace_uri,
				(xmlChar *)JALP_XML_AES256,
				(xmlChar *)JALP_XML_AES256_URI,
				JALP_TRANSFORM_AES256_KEYSIZE,
				transform->enc_info);
		if (ret != JAL_OK) {
			goto error_out;
		}
		break;
	case JALP_TRANSFORM_DEFLATE:
		xmlSetProp(transform_elm, (xmlChar *)JALP_XML_ALGORITHM,
				(xmlChar *)JALP_XML_DEFLATE_URI);
		break;
	default:
		goto error_out;
	}
	ret = JAL_OK;
	goto out;

error_out:
	if (transform_elm) {
		xmlFreeNode(transform_elm);
	}
	transform_elm = NULL;
out:
	*out = transform_elm;
	return ret;
}

enum jal_status jalp_transform_to_elem_handle_custom(
		xmlNodePtr *transform_elm,
		const struct jalp_transform_other_info *other_info)
{
	xmlChar *xml_algorithm = NULL;
	enum jal_status ret = JAL_OK;
	if (!other_info || !other_info->uri) {
		ret = JAL_E_INVAL_TRANSFORM;
		goto out;
	}
	xml_algorithm = (xmlChar *) other_info->uri;
	if (!xmlParseURI(other_info->uri)) {
		ret = JAL_E_INVAL_URI;
		goto out;
	}
	xmlSetProp(*transform_elm, (xmlChar *)JALP_XML_ALGORITHM, xml_algorithm);

	xmlNodePtr child_elm = NULL;
	if (other_info->xml) {
		ret = jal_parse_xml_snippet(&child_elm, other_info->xml);
		xmlAddChild(*transform_elm, child_elm);
	}
out:
	return ret;
}

enum jal_status jalp_transform_to_elem_handle_xor(
		xmlDocPtr doc,
		xmlNodePtr *transform_elm,
		const xmlChar *namespace_uri,
		const struct jalp_transform_encryption_info *enc_info)
{
	enum jal_status ret = JAL_OK;
	// A key is required, but IV is disallowed.
	xmlNodePtr xor_elm = NULL;
	xmlNodePtr key_elm = NULL;
	if (!enc_info || !enc_info->key || enc_info->iv) {
		ret = JAL_E_INVAL_TRANSFORM;
		goto error_out;
	}
	ret = jal_create_base64_element(doc,
			enc_info->key,
			JALP_TRANSFORM_XOR_KEYSIZE,
			namespace_uri,
			(xmlChar *)JALP_XML_KEY,
			&key_elm);
	if (ret != JAL_OK) {
		ret = JAL_E_XML_CONVERSION;
		goto error_out;
	}

	xmlSetProp(*transform_elm, (xmlChar *)JALP_XML_ALGORITHM, (xmlChar *)JALP_XML_XOR_URI);

	xor_elm = xmlNewChild(*transform_elm, NULL, (xmlChar *)JALP_XML_XOR, NULL);
	xmlAddChild(xor_elm, key_elm);

	goto out;
error_out:
	if (xor_elm) {
		xmlFreeNode(xor_elm);
	} else if (key_elm) {
		xmlFreeNode(key_elm);
	}

out:
	return ret;
}

enum jal_status jalp_transform_to_elem_handle_aes(
		xmlDocPtr doc,
		xmlNodePtr *transform_elm,
		const xmlChar *namespace_uri,
		const xmlChar *elm_name,
		const xmlChar *algorithm,
		const size_t key_size,
		const struct jalp_transform_encryption_info *enc_info)
{
	enum jal_status ret = JAL_OK;
	xmlNodePtr key_elm = NULL;
	xmlNodePtr iv_elm = NULL;
	xmlNodePtr aes_elm = NULL;
	if (enc_info) {
		if (enc_info->key) {
			ret = jal_create_base64_element(doc,
					enc_info->key,
					key_size,
					namespace_uri,
					(xmlChar *)JALP_XML_KEY,
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
					(xmlChar *)JALP_XML_IV,
					&iv_elm);
			if (ret != JAL_OK) {
				ret = JAL_E_XML_CONVERSION;
				goto error_out;
			}
		}
	}
	aes_elm = xmlNewChild(
			*transform_elm,
			NULL,
			elm_name,
			NULL);

	if (key_elm) {
		xmlAddChild(aes_elm, key_elm);
	}
	if (iv_elm) {
		xmlAddChild(aes_elm, iv_elm);
	}
	xmlSetProp(*transform_elm, (xmlChar *)JALP_XML_ALGORITHM, algorithm);
	goto out;

error_out:
	if (aes_elm) {
		xmlFreeNode(aes_elm);
	} else {
		if (iv_elm) {
			xmlFreeNode(iv_elm);
		}
		if (key_elm) {
			xmlFreeNode(key_elm);
		}
	}
out:
	return ret;
}
