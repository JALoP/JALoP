/**
 * @file jalp_digest_audit_xml.h Provides a function for parsing, validating,
 * and digesting an audit XML file.
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
#ifndef _JALP_DIGEST_AUDIT_XML_H_
#define _JALP_DIGEST_AUDIT_XML_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <jalop/jal_status.h>
#include <stdint.h>
#include <unistd.h>
/**
 * Parse a byte buffer as XML and validate it against the MITRE CEE audit
 * schema.
 *
 */
enum jal_status jalp_digest_audit_record(const struct jal_digest_ctx *ctx,
		char *schema_root,
		uint8_t *buffer,
		size_t buf_len,
		uint8_t**digest_value,
		int *digest_len);

#ifdef __cplusplus
}
#endif

#endif //_JALP_DIGEST_AUDIT_XML_H_

