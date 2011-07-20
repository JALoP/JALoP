/**
 * @file jalp_audit_helper.h C interface to helper functions for generating the
 * application metadata XML related to an audit record.
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
#ifndef __JALP_AUDIT_HELPER_H__
#define __JALP_AUDIT_HELPER_H__
#include <stdint.h>
#include <jalop/jalp_context.h>
#include <jalop/jalp_app_metadata.h>

enum jal_status jalp_audit_app_meta_helper(jalp_context *ctx, struct jalp_app_metadata *app_meta,
		const uint8_t *audit_buffer, const size_t log_buffer_size,
		uint8_t **app_meta_buffer, size_t *app_meta_buf_len);
#endif // __JALP_AUDIT_HELPER_H__
