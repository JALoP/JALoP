/**
 * @file
 *
 * @brief This file contains function declarations for code related
 * to sending JAL records to the Subscriber.
 *
 * ### LICENSE
 *
 * Copyright (C) 2018-2026 Concurrent Technologies Corporation.
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
#pragma once
#ifdef __cplusplus
extern "C" {
#endif
#include <jalop/jal_status.h>
#include "jaln_session.h"
#include "jaldb_record.h"

enum jal_status jaln_send_record_impl(
	jaln_session* sess,
	struct jaldb_record* rec,
	uint8_t** digestOut,
	uint32_t* digestLenOut,
	uint8_t** peerDigestOut,
	uint32_t* peerDigestLenOut);

enum jal_status jaln_send_digest_response_impl(
	jaln_session* sess,
	const char* paramNonce,
	const uint8_t* localDigest,
	const uint32_t localLen,
	const uint8_t* peerDigest,
	const int32_t peerLen);

#ifdef __cplusplus
}
#endif
