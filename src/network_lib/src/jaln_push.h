/**
 * @file jaln_push.h
 *
 * Functions for sending records from a publisher to a subscriber.
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
#ifndef _JALN_PUSH_H_
#define _JALN_PUSH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "jaln_session.h"

/* This must match JALDB_MAX_NETWORK_NONCE_LENGTH in jaldb_serialize_record.h
 *
 * In the network library, this is used to ensure the publisher's nonce
 * can be serialized and deserialized as a network_nonce once it sent
 * over the network. */
#define JALN_MAX_NONCE_LENGTH 127

/*
 * Helper method used to initialize the record information
 * that is to be sent to the subscriber.
 */
enum jal_status jaln_send_record_init(
			jaln_session *sess,
			void *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len, 
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			struct jaln_record_info *rec_info);

/*
 * Helper method used to send the record, in the form of buffers,
 * to the subscriber.
 *
 * This method initializes the record information to be sent and
 * subsequently initiates the process of sending the record to the
 * subscriber.
 */
enum jal_status jaln_send_record(
			jaln_session *sess,
			char *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len, 
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			uint8_t *payload_buf,
			uint64_t payload_len);

/*
 * Helper method used to send a record, via a feeder, to the
 * subscriber.
 * 
 * This method initializes the record information to be sent,
 * reads the payload data from the feeder, and subsequently
 * initiates the process of sending the record to the subscriber.
 *
 * TODO: Convert audit and log handling to feeders.
 */
enum jal_status jaln_send_record_feeder(
			jaln_session *sess,
			char *nonce,
			uint8_t *sys_meta_buf,
			uint64_t sys_meta_len, 
			uint8_t *app_meta_buf,
			uint64_t app_meta_len,
			uint64_t payload_len,
			uint64_t offset,
			struct jaln_payload_feeder *feeder);

#ifdef __cplusplus
}
#endif

#endif // _JALN_NETWORK_
