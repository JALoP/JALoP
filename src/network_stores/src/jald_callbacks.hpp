/**
 * @file
 *
 * @brief This file contains the definitions of function callbacks invoked by
 * the jaln network_lib to pass information to jald.
 *
 * ### LICENSE
 *
 * Copyright (C) 2025 Concurrent Technologies Corporation.
 * Copyright (c) 2012-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <jalop/jaln_network.h>

/** jald-specific implementation for the callback "on_channel_close" offered by
 * the jaln_network library. Shuts down the lmdb_lib handle or signals the filter
 * to terminate a particular stream, depending on filter configuration, then triggers
 * other channels on the same connection to also close.
 *
 * @param[in] ch_info Non-owning pointer to information about the channel which is
 * closing
 * @param[in] user_data a struct peer_config_t* (passed as void*) used to access
 * the associated channels
 */
void on_channel_close(
		const struct jaln_channel_info *ch_info,
		void *user_data);

/** jald-specific implementation for the callback "on_connection_close" offered by
 * the jaln_network library. Signals that the entire connection to the subscriber
 * is shutting down. Instructs all associated channels to shut down.
 *
 * @param[in] jal_conn Infomation about the connection which is closing. Unused
 * @param[in] user_data a struct peer_config_t* (passed as void*) used to access
 * the connection which is closing.
 */
void on_connection_close(
		const struct jaln_connection *jal_conn,
		void *user_data);

/** jald-specific implementation for the callback "on_connect_ack" offered by
 * the jaln_network  library. Signals that an INIT_ACK message has been received
 * from the subscriber.
 *
 * @param[in] ack Information about the received ack
 * @param[in] user_data Unused
 */
void on_connect_ack(
		const struct jaln_connect_ack *ack,
		void *user_data);

/** jald-specific implementation for the callback "on_connect_nack" offered by
 * the jaln_network library. Signals that an INIT_NACK message has been received
 * from the subscriber.
 *
 * @param[in] nack Information about the received nack
 * @param[in] user_data Unused
 */
void on_connect_nack(
		const struct jaln_connect_nack *nack,
		void *user_data);

/** jald-specific implementation for the callback "on_journal_resume" offered by
 * the jaln_network library. Indicates that the init-ack message requested a journal
 * resume.
 *
 * @param[in] sess Unused
 * @param[in] ch_info Used to select appropriate session from the session maps and to
 * correctly annotate DEBUG_LOG_* messages
 * @param[in] record_info Contains information about the record being resumed
 * @param[in] offset Unused
 * @param[out] system_metadata_buffer Set to point to the system metadata payload of the
 * record being resumed
 * @param[out] application_metadata_buffer Set to point to the application metadata payload
 * of the record being resumed
 * @param[in] headers Unused
 * @param[in] user_data Unused
 *
 * @return JAL_OK on successful handling of the resume request and successful handling
 * of the subscriber. Otherwise a jal_status error code.
 */
enum jal_status pub_on_journal_resume(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		struct jaln_record_info *record_info,
		uint64_t offset,
		uint8_t **system_metadata_buffer,
		uint8_t **application_metadata_buffer,
		struct jaln_mime_header *headers,
		void *user_data);

/** jald-specific implementation for the callback "on_subscribe" offered by
 * the jaln_network library. Creates the thread to handle lookup and sending of
 * the requested record type.
 *
 * @param[in] sess  The jaln_session created to handle this subscription by the
 * network library
 * @param ch_info Information about the channel created to handle this record type
 * by the network library
 * @param[in] type The record type for this channel
 * @param[in] mode The mode for this channel
 * @param[in] headers Unused
 * @param[in] user_data Unused
 *
 * @return JAL_OK on successful creation of the send thread. Otherwise a
 * jal_status error code.
 */
enum jal_status pub_on_subscribe(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		enum jaln_publish_mode mode,
		struct jaln_mime_header *headers,
		void *user_data);

/** jald-specific implementation for the callback "on_record_complete" offered by
 * the jaln_network library. Invoked when a record response has been sucesfully sent
 * to the subscriber. Note that this does not mean the digest challenge (if enabled)
 * was sucesfully, or that the  subscriber has fully processed the record, only that
 * the network library finished sending it.
 *
 * @param[in] sess Information about the subscriber session
 * @param[in] ch_info Information about the specific channel on which the record was
 * sent
 * @param[in] type The type of the record sent
 * @param[in] nonce The id of the record sent
 * @param[in] user_data Unused
 *
 * @return JAL_OK if the notification was succesfully handled. Otherwise a jal_status
 * error code.
 */
enum jal_status pub_on_record_complete(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		char *nonce,
		void *user_data);

/** jald-specific implementation for the callback "sync" offered by
 * the jaln_network library. Invoked when a sync response has been received from the
 * subscriber, indicating a record was accepted by the subscriber.
 *
 * @param[in] sess Unused
 * @param[in] ch_info Information about the specific channel on which the record was
 * sent
 * @param[in] type The type of the record sent
 * @param[in] mode The mode of the subscriber channel
 * @param[in] nonce The id of the record sent
 * @param[in] headers Unused
 * @param[in] user_data Unused
 *
 * @return JAL_OK if the notification was succesfully handled. Otherwise a jal_status
 * error code.
 */
void pub_sync(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		enum jaln_publish_mode mode,
		const char *nonce,
		struct jaln_mime_header *headers,
		void *user_data);

/** jald-specific implementation for the callback "notify_digest" offered by
 * the jaln_network library. Invoked when a digest is locally calculated for a record.
 *
 * @param[in] sess Unused
 * @param[in] ch_info Channel information for debug print
 * @param[in] type Unused
 * @param[in] nonce Nonce of the record for which the digest was generated
 * @param[in] digest The digest generated
 * @param[in] size The size of the digest
 * @param[in] user_data Unused
 */
void pub_notify_digest(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *nonce,
		const uint8_t *digest,
		const uint32_t size,
		void *user_data);

/** jald-specific implementation for the callback "peer_digest" offered by
 * the jaln_network library. Invoked when a digest challenge message is received to provide
 * the peer-calculated and locally-calculated digest to jald for additional inspection
 * or handling.
 *
 * @param[in] sess Unused
 * @param[in] ch_info Channel information for debug print
 * @param[in] type Type of the record for which the digest was generated
 * @param[in] nonce Nonce of the record for which the digest was generated
 * @param[in] local_digest Locally calculated digest
 * @param[in] local_size The size of the locally calculated digest
 * @param[in] peer_digest The digest as calculated by the subscriber
 * @param[in] peer_size The size of the peer_digest
 * @param[in] user_data Unused
 */
void pub_peer_digest(
		jaln_session *sess,
		const struct jaln_channel_info *ch_info,
		enum jaln_record_type type,
		const char *nonce,
		const uint8_t *local_digest,
		const uint32_t local_size,
		const uint8_t *peer_digest,
		const uint32_t peer_size,
		void *user_data);
