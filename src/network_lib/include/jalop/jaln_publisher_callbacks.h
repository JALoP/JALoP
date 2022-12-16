/**
 * @file jaln_publisher_callbacks.h This file declares jaln_publisher_callbacks
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
#ifndef _JALN_PUBLISHER_CALLBACKS_H_
#define _JALN_PUBLISHER_CALLBACKS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/jaln_network_types.h>
#include <stdlib.h>

/**
 * @struct jaln_publisher_callbacks
 * The application must fill one of these in for each accepted connection.
 *
 */
struct jaln_publisher_callbacks {
	/**
	 * The JNL will execute this callback when it receives a
	 * 'journal-resume' message.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in,out] record_info The JNL will fill in the nonce,
	 * applications must fill in the rest of this structure.
	 * @param[in] offset The offset into the record the peer would like to
	 * begin transferring from.
	 * @param[out] system_metadata_buffer a user allocated buffer that contains the bytes
	 * of the system metadata. The \p sys_meta_len field of \p record_info
	 * indicates the size of this buffer.
	 * @param[out] application_metadata_buffer a user allocated buffer that contains the bytes
	 * of the application metadata. The \p sys_meta_len field of
	 * \p record_info indicates the size of this buffer.
	 * @param[in] headers additional mime headers sent as part of this message
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_publish.
	 *
	 * @return JAL_OK to continue sending the resumed record, JAL_E_JOURNAL_MISSING to send the
	 * next record, or anything else to stop.
	 */
	enum jal_status (*on_journal_resume)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			struct jaln_record_info *record_info,
			uint64_t offset,
			uint8_t **system_metadata_buffer,
			uint8_t **application_metadata_buffer,
			struct jaln_mime_header *headers,
			void *user_data);

	/**
	 * The JNL executes this callback to inform the application of a
	 * 'subscribe' message. This callback is purely informational.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of records the remote is subscribing 
	 * to (journal, audit, or log).
	 * @param[in] mode The mode with which to publish record (archive or live)
	 * @param[in] headers additional mime headers sent as part of this message
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_publish.
	 * @return JAL_OK to continue sending records, anything else to stop.
	 */
	enum jal_status (*on_subscribe)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			enum jaln_publish_mode mode,
			struct jaln_mime_header *headers,
			void *user_data);

	/**
	 * The JNL calls this once the record is fully sent, or the
	 * connection/channel is severed. It provides a chance for the
	 * application to clean up any resources (including those in
	 * record_info);
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of record (journal, audit, or log)
	 * @param[in] nonce The nonce of this record_info
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_publish.
	 */
	enum jal_status (*on_record_complete)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			char *nonce,
			void *user_data);

	/**
	 * The JNL executes this callback when it receives a 'sync' message
	 * from the peer.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of record (journal, audit, or log)
	 * @param[in] mode The connection mode
	 * @param[in] nonce the nonce of the record sent by the remote peer.
	 * @param[in] headers Any additional headers sent with this message.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_publish.
	 *
	 */
	void (*sync)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			enum jaln_publish_mode mode,
			const char *nonce,
			struct jaln_mime_header *headers,
			void *user_data);

	/**
	 * Informs the application of the calculated checksum of the record
	 * identified by nonce. This is the checksum calculated as the
	 * record is sent, not the digest received by the remote side. This is
	 * purely informational as the JNL maintains the sent of sent, but not
	 * yet confirmed digests.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of record (journal, audit, or log)
	 * @param[in] nonce The nonce of the record.
	 * @param[in] digest The digest value of the record.
	 * @param[in] lenght The length of the digest, in bytes.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_publish.
	 *
	 * @note should the JNL really track the digests? seems like a
	 * reasonable feature, but may need some extra tuning parameters or
	 * callbacks so the applications can start flushing memory, or should
	 * cache to disk unconfirmed digests...
	 */
	void (*notify_digest)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			const char *nonce,
			const uint8_t *digest,
			const uint32_t size,
			void *user_data);

	/**
	 * Inform the application of the calculated checksum sent by the peer.
	 * The JNL tracks the nonce and digests for all records sent on each
	 * channel. The JNL automatically checks the peer's calculated digest
	 * against the locally calculated digest and builds an appropriate
	 * 'digest-response' message for every 'digest' message. Once the JNL
	 * sends a 'digest-response' message to the peer, the JNL removes the
	 * entry from its internal structures.
	 *
	 * This is called for each record in the 'digest' message.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of record (journal, audit, or log)
	 * @param[in] nonce The nonce of a particular record
	 * @param[in] local_digest The digest, as calculated by the JNL when the
	 * record was sent. If the nonce of this record has not been seen, or 
	 * was already flushed from memory, \p local_digest will be NULL.
	 * @param[in] local_size The size, in bytes, of the local_digest. If
	 * the nonce of this record has not been seen, or was already flushed 
	 * from memory, \p local_size will be 0.
	 * @param[in] peer_digest The digest, as calculated by the remote peer.
	 * @param[in] peer_size The size, in bytes, of #peer_digest
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_publish.
	 */
	void (*peer_digest)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			const char *nonce,
			const uint8_t *local_digest,
			const uint32_t local_size,
			const uint8_t *peer_digest,
			const uint32_t peer_size,
			void *user_data);
};

/**
 * Create a jaln_publisher_callbacks structure
 *
 * @return a newly created and initialized jaln_publisher_callbacks structure.
 */
struct jaln_publisher_callbacks *jaln_publisher_callbacks_create();

/**
 * Destroy a jaln_publisher_callbacks structure
 *
 * @param[in,out] callbacks The structure to destroy. This will 
 *       be set to NULL.
 */
void jaln_publisher_callbacks_destroy(struct jaln_publisher_callbacks **callbacks);


#ifdef __cplusplus
}
#endif

#endif // _JALN_PUBLISHER_CALLBACKS_H_
