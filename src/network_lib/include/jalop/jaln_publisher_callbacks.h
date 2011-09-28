/**
 * @file jaln_publisher_callbacks.h
 *
 * @section LICENSE
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
	 * 'journal-resume' message. This function allows the application to
	 * create an application defined subscriber context that the JNL will
	 * pass to the subsequent jaln_publisher_callbacks
	 *
	 * @param[in] headers additional mime headers sent as part of this message
	 * @param[in,out] record_info Information about this record. The JNL
	 * fills in the serial_id field and the application must fill in the
	 * rest. The JNL assumes ownership of this structure and all it data
	 * members. The JNL will call free() and jaln_mime_headers_free()
	 * when the record_info is no longer needed.
	 *
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 * @return JAL_OK to continue sending records, anything else to stop.
	 */
	int (*on_journal_resume)(const struct jaln_channel_info *ch_info,
			struct jaln_record_info *record_info,
			struct jaln_mime_header *headers,
			void *user_data);

	/**
	 * The JNL executes this callback to inform the application of a
	 * 'subscribe' message. This callback is purely informational.
	 *
	 * @param[in] type The type of records the remote is subscribing 
	 * to (journal, audit, or log).
	 * @param[in] serial_id The serial_id in the subscribe message
	 * @param[in] headers additional mime headers sent as part of this message
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 * @return JAL_OK to continue sending records, anything else to stop.
	 */
	int (*on_subscribe)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			const char *serial_id,
			struct jaln_mime_header *headers,
			void *user_data);

	/**
	 * The JNL will execute this callback to obtain the record info for the
	 * next record that should be sent on this channel.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param type The type of record (journal, audit, or log) to obtain
	 * data for.
	 * @param[in] serial_id The serial_id sent by the peer as part of this
	 * 'subscribe' message.
	 * @param[out] record_info The application must properly fill out the
	 * jaln_record_info structure. The JNL assumes ownership of this
	 * structure and any members and will call appropriate functions to
	 * release memory.
	 * @param[out] system_metadata_buffer a user allocated buffer that contains the bytes
	 * of the system metadata. The \p sys_meta_len field of \p record_info
	 * indicates the size of this buffer.
	 * @param[out] application_metadata_buffer a user allocated buffer that contains the bytes
	 * of the application metadata. The \p sys_meta_len field of
	 * \p record_info indicates the size of this buffer.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @note The JNL executes release_metadata_buffers when it no longer
	 * needs access to \p system_metadata_buffer and
	 * \p application_metadata_buffer.
	 *
	 * @return JAL_OK to continue sending records, anything else will
	 * complete the ANS stream
	 */
	int (*get_next_record_info_and_metadata)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			const char *last_serial_id,
			struct jaln_record_info *record_info,
			uint8_t **system_metadata_buffer,
			uint8_t **application_metadata_buffer,
			void *user_data);

	/**
	 * The JNL execute this callback when it is no longer using the bytes
	 * of the system metadata and application metadata. 
	 * Applications must
	 * release any resources allocated when the JNL executed
	 * \p get_next_record_info_and_metadata
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The serial_id of the record.
	 * @param[in] system_metadata_buffer The buffer obtained by the call
	 * to \p get_next_record_info_and_metadata.
	 * @param[in] application_metadata_buffer The buffer obtained by the call
	 * to \p get_next_record_info_and_metadata.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue sending records, anything else will
	 * complete the ANS stream.
	 */
	int (*release_metadata_buffers)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			uint8_t *system_metadata_buffer,
			uint8_t *application_metadata_buffer,
			void *user_data);

	/**
	 * Acquire a pointer to the log payload. The buffer must contain the
	 * same number of bytes as were designated in the
	 * #jaln_record_info obtained in #get_next_record_info_and_metadata(). When the JNL
	 * is finished with this buffer, it will call release_log_data()
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The serial_id of the record to get.
	 * @param[out] buffer a user allocated buffer that contains the bytes
	 * of the log entry.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue sending records, anything else will
	 * complete the ANS stream.
	 */
	int (*acquire_log_data)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			uint8_t **buffer,
			void *user_data);

	/**
	 * Release the log buffer.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The serial id relating to this buffer
	 * @param[in] buffer a pointer that was obtained by the call to
	 * acquire_log_buffer()
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue sending records, anything else will
	 * complete the ANS stream.
	 */
	int (*release_log_data)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			uint8_t *buffer,
			void *user_data);

	/**
	 * Acquire a pointer to audit data. The buffer must contain the
	 * same number of bytes as were designated in the jaln_record_info
	 * obtained by calling get_next_record_info_and_metadata(). When the JNL is finished
	 * with this buffer, it will call release_audit_data();
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The serial_id of the record to get.
	 * @param[out] buffer a user allocated buffer that contains the bytes
	 * of the payload.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue sending records, anything else will
	 * complete the ANS stream.
	 */
	int (*acquire_audit_data)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			uint8_t **buffer,
			void *user_data);

	/**
	 * Release the audit buffer.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The serial id relating to this buffer
	 * @param[in] a pointer that was obtained by a call to
	 * acquire_audit_data()
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue sending records, anything else will
	 * complete the ANS stream.
	 */
	int (*release_audit_data)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			uint8_t *buffer,
			void *user_data);

	/**
	 * Acquire a payload feeder for the journal record identified by serial_id.
	 * When the JNL is finished with the feeder, it will call #release_journal_feeder()
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The serial id of the record to get.
	 * @param[out] feeder The callbacks necessary to retrieve bytes of data
	 * for the payload.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue sending records, anything else will
	 * complete the ANS stream.
	 */
	int (*acquire_journal_feeder)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			struct jaln_payload_feeder *feeder,
			void *user_data);

	/**
	 * Release a payload feeder for journal record identified by \p serial_id.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The serial id of the record to get.
	 * @param[in] feeder The feeder object
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 */
	void (*release_journal_feeder)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			struct jaln_payload_feeder *feeder,
			void *user_data);

	/**
	 * The JNL calls this once the record is fully sent, or the
	 * connection/channel is severed. It provides a chance for the
	 * application to clean up any resources (including those in
	 * record_info);
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of record (journal, audit, or log)
	 * @param[in] serial_id The serial_id of this record_info
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 */
	void (*on_record_complete)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			char *serial_id,
			void *user_data);

	/**
	 * The JNL executes this callback when it receives a 'sync' message
	 * from the peer.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of record (journal, audit, or log)
	 * @param[in] serial_id the serial_id sent by the remote peer.
	 * @param[in] headers Any additional headers sent with this message.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 */
	void (*sync)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			const char *serial_id,
			struct jaln_mime_header *headers,
			void *user_data);

	/**
	 * Informs the application of the calculated checksum of the record
	 * identified by serial_id. This is the checksum calculated as the
	 * record is sent, not the digest received by the remote side. This is
	 * purely informational as the JNL maintains the sent of sent, but not
	 * yet confirmed digests.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of record (journal, audit, or log)
	 * @param[in] serial_id The serial_id of the record.
	 * @param[in] digest The digest value of the record.
	 * @param[in] lenght The length of the digest, in bytes.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @note should the JNL really track the digests? seems like a
	 * reasonable feature, but may need some extra tuning parameters or
	 * callbacks so the applications can start flushing memory, or should
	 * cache to disk unconfirmed digests...
	 */
	void (*notify_digest)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			const char *serial_id,
			const uint8_t *digest,
			const uint32_t size,
			void *user_data);

	/**
	 * Inform the application of the calculated checksum sent by the peer.
	 * The JNL tracks the serial_id and digests for all records sent on each
	 * channel. The JNL automatically checks the peer's calculated digest
	 * against the locally calculated digest and builds an appropriate
	 * 'digest-response' message for every 'digest' message. Once the JNL
	 * sends a 'digest-response' message to the peer, the JNL removes the
	 * entry from it's internal structures.
	 *
	 * This is called for each record in the 'digest' method.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of record (journal, audit, or log)
	 * @param[in] serial_id The serial_id of a particular record
	 * @param[in] local_digest The digest, as calculated by the JNL when the
	 * record was sent.
	 * @param[in] local_size The size, in bytes, of the local_digest
	 * @param[in] peer_digest The digest, as calculated by the remote peer.
	 * @param[in] peer_size The size, in bytes, of #peer_digest
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 */
	void (*peer_digest)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			const char *serial_id,
			const uint8_t *local_digest,
			const uint32_t local_size,
			const uint8_t *peer_digest,
			const uint32_t peer_size,
			void *user_data);
};


#ifdef __cplusplus
}
#endif

#endif // _JALN_PUBLISHER_CALLBACKS_H_
