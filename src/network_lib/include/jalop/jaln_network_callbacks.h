/**
 * @file network_callbacks.h
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
#ifndef JALN_NET_CALLBACKS_H
#define JALN_NET_CALLBACKS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/network_types.h>
#include <stdlib.h>
/**
 * @struct jaln_subscriber_callbacks
 * The JAL network store fills this in for each accepted connection.
 * All of the callback functions take a user_data parameter which is the same
 * pointer that is passed into a call to
 * jaln_create_subscriber_channel() or a call to jaln_journal_recover(), or a
 * call to jaln_subscribe()
 */
struct jaln_subscriber_callbacks {
	/**
	 * After a connection is accepted where the local peer is slated as the
	 * 'subscriber' the JNL calls this function to get the parameters
	 * needed to send a 'subscribe' of 'journal-resume' message. For
	 * journal and audit records, the application only needs to set the
	 * serial_id. The JNL interprets this as the last serial_id the
	 * application downloaded and received a 'digest-conf' for. The JNL
	 * will send a 'subscribe' message with this serial_id.  Applications
	 * should use the special strings JALN_SERIAL_ID_EPOCH and
	 * JALN_SERIAL_ID_NOW to specify transfer should start with the oldest
	 * records, or only receive new records.
	 *
	 * For journal records, the Application must specify the offset. When
	 * the offset is 0, the JNL behaves in the same way as audit and
	 * log records. When the offset is non-zero, the JNL will send a
	 * 'journal-resume' message and indicate that \p offset bytes of the
	 * record identified by \p serial_id were downloaded.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of JAL record the JNL is getting ready to
	 * subscribe to.
	 * @param[out] serial_id The serial_id to send, the JNL will release
	 * this memory by calling free().
	 * @param[out] offset The number of bytes already downloaded.
	 * @return JAL_OK to continue with the request, anything else to close
	 * the channel.
	 */
	int (*get_subscribe_request)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			char **serial_id,
			uint64_t *offset);
	/**
	 * The JNL will execute this function after it receives and parses the
	 * MIME headers and has the system and application metadata sections of
	 * a specific record.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of JAL record to retrieve.
	 * @param[in] record_info The details of this record.
	 * @param[in] headers Any additional headers.
	 * @param[in] system_metadata_buffer A buffer containing the system metadata. The
	 *            application is responsible for freeing this pointer with
	 *            free().
	 * @param[in] system_metadata_size The size, in bytes, of the \p
	 *            system_metadata_buffer.
	 * @param[in] application_metadata_buffer A buffer containing the application metadata. The
	 *            application is responsible for freeing this pointer with
	 *            free().
	 * @param[in] appliction_metadata_size The size, in bytes, of the \p
	 *            application_metadata_buffer.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue receiving data.
	 *
	 */
	int (*on_record_info)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			const struct jaln_record_info *record_info,
			const struct jaln_mime_header *headers,
			const uint8_t *system_metadata_buffer,
			const uint32_t system_metadata_size,
			const uint8_t *application_metadata_buffer,
			const uint32_t application_metadata_size,
			void *user_data);
	/**
	 * The JNL calls this function to deliver the entire contents of the
	 * audit entry.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The Publisher assigned sequence ID of this record
	 * @param[in] buffer A buffer containing audit entry. The
	 * application is responsible for freeing this memory with a call to
	 * free()
	 * @param[in] cnt The number of bytes in the buffer.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue receiving data, anything else will cause
	 * the JNL ignore any more messages for audit records.
	 */
	int (*on_audit)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			const uint8_t *buffer,
			const uint32_t cnt,
			void *user_data);
	/**
	 * The JNL calls this function to deliver the entire contents of a log
	 * entry.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The Publisher assigned sequence ID of this record
	 * @param[in] buffer A buffer containing the entire log entry. The
	 * application is responsible for freeing this memory with a call to
	 * free()
	 * @param[in] cnt The number of bytes in the buffer.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue receiving data, anything else will cause
	 * the JNL ignore any more messages related to log records.
	 */
	int (*on_log)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			const uint8_t *buffer,
			const uint32_t cnt,
			void *user_data);
	/**
	 * The JNL calls this function to deliver bytes of a journal entry to the
	 * application. This function may be called multiple times for a single
	 * journal record. Each time the function is called, it delivers more
	 * data 
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The Publisher assigned sequence ID of this record
	 * @param[in] buffer A buffer containing bytes of the journal, after
	 * this application returns from this call they must not access buffer.
	 * @param[in] cnt The number of bytes contained in buffer
	 * @param[in] offset The offset into the journal data.
	 * @param[in] more Boolean flag to indicate if there is more data
	 * expected, this is set to 1 if there are more bytes expected, and 0 otherwise
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue receiving data, anything else will cause
	 * the JNL ignore any more messages for journal records.
	 */
	int (*on_journal)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			const uint8_t *buffer,
			const uint32_t cnt,
			const uint64_t offset,
			const int more,
			void *user_data);
	/**
	 * The JNL calls this to inform the JAL Network store of the digest it
	 * calculated for a particular record.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of this record (journal, audit, or log).
	 * @param[in] serial_id The Publisher assigned sequence ID of the record
	 * @param[in] digest A buffer containing bytes of the digest
	 * @param[in] len The length of the digest, in bytes.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue receiving data, anything else will cause
	 * the JNL ignore any more messages for the specific record type and
	 * attempt to close the connection.
	 */
	int (*notify_digest)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			char *serial_id,
			const uint8_t *digest,
			const uint32_t len,
			const void *user_data);
	/**
	 * The JNL will execute this callback for every record in a
	 * 'digest-response' message.
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of this record (journal, audit, or log).
	 * @param[in] serial_id The Publisher assigned sequence ID of the record
	 * @param[in] status Indicates whether or not the digest calculated locally
	 * matches the digest calculated by the remote side.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue receiving data, anything else will cause
	 * the JNL ignore any more messages for the specific record type and
	 * attempt to close the connection.
	 */
	int (*on_digest_response)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			const char *serial_id,
			const enum jaln_digest_status status,
			const void *user_data);
	/**
	 * Called when the remote peer completes a subscribe message.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of this record (journal, audit, or log).
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 */
	void (*message_complete)(const struct jaln_channel_info *ch_info,
			enum jaln_record_type,
			void *user_data);
	/**
	 * Get a payload feeder to process the already downloaded portion of a
	 * journal record.
	 *
	 * To handle a 'journal-resume' message, applications must provide the
	 * JNL with the portion of a journal record that was already
	 * transferred. The JNL calls this function to acquire a payload
	 * feeder that it uses to calculate the digest of the JAL record. The
	 * application informs the JNL of how many bytes were previously
	 * downloaded when it calls jaln_context_subscribe.
	 *
	 * @param[in] serial_id The serial id of the record to get.
	 * @param[out] feeder The callbacks necessary to retrieve the already
	 * downloaded portions of the record.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue receiving data, anything else will cause
	 * the JNL ignore any more messages for journal records.
	 */
	int (*acquire_journal_feeder)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			struct jaln_payload_feeder *feeder,
			void *user_data);
	/**
	 * Release a payload feeder for the identified serial_id.
	 *
	 * @param[in] serial_id The serial id of the record to get.
	 * @param[in] feeder The callbacks necessary to retrieve bytes of data
	 * for the payload.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 */
	void (*release_journal_feeder)(const struct jaln_channel_info *ch_info,
			const char *serial_id,
			struct jaln_payload_feeder *feeder,
			void *user_data);
};
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
			struct jaln_mime_header *headers);
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
	int (*get_next_record_info)(const struct jaln_channel_info *ch_info,
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
	 * \p get_next_record_info
	 *
	 * @param[in] ch_info Information about the connection
	 * @param[in] serial_id The serial_id of the record.
	 * @param[in] system_metadata_buffer The buffer obtained by the call
	 * to \p get_next_record_info.
	 * @param[in] application_metadata_buffer The buffer obtained by the call
	 * to \p get_next_record_info.
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
	 * #jaln_record_info obtained in #get_next_record_info(). When the JNL
	 * is finished with this buffer, it will call release_payload_buffer()
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
	 * obtained by calling get_next_record_info(). When the JNL is finished
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
	 * When the JNL is finished with the feeder, it will call #release_payload_feeder()
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

/**
 * Structure that contains all the callback methods an application should
 * implement to allow/deny connections and be notified when channels close.
 */
struct jaln_connection_handlers {
	/**
	 * The JNL will execute this callback when it receives a 'connect'
	 * message from the remote peer.
	 * @param[in] req A structure containing the connection info requested by
	 * the peer, including additional MIME headers.
	 *
	 * @param[in,out] selected_encoding Indicates which encoding the JNL is going
	 * to select. Applications may change this value and override the selection
	 * made by JNL.
	 * The index starts at zero, so if the remote peer indicates
	 * @verbatim
	 * accept-encoding: exi, xml
	 * @endverbatim
	 * The application would signal 'EXI' by setting selected_encoded to 0, or
	 * signal XML by setting selected_encoded to 1. The application may
	 * refuse all encodings by setting selected_encoded to -1.
	 * @param[in,out] selected_digest Indicates which digest method the JNL is
	 * going to select. Applications may change this value and override the selection
	 * made by JNL.
	 * The index starts at zero, so if the remote peer indicates
	 * @verbatim
	 * accept-digest: sha512, sha256
	 * @endverbatim
	 * The application would signal 'sha512' by setting selected_digest to 0, or
	 * signal sha256 to 1. The application may refuse all digest methods by setting
	 * selected_encoded to -1.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @returns JALN_CONNECT_ERR_NONE to accept the connection, or any of the
	 * jaln_connect_errors to indicate the failure to return.
	 *
	 * @note: This limits applications to a single error code. In
	 * practice this is probably fine, but not sure it should be so limited...
	 *
	 *
	 */
	enum jaln_connect_error (*connect_request_handler)(const struct jaln_connect_request *req,
			int *selected_encoding,
			int *selected_digest,
			void *user_data);
	/**
	 * Notify the application that a channel was closed.
	 * @param[in] channel_info Information about the channel that is closing.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 */
	void (*on_channel_close)(const struct jaln_channel_info *channel_info,
		void *user_data);

	/**
	 * Notify the application when all channels for a connection have
	 * closed.
	 * @param[in] jaln_conn The connection object. The JNL releases this
	 * object when the function returns.
	 */
	void (*on_connection_close)(const struct jaln_connection *jal_conn, void *user_data);

	/**
	 * The JNL will execute this callback when it receives a 'connect-ack'
	 * message from the remote peer.
	 * @param[in] ack A structure containing information about the connection,
	 * including the MIME headers.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @see jaln_connect_ack
	 */
	void (*connect_ack)(const struct jaln_connect_ack *ack,
			    void *user_data);
	/**
	 * The JNL will execute this callback when it receives a 'connect-nack'
	 * message from the remote peer.
	 * @param nack The failure reasons given by the remote peer.
	 * This includes any additional MIME headers.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 */
	void (*connect_nack)(const struct jaln_connect_nack *nack,
			     void *user_data);
};

#ifdef __cplusplus
}
#endif

#endif // JALN_NET_CALLBACKS_H
