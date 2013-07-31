/**
 * @file jaln_subscriber_callbacks.h This file defined jaln_subscriber_callbacks
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
#ifndef _JALN_SUBSCRIBER_CALLBACKS_H_
#define _JALN_SUBSCRIBER_CALLBACKS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/jaln_network_types.h>
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
	 * needed to send a 'subscribe' or 'journal-resume' message. For
	 * journal and audit records, the application only needs to set the
	 * nonce. The JNL interprets this as the last record the
	 * application downloaded and received a 'digest-conf' for. The JNL
	 * will send a 'subscribe' message indicating that this was the last
	 * record received.  Applications should use the special strings 
	 * JALN_SERIAL_ID_EPOCH and JALN_SERIAL_ID_NOW to specify transfer should 
	 * start with the oldest records, or only receive new records.
	 *
	 * For journal records, the Application must specify the offset. When
	 * the offset is 0, the JNL behaves in the same way as audit and
	 * log records. When the offset is non-zero, the JNL will send a
	 * 'journal-resume' message and indicate that \p offset bytes of the
	 * record identified by \p nonce were downloaded.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of JAL record the JNL is getting ready to
	 * subscribe to.
	 * @param[out] nonce The last record received, the JNL will release
	 * this memory by calling free().
	 * @param[out] offset The number of bytes already downloaded.
	 * @return JAL_OK to continue with the request, anything else to close
	 * the channel.
	 */
	int (*get_subscribe_request)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			char **nonce,
			uint64_t *offset);

	/**
	 * The JNL will execute this function after it receives and parses the
	 * MIME headers and has the system and application metadata sections of
	 * a specific record.
	 *
	 * @param[in] session The jaln_session.
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
	int (*on_record_info)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
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
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] nonce The previously provided nonce of this record
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
	int (*on_audit)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			const char *nonce,
			const uint8_t *buffer,
			const uint32_t cnt,
			void *user_data);

	/**
	 * The JNL calls this function to deliver the entire contents of a log
	 * entry.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] nonce The previously provided nonce of this record
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
	int (*on_log)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			const char *nonce,
			const uint8_t *buffer,
			const uint32_t cnt,
			void *user_data);

	/**
	 * The JNL calls this function to deliver bytes of a journal entry to the
	 * application. This function may be called multiple times for a single
	 * journal record. Each time the function is called, it delivers more
	 * data to the application.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] nonce The previously provided nonce of this record
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
	int (*on_journal)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			const char *nonce,
			const uint8_t *buffer,
			const uint32_t cnt,
			const uint64_t offset,
			const int more,
			void *user_data);

	/**
	 * The JNL calls this to inform the JAL Network store of the digest it
	 * calculated for a particular record.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of this record (journal, audit, or log).
	 * @param[in] nonce The previously provided nonce of this record

	 * @param[in] digest A buffer containing bytes of the digest
	 * @param[in] len The length of the digest, in bytes.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue receiving data, anything else will cause
	 * the JNL ignore any more messages for the specific record type and
	 * attempt to close the connection.
	 */
	int (*notify_digest)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			char *nonce,
			const uint8_t *digest,
			const uint32_t len,
			const void *user_data);

	/**
	 * The JNL will execute this callback for every record in a
	 * 'digest-response' message.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of this record (journal, audit, or log).
	 * @param[in] nonce The previously provided nonce of this record
	 * @param[in] status Indicates whether or not the digest calculated locally
	 * matches the digest calculated by the remote side.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue receiving data, anything else will cause
	 * the JNL ignore any more messages for the specific record type and
	 * attempt to close the connection.
	 */
	int (*on_digest_response)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			enum jaln_record_type type,
			const char *nonce,
			const enum jaln_digest_status status,
			const void *user_data);

	/**
	 * Called when the remote peer completes a subscribe message.
	 * @param[in] ch_info Information about the connection
	 * @param[in] type The type of this record (journal, audit, or log).
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 */
	void (*message_complete)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
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
	 * @param[in] session The jaln_session.
	 * @param[in] nonce The nonce of the record to get.
	 * @param[out] feeder The callbacks necessary to retrieve the already
	 * downloaded portions of the record.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 * @return JAL_OK to continue receiving data, anything else will cause
	 * the JNL ignore any more messages for journal records.
	 */
	int (*acquire_journal_feeder)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			const char *nonce,
			struct jaln_payload_feeder *feeder,
			void *user_data);

	/**
	 * Release a payload feeder for the identified nonce.
	 *
	 * @param[in] session The jaln_session.
	 * @param[in] nonce The nonce of the record to get.
	 * @param[in] feeder The callbacks necessary to retrieve bytes of data
	 * for the payload.
	 * @param[in] user_data A pointer to user data that was passed into
	 * \p jaln_listen, \p jaln_publish, or \p jaln_subscribe.
	 *
	 */
	void (*release_journal_feeder)(
			jaln_session *session,
			const struct jaln_channel_info *ch_info,
			const char *nonce,
			struct jaln_payload_feeder *feeder,
			void *user_data);
};

/**
 * Create a jaln_subscriber_callbacks structure
 *
 * @return a newly created and initialized jaln_subscriber_callbacks structure.
 */
struct jaln_subscriber_callbacks *jaln_subscriber_callbacks_create();

/**
 * Destroy a jaln_subscriber_callbacks structure
 *
 * @param[in,out] callbacks The structure to destroy. This will be set to NULL.
 */
void jaln_subscriber_callbacks_destroy(struct jaln_subscriber_callbacks **callbacks);


#ifdef __cplusplus
}
#endif

#endif // _JALN_SUBSCRIBER_CALLBACKS_H_
