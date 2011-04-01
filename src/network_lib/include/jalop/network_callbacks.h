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
#include <jalop/network_types.h>
/**
 * @struct jaln_subscriber_callbacks
 * The JAL network store fills this in for each accepted connection.
 * All of the callback functions take a user_data parameter which is the same
 * pointer that is passed into a call to
 * jaln_create_subscriber_channel(struct VortexConnection *, int, VortexOnCloseHandler,
 * axlPointer, VortexOnChannelCreated, axlPointer, struct jaln_connection_response_handlers *,
 * void *, struct jaln_connect_request *) or a call to 
 * jaln_journal_recover(struct jaln_channel *channel, const char *serial_id,
 * struct jaln_subscriber_callbacks subscribe_callbacks, void *subscriber_data,
 * or a call to jaln_subscribe(struct jaln_channel *channel,
 * const char *serial_id, struct jaln_subscriber_callbacks, void *subscriber_data,
 * jaln_on_message_complete subscribe_complete, void *recover_complete_data);
 */
struct jaln_subscriber_callbacks {
	/**
	 * The JNL will execute this function after it receives and parses the
	 * MIME headers of a '*-record' message.
	 *
	 * @param[in] serial_id The Publisher assigned sequence ID of this record
	 * @param[in] record_info The details of this record.
	 * @param[in] headers Any additional headers.
	 * @param[in] user_data A pointer to user data supplied in 
	*/
	void (*on_record_headers)(const char *serial_id,
				  const struct jaln_record_info *record_info,
				  const struct jaln_mime_header *headers,
				  void *user_data);
	/**
	 * The JNL calls this function to delivery the payload of the
	 * application metadata. This will be called once for each
	 * subscriber_id and delivers the entire contents of the application
	 * metadata in the buffer.
	 *
	 * @param[in] serial_id The Publisher assigned sequence ID of this record
	 * @param[in] buffer A buffer containing the application metadata. The
	 *            application is responsible for freeing this pointer with
	 *            #jal_free().
	 * @param[in] cnt The size, in bytes, of the buffer.
	 * @param[in] user_data A pointer to the user_data.
	 */
	void (*on_app_metadata)(const char *serial_id,
				const uint8_t *buffer,
				const uint32_t cnt,
				void *user_data);
	/**
	 * The JNL calls this function to delivery the entire contents of the
	 * system metadata block.
	 *
	 * @param[in] serial_id The Publisher assigned sequence ID of this record
	 * @param[in] buffer A buffer containing system metadata. The
	 * application is responsible for freeing this memory with a call to
	 * #jal_free()
	 * @param[in] cnt The number of bytes in the buffer.
	 * @param[in] user_data A pointer to the user_data
	 */
	void (*on_sys_metadata)(const char *serial_id,
				const uint8_t *buffer,
				const uint32_t cnt,
				void *user_data);
	/**
	 * The JNL calls this function to delivery the entire contents of the
	 * audit entry.
	 *
	 * @param[in] serial_id The Publisher assigned sequence ID of this record
	 * @param[in] buffer A buffer containing audit entry. The
	 * application is responsible for freeing this memory with a call to
	 * #jal_free()
	 * @param[in] cnt The number of bytes in the buffer.
	 * @param[in] user_data A pointer to the user_data
	 */
	void (*on_audit)(const char *serial_id,
			 const uint8_t *buffer,
			 const uint32_t avail,
			 void *user_data);
	/**
	 * The JNL calls this function to delivery the entire contents of a log
	 * entry.
	 *
	 * @param[in] serial_id The Publisher assigned sequence ID of this record
	 * @param[in] buffer A buffer containing the entire log entry. The
	 * application is responsible for freeing this memory with a call to
	 * #jal_free()
	 * @param[in] cnt The number of bytes in the buffer.
	 * @param[in] user_data A pointer to the user_data
	 */
	void (*on_log)(const char *serial_id,
			 const uint8_t *buffer,
			 const uint32_t avail,
			 void *user_data);
	/**
	 * The JNL calls this function to feed bytes of a journal entry to the
	 * application.
	 *
	 * @param[in] serial_id The Publisher assigned sequence ID of this record
	 * @param[in] buffer A buffer containing bytes of the payload, after
	 * this application returns from this call they must not access buffer.
	 * @param[in] avail The number of bytes contained in buffer
	 * @param[in] more Boolean flag to indicate if there is more data availble. This is
	 * set to 1 if there are more bytes expected, and 0 otherwise
	 * @param[in] user_data A pointer to the user_data.
	 */
	void (*on_journal)(const char *serial_id,
			   const uint8_t *buffer,
			   const uint32_t avail,
			   const int more,
			   void *user_data);
	/**
	 * The JNL calls this to inform the JAL Network store of the digest it
	 * calculated for a particular record. Note that the JNL will not send
	 * the 'digest' method automatically. The application must explicitly
	 * send the message with a call to #XXX
	 *
	 * @param[in] serial_id The Publisher assigned sequence ID of the record
	 * @param[in] digest A buffer containing bytes of the digest
	 * @param[in] len The length of the digest, in bytes.
	 * @param[in] user_data A pointer to the user data.
	 */
	void (*notify_digest)(const char *serial_id,
			      const uint8_t *digest,
			      const uint32_t len,
			      const void *user_data);
	/**
	 * The JNL will execute this callback for every record in a
	 * 'digest-response' message.
	 *
	 * @param[in] serial_id The Publisher assigned sequence ID of the record
	 * @param[in] status Indicates whether or not the digest calculated locally
	 * matches the digest calculated by the remote sidel.
	 * @param[in] user_data A pointer to the user_data.
	 */
	void (*on_digest_response)(const char *serial_id,
				   const enum jaln_digest_status status,
				   const void *user_data);
};
/**
 * Called when the sending ends completes a message message.
 */
typedef void (*jaln_on_message_complete)(const void *user_data);

/**
 * @struct jaln_publisher_callbacks
 * The application must fill one of these in for each accepted connection.
 *
 */
struct jaln_publisher_callbacks {
	/**
	 * The JNL will execute this callback when it receives a
	 * 'journal-resume' message. This call is to inform the application of 
	 * provided #jaln_record_feeder structure with appropriate function
	 * pointers and context data. When the application returns control back
	 * to the JNL, it will begin sending a response to this
	 * 'journal-recover' message using the data in the jaln_record_feeder.
	 *
	 * @param[in] headers additional mime headers sent as part of this message
	 * @param[in,out] record_info Information about this record. The JNL
	 * fills in the serial_id field and the application must fill in the
	 * rest. The JNL assumes ownership of the serial_id and headers fields
	 * of the this structure and will call jal_free() and
	 * jaln_mime_headers_free() respectively when the record_info is no
	 * longer needed.
	 * @param[out] payload_delivery Determines which set of functions the
	 * JNL will call to acquire the bytes of the journal payload.
	 * @param[in] user_data A pointer to the user_data of this
	 * #jaln_publisher_callbacks
	 */
	int (*on_journal_resume)(struct jaln_record_info *record_info,
				 int offset,
				 struct jaln_mime_header *headers,
				 enum payload_delivery_type *payload_delivery
				 void *user_data);
	/**
	 * The JNL executes this callback to inform the application of a
	 * 'subscribe' message. This callback is purely informational.
	 *
	 * @param[in] serial_id The serial_id in the subscribe message
	 * @param[in] headers additional mime headers sent as part of this message
	 * @param[in] user_data the user pointer.
	 */
	void (*on_subscribe)(const char *serial_id,
			     struct jaln_mime_header *headers,
			     void *user_data);
	/**
	 * The JNL will execute this callback to obtain the record info for the
	 * next record that should be sent on this channel.
	 *
	 * @param[in] serial_id The serial_id sent by the peer as part of this
	 * 'subscribe' message.
	 * @param[out] feeder The application should fill out this structure
	 * with appropriate data to send a record to a peer. The JNL assumes
	 * ownership of the serial_id and headers fields and will call
	 * jal_free() and jaln_mime_header_free() respectively when it is
	 * finished with the structure.
	 * @param[out] payload_delivery The aplication must set this to
	 * indicate which set of callbacks JNL should call to get the payload.
	 * @param[in] user_data A pointer to the user supplied data
	 *
	 * @return JAL_OK to continue sending records, anything else will
	 * complete end ANS stream
	 */
	int (*get_next_record_info)(const char *last_serial_id,
				    struct jaln_record_info *record_info,
				    enum payload_delivery_type *payload_delivery
				    void *user_data);
	/**
	 * Aquire a pointer to the system metadata. The buffer must contain the
	 * same number of bytes as were designated in the
	 * #jaln_record_info obtained in #get_next_record_info(). When
	 * the JNL is finished with this buffer, it will call
	 * #release_record_sys_metadata();
	 *
	 * @param[in] serial_id The serial_id of the record to get.
	 * @param[out] buffer a user allocated buffer that contains the bytes
	 * of the system metadata.
	 * @param[in] user_data A pointer to the user provided data.
	 */
	int (*acquire_sys_metadata(const char *serial_id,
				uint8_t **buffer,
				void *user_data);
	/**
	 * Release the system metadata buffer.
	 *
	 * @param[in] serial_id The serial id relating to this buffer
	 * @param[in] a pointer that was obtained by the call to
	 * #acquire_record_sys_metadata()
	 * @param[in] user_data A pointer to the user provided data.
	 */
	int (*release_sys_metadata(const char *serial_id,
				uint8_t **buffer,
				void *user_data);
	/**
	 * Aquire a pointer to the application metadata. The buffer must contain the
	 * same number of bytes as were designated in the
	 * #jaln_record_info obtained in #get_record_info(). When
	 * the JNL is finished with this buffer, it will call
	 * #release_record_app_metadata();
	 *
	 * @param[in] serial_id The serial_id of the record to get.
	 * @param[out] buffer a user allocated buffer that contains the bytes
	 * of the application metadata.
	 * @param[in] user_data A pointer to the user provided data.
	 */
	int (*acquire_app_metadata(const char *serial_id,
				uint8_t **buffer,
				void *user_data);
	/**
	 * Release the application metadata buffer.
	 *
	 * @param[in] serial_id The serial id relating to this buffer
	 * @param[in] a pointer that was obtained by the call to
	 * #acquire_record_app_metadata()
	 * @param[in] user_data A pointer to the user provided data.
	 */
	int (*release_app_metadata(const char *serial_id,
				uint8_t *buffer,
				void *user_data);
	/**
	 * Aquire a pointer to the payload. The buffer must contain the
	 * same number of bytes as were designated in the
	 * #jaln_record_info obtained in #get_record_info() (minus \b offset
	 * bytes). When the JNL is finished with this buffer, it will call
	 * #release_payload_buffer();
	 *
	 * @param[in] serial_id The serial_id of the record to get.
	 * @param[in] offset The offset into the data the JNL would like to
	 * start reading from. In most cases this will be 0, but this function
	 * may be called in response to a 'journal resume' message, in which
	 * case, the offset would indicate the number of bytes the remote side
	 * is claiming it received. Regardless, then JNL will start reading
	 * from this address (not buffer + offset).
	 * @param[out] buffer a user allocated buffer that contains the bytes
	 * of the payload.
	 * @param[in] user_data A pointer to the user provided data.
	 */
	int (*acquire_payload_buffer(const char *serial_id,
				size_t offset,
				uint8_t **buffer,
				void *user_data);
	/**
	 * Release the payload buffer.
	 *
	 * @param[in] serial_id The serial id relating to this buffer
	 * @param offset The offset that was passed into
	 * #acquire_payload_buffer. This may be usefull if, for example, the
	 * payload was mmapped and the application needs to retrieve the
	 * original pointer.
	 * @param[in] a pointer that was obtained by the call to
	 * #acquire_payload_buffer()
	 * @param[in] user_data A pointer to the user provided data.
	 */
	int (*release_payload_buffer(const char *serial_id,
				size_t offset,
				uint8_t *buffer,
				void *user_data);
	/**
	 * Acquire a payload feeder for the identified serial_id. When the
	 * application is finished with the feeder, it will call
	 * #release_payload_feeder()
	 *
	 * @param[in] serial_id The serial id of the record to get.
	 * @param[out] feeder The callbacks necessary to retrieve bytes of data
	 * for the payload.
	 * @param user_data A pointer to the user provided data.
	 */
	int (*acquire_payload_feeder(const char *serial_id,
				     struct *payload_feeder,
				     void *user_data);
	/**
	 * Release a payload feeder for the identified serial_id.
	 *
	 * @param[in] serial_id The serial id of the record to get.
	 * @param[in] feeder The callbacks necessary to retrieve bytes of data
	 * for the payload.
	 * @param user_data A pointer to the user provided data.
	 */
	int (*release_payload_feeder(const char *serial_id,
				     struct *payload_feeder,
				     void *user_data);
	/**
	 * The JNL calls this once the record is fully sent, or the
	 * connection/channel is severed. It provides a chance for the
	 * application to clean up any resources (including those in
	 * record_info);
	 *
	 * @param serial_id The serial_id of this record_info
	 * @param record_info The record_info struct
	 */
	void (*on_record_complete)(char *serial_id);
	/**
	 * The JNL executes this callback when it receives a 'sync' message
	 * from the peer.
	 *@param[in] serial_id the serial_id sent by the remote peer.
	 * @param headers Any additional headers sent with this message.
	 * @param[in] user_data A pointer to the user provided data.
	 */
	void (*sync)(const char *serial_id,
		     struct jaln_mime_header *headers,
		     void *user_data);
	/**
	 * Informs the application of the calculated checksum of the record
	 * identified by serial_id. This is the checksum calculated as the
	 * record is sent, not the digest received by the remote side. This is
	 * purely informational as the JNL maintains the sent of sent, but not
	 * yet confirmed digests.
	 *
	 * @param[in] serial_id The serial_id of the record.
	 * @param[in] digest The digest value of the record.
	 * @param[in] lenght The length of the digest, in bytes.
	 * @param[in] user_data A pointer to the user_data of this
	 * jaln_publisher_callbacks
	 *
	 * @note should the JNL really track the digests? seems like a
	 * reasonable feature, but may need some extra tuning parameters or
	 * callbacks so the applications can start flushing memory, or should
	 * cache to disk unconfirmeded digests...
	 */
	void (*notify_digest)(const char *serial_id,
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
	 * @param[in] serial_id The serial_id of a particular record
	 * @param[in] local_digest The digest, as calculated by the JNL when the
	 * record was sent.
	 * @param[in] local_size The size, in bytes, of the local_digest
	 * @param[in] peer_digest The digest, as calculated by the remote peer.
	 * @param[in] peer_size The size, in bytes, of #peer_digest
	 * @param[in] user_data A pointer to the user_data of this
	 * #jaln_publisher_callbacks
	 */
	void (*peer_digest)(const char *serial_id,
			   const uint8_t *local_digest,
			   const uint32_t local_size,
			   const uint8_t *peer_digest,
			   const uint32_t peer_size,
			   enum jaln_digest_status status,
			   struct jaln_mime_header *headers,
			   void *user_data);
};

/**
 * The JNL will execute this callback when it receies a 'connect'
 * message from the remote peer.
 * @param[in] req A structure containing the connection info requested by
 * the peer, including additional MIME headesr.
 *
 * @param[out] selected_encoding The application must indicate which
 * encoding it will send the JAL metadata and audit records in. The
 * application is responsible for sending the metadata and audit
 * records in the selected encoding. The application may signal that no
 * encoding is acceptable by setting selected_encoding to value out of
 * range. The index starts at zero, so if the remote peer indicates
 * @verbatim
 * aceept-encoding: exi, xml
 * @endverbatim
 * The application would signal 'EXI' by setting selected_encoded to 0, or
 * signal XML by setting selected_encoded to 1. The application may
 * refuse all encodings by setting selected_encoded to -1.
 * @param[in] user_data A pointer to the user_data of this
 * jaln_publisher_callbacks
 *
 * @returns JALN_CONNECT_ERR_NONE to accept the connection, or any of the
 * jaln_connect_errors to indicate the failure to return.
 *
 * @note: This imits applications to a single error code. In
 * practice this is probably fine, but not sure it should be so limited...
 *
 *
 */
typedef enum  jal_status (*jaln_connect_handler)(const struct jaln_connect_request *req,
						int *selected_encoding,
						void *user_data);

/**
 * This structure contains the handlers for 'connect-ack' and 'connect-nack'
 * messages.
 * @see jaln_connect()
 */
struct jaln_connection_response_handlers {
	/**
	 * The JNL will execute this callback when it receies a 'subscribe-ack'
	 * message from the remote peer.
	 * including the MIME headesr.
	 * @param[in] channel The JAL channel the 'connect-ack' was received
	 * @param[in] ack A structure containing information about the connection,
	 * @param[in] user_data The user data.
	 *
	 * @see jaln_connect_ack
	 */
	void (*connect_ack)(const jaln_channel *channal,
			    const struct jaln_connect_ack *ack,
			    void *user_data);
	/**
	 * The JNL will execute this callback when it receies a 'subscribe-nack'
	 * message from the remote peer.
	 * @param nack The failure reasons given by the remote peer.
	 * This includes any additional MIME headers.
	 * @param user_data The user data.
	 *
	 * @note maybe add the jalchannel.. not sure it's usefull in the
	 * connect_nack, since the channel will be closing at this point
	 */
	void (*connect_nack)(const struct jaln_connect_nack *nack,
			     void *user_data);
};

/**
 * This handler allows the application to accept or reject a request from the
 * peer to close a channel.
 *
 * @param channel_num The channel number in question
 * @param connection the connection the channel is on.
 * @param user_data A user provided pointer.
 *
 * @return JAL_OK to accept the close request
 */
typedef jal_status (*jaln_on_close_handler)(int channel_num, jaln_connection *connection, void *user_data)


/**
 * This handler allows the application to be notified when the jalop channel is
 * created. If there is an error channel_num will be -1, and channel will be NULL.
 * This is called after the channel is established, but before the 'connect'
 * message is sent.
 *
 * TODO: provide a mechanism to get underlyihng vortex errors?
 *
 * @param channel_num The channel number in question.
 * @param channel The new channel
 * @param user_data A user provided pointer.
 */
typedef void (*jaln_on_channel_created)(int channel_num, jaln_connection *connection, void *user_data)
#endif // JALN_NET_CALLBACKS_H
