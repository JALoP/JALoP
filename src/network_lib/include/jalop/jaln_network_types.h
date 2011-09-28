/**
 * @file jaln_network_types.h
 *
 * Public types of the JALoP Network Library.
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
#ifndef _JALN_NETWORK_TYPES_H_
#define _JALN_NETWORK_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * Enum used to distinguish between record types
 */
enum jaln_record_type {
	/** Indicates a Journal Record */
	JALN_RTYPE_JOURNAL = 1 << 0,
	/** Indicates an Audit Record */
	JALN_RTYPE_AUDIT = 1 << 1,
	/** Indicates a Log Record */
	JALN_RTYPE_LOG = 1 << 2,
};

/**
 * Structure to encompass MIME headers
 */
struct jaln_mime_header {
	/** The name of this header */
	char *name;
	/** The value of this header */
	char *value;
	/** The next header in the list */
	struct jaln_mime_header *next;
};

/**
 * Create a jaln_mime_header list.
 * @return a newly created jaln_mime_header_list
 */
struct jaln_mime_header *jaln_mime_header_create(struct jaln_mime_header **headers);

/**
 * Destroy a list of MIME headers
 *
 * @param[in,out] headers The headers to free. This will be set to NULL.
 */
void jaln_mime_header_destroy(struct jaln_mime_header **headers);

/**
 * Information about a connected JALoP Channel
 */
struct jaln_channel_info {
	/** The hostname of the remote peer (if available) */
	char *hostname;
	/** The IP address in dotted decimal notation (i.e. "192.168.1.6") */
	char *addr;
	/** The selected XML encoding, "XML", "EXI", "deflate" etc */
	char *encoding;
	/** The selected digest method, "sha256", "sha512", etc */
	char *digest_method;
	/** The type of JAL records exchanged on this channel */
	enum jaln_record_type type;
};

/**
 * Provides some metadata about a specific JAL record.
 */
struct jaln_record_info {
	/** The type of this record (journal, audit, or log) */
	enum jaln_record_type type;
	/** The serial ID of this record */
	char *serial_id;
	/** The length of the system metadata */
	uint64_t sys_meta_len;
	/** The length of the application metadata */
	uint64_t app_meta_len;
	/** The length of the payload (raw journal, audit, or log data) */
	uint64_t payload_len;
	/** Any additional headers the application would like to send.  */
	struct jaln_mime_header *headers;
};

/**
 * Enum used to indicate the 'status' of a digest
 */
enum jaln_digest_status {
	/** Indicates the digest calculated by both peers is the same */
	JALN_DIGEST_STATUS_CONFIRMED,
	/** Indicates the digest calculated by both peers is not the same */
	JALN_DIGEST_STATUS_INVALID,
	/** Indicates the serial_id was not recognized */
	JALN_DIGEST_STATUS_UNKNOWN,
};

/**
 * Enum used to indicate the role a particular peer is supposed to fill.
 * @see #jaln_connect_ack
 */
enum jaln_role {
	/**
	 * The peer should act as a subscriber. They are expected to send only
	 * 'subscribe', 'journal-resume', 'digest', and 'sync' messages.
	 *
	 * The must be prepared to handle '*-record', and 'digest-response'
	 * messages.
	 */
	JALN_ROLE_SUBSCRIBER,
	/**
	 * The peer should act as a publisher. They are expected to send only
	 * '*-record', and 'digest-response'
	 *
	 * They must be prepared to handle 'subscribe', 'journal-recover',
	 * 'digest', and 'sync' messages.
	 */
	JALN_ROLE_PUBLISHER
};

/**
 * This represents the data that is sent as part of a 'connect-ack' message.
 */
struct jaln_connect_ack {
	/** The hostname (if available) of the remote peer. */
	char *hostname;
	/** The IP address in dotted decimal notation (i.e. "192.168.1.1"). */
	char *addr;
	/**
	 * The version of JALoP that the peers are using to communicate.
	 */
	int jaln_version;
	/**
	 * The JALoP user agent string (if any). This is the user agent of the
	 * receiver of the 'connect' (sender of 'connect-ack') message.
	 */
	char *jaln_agent;
	/**
	 * Indicates which role this side of the connection is expected to
	 * play.
	 */
	enum jaln_role mode;
	/**
	 * This list contains any extra headers, not processed by the JNL. It
	 * only contains additional headers not included the JALoP spec.
	 */
	struct jaln_mime_header *headers;
};

/**
 * This represents the data that is sent as part of a 'connect' message.
 */
struct jaln_connect_request {
	/** The hostname of the remote peer */
	char *hostname;
	/** The address of the remote peer */
	char *addr;
	/** Information about the connection request; */
	struct jaln_channel_info ch_info;
	/** The requested type of data to transfer using this channel. */
	enum jaln_record_type type;
	/** The version of JALoP that the peers are using to communicate. */
	int jaln_version;
	/**
	 * The proposed encodings the sender of this 'connect' message is will
	 * to use.
	 */
	char **encodings;
	/** The number of encodings in the array. */
	int enc_cnt;
	/** The proposed digest methods. */
	char **digest;
	/** The number of digests in the array. */
	int dgst_cnt;
	/**
	 * The mode as sent by the remote peer. Note that when the peer sends a
	 * 'connect' message with the mode set to JALN_ROLE_SUBSCRIBE, it is
	 * indicating that it plans on acting as a subscriber. Conversely, when
	 * the mode is JALN_ROLE_PUBLISH, it indicates the peer plans on acting
	 * as a publisher.
	 */
	enum jaln_role role;
	/**
	 * The jal user agent string (if any). This is the user agent of the
	 * sender of the 'connect' message.
	 */
	char *jaln_agent;
	/**
	 * This list contains any extra headers not processed by the JNL. It
	 * only contains additional headers not included the JALoP spec.
	 */
	struct jaln_mime_header *headers;
};

/**
 * The JNL fills out the #jaln_connect_nack and passes it to the application
 * when the peer sends a 'connect-nack' message.
 */
struct jaln_connect_nack {
	/** Information about the channel. */
	struct jaln_channel_info *ch_info;
	/** Array of failure reasons given by the remote peer. */
	struct jaln_string_list **error_list;
	/** Number of elements in the \p error_list */
	int error_cnt;
	/**
	 * Any additional headers. This list will not contain the headers for
	 * the errors in #error_list.
	 */
	struct jaln_mime_header *headers;
};

/**
 * @struct jaln_payload_feeder
 * The jaln_payload_feeder is used to send bytes of the payload (journal,
 * audit, or log data) to the remote peer.
 */
struct jaln_payload_feeder {
	/**
	 * An application may set this to anything they like. It will be passed
	 * as the \p feeder_data parameter of #get_bytes.
	 *
	 * the JNL will call release_payload_feeder when it is done with a
	 * particular instance to give the application a chance to release any
	 * data associated with the feeder.
	 */
	void *feeder_data;
	/**
	 * The JNL calls this when it needs to read more bytes of the payload
	 * (raw journal, audit, or log data).
	 *
	 * @param[in] offset The offset, in bytes, to start reading from.
	 * @param[in] buffer The buffer to fill with data.
	 * @param[in,out] size The number of bytes available in the buffer.
	 * Applications must set this to the actual number of bytes read.
	 * @param[in] feeder_data the application defined feeder_data pointer of this struct.
	 *
	 * @return JAL_OK to continue, some other value to stop sending data.
	 */
	enum jal_status (*get_bytes)(const uint64_t offset,
			   uint8_t * const buffer,
			   uint32_t *size,
			   void *feeder_data);
};

/**
 * Used to indicate whether a connection should be accepted or rejected
 */
enum jaln_connect_error {
	JALN_CE_ACCEPT = 0,
	JALN_CE_REJECT,
};

struct jaln_connection;

/**
 * This holds global data such as base publisher
 * callbacks, and channel creation handlers.
 */
typedef struct jaln_context_t jaln_context;

#ifdef __cplusplus
}
#endif

#endif // _JALN_NETWORK_TYPES_H_
