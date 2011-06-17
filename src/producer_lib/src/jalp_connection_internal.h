/**
 * @file jalp_connection_internal.h 
 * This file contains defines and structures used when connecting to the local store.
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
#ifndef _JALP_CONNECTION_INTERNAL_H_
#define _JALP_CONNECTION_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "jalp_context_internal.h"

/**
 * This is the string used when using sendmsg/recvmsg to send data to the
 * local store.  It is after the application metadata and the other buffer.
 */
#define JALP_BREAK_STR "BREAK"

/**
 * Message types used for the message_type member of the
 * jalp_connection_headers structure.
 */
enum jalp_connection_msg_type {
	JALP_LOG_MSG = 1,
	JALP_AUDIT_MSG = 2,
	JALP_JOURNAL_MSG = 3,
	JALP_JOURNAL_FD_MSG = 4,
};

/**
 * These correspond to the headers in a message to the local store.
 */
struct jalp_connection_headers {
	/**
	 * The version of the JALoP local store protocol.  This will always be 1 for this
	 * version of JALoP.
	 */
	uint16_t protocol_version;
	/**
	 * Message type.  This will be one of the \p jalp_connection_msg_type enums.
	 * It is either a log record, an audit record, a journal record, or a journal
	 * record with a file descriptor.
	 */
	uint16_t message_type;
	/**
	 * This is the length of the data record. For example, in jalp_log(), it corresponds
	 * to the length of \p log_buffer.
	 */
	uint64_t data_len;
	/**
	 * The length of the application metadata document.
	 */
	uint64_t meta_len;
};

/**
 * Allocate and initialize a #jalp_connection_headers structure.
 *
 * @param[in] message_type The type of this message.  This should be 
 * one of the #jalp_connection_msg_type enums. It is either a log record,
 * an audit record, a journal record, or a journal record with a file descriptor.
 *
 * @param[in] data_len The length of the data record.
 *
 * @param[in] meta_len The length of the application metadata document.
 *
 * @return The newly allocated #jalp_connection_headers
 */
struct jalp_connection_headers *jalp_connection_headers_create(uint16_t message_type,
		uint64_t data_len, uint64_t meta_len);
/**
 * Destroy a #jalp_connection_headers structure and all it's members.
 * @param[in,out] connection_headers A #jalp_connection_headers object to destroy. This will
 * be set to NULL.
 */
void jalp_connection_headers_destroy(struct jalp_connection_headers **connection_headers);

/**
 * Allocate and initialize a #msghdr structure.
 *
 * This uses jalp_connection_headers() to generate a msghdr structure
 * that can be used with recvmsg() and sendmsg().  This sets the io vectors
 * to the format specified by the JALoP protocol.
 *
 * @param[in,out] msgh The msgh to fill out.
 *
 * @param[in,out] iov The io vector to fill out and attach to the msghdr struct. This should
 * be a 5 element iovec array.
 *
 * @param[in] connection_headers Connection headers to use to fill out the io vector.
 *
 * @param[in] data A buffer for the data record..
 *
 * @param[in] meta A buffer for the application metadata record.
 *
 * @return JAL_OK if everything was filled out correctly.  JAL_E_INVAL if
 * \p msgh or \p iov were passed in as NULL.
 */
enum jal_status jalp_connection_fill_out_msghdr(struct iovec *iov,
		struct jalp_connection_headers *connection_headers, void *data, void *meta);

/**
 * Send a msghdr using the socket in ctx.  Trys to reconnect and send if 
 * the first send fails.
 *
 * @param[in] ctx a #jalp_context that will be used to send the \p msgh over.
 * @param[in] msgh The #msghdr that will be passed to sendmsg().
 *
 * @return JAL_OK if the message was sent correctly.  JAL_E_INVAL if
 * \p msgh or \p ctx were passed in as NULL.
 */
enum jal_status jalp_sendmsg(jalp_context *ctx, struct msghdr *msgh);

/**
 * Send a buffer using jalp_sendmsg(). 
 *
 * @param[in] ctx a #jalp_context that will be used to send the buffer.
 *
 * @param[in] message_type The type of this message.  This should be 
 * one of the #jalp_connection_msg_type enums. It is either a log record,
 * an audit record, a journal record, or a journal record with a file descriptor.
 *
 * @param[in] data A buffer for the data record..
 *
 * @param[in] data_len The length of the data record.
 *
 * @param[in] meta A buffer for the application metadata record.
 *
 * @param[in] meta_len The length of the application metadata document.
 *
 * @param[in] fd The file descriptor to use if this is a JALP_JOURNAL_FD_MSG.
 * Otherwise, just -1.
 *
 * @return JAL_OK if the message was sent correctly.  JAL_E_INVAL if
 * \p msgh or \p ctx were passed in as NULL.
 */
enum jal_status jalp_send_buffer(jalp_context *ctx, uint16_t message_type,
		void *data, uint64_t data_len, void *meta, uint64_t meta_len, int fd);

#ifdef __cplusplus
}
#endif
#endif // _JALP_CONNECTION_INTERNAL_H_


