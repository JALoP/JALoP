/**
 * @file jalp_connection.c 
 * This file defines helper functions for making a connection to a local store.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <jalop/jal_status.h>
#include "jal_alloc.h"
#include "jalp_connection_internal.h"
#include "jalp_context_internal.h"

struct jalp_connection_headers *jalp_connection_headers_create(uint16_t message_type,
		uint64_t data_len, uint64_t meta_len)
{
	struct jalp_connection_headers *connection_headers = jal_malloc(sizeof(*connection_headers));
	connection_headers->protocol_version = 1;
	connection_headers->message_type = message_type;
	connection_headers->data_len = data_len;
	connection_headers->meta_len = meta_len;
	return connection_headers;
}

void jalp_connection_headers_destroy(struct jalp_connection_headers **connection_headers)
{
	if (!connection_headers || !(*connection_headers)) {
		return;
	}

	free(*connection_headers);
	*connection_headers = NULL;
}

enum jal_status jalp_connection_fill_out_msghdr(struct iovec *iov,
		struct jalp_connection_headers *connection_headers, void *data, void *meta)
{
	// make sure msgh and iov have been allocated
	if (!iov) {
		return JAL_E_INVAL;
	}

	int i = 0;

	// protocol version
	iov[i].iov_base = &connection_headers->protocol_version;
	iov[i].iov_len = sizeof(connection_headers->protocol_version);
	i++;

	// message type
	iov[i].iov_base = &connection_headers->message_type;
	iov[i].iov_len = sizeof(connection_headers->message_type);
	i++;

	// data length
	iov[i].iov_base = &connection_headers->data_len;
	iov[i].iov_len = sizeof(connection_headers->data_len);
	i++;

	// metadata length
	iov[i].iov_base = &connection_headers->meta_len;
	iov[i].iov_len = sizeof(connection_headers->meta_len);
	i++;

	if (connection_headers->message_type != JALP_JOURNAL_FD_MSG) {
		// log data
		iov[i].iov_base = data;
		iov[i].iov_len = connection_headers->data_len;
		i++;

		// BREAK
		iov[i].iov_base = JALP_BREAK_STR;
		iov[i].iov_len = strlen(JALP_BREAK_STR);
		i++;
	}

	// metadata 
	iov[i].iov_base = meta;
	iov[i].iov_len = connection_headers->meta_len;
	i++;

	// BREAK
	iov[i].iov_base = JALP_BREAK_STR;
	iov[i].iov_len = strlen(JALP_BREAK_STR);

	return JAL_OK;
}

enum jal_status jalp_sendmsg(jalp_context *ctx, struct msghdr *msgh)
{
	int flags = 0;
	ssize_t bytes_sent = 0;

	if (!ctx || !msgh) {
		return JAL_E_INVAL;
	}

	size_t i = 0;
	while (i < (size_t)msgh->msg_iovlen) {
		if (bytes_sent >= (ssize_t)msgh->msg_iov[i].iov_len) {
			bytes_sent -= msgh->msg_iov[i].iov_len;
			msgh->msg_iov[i].iov_len = 0;
			msgh->msg_iov[i].iov_base = NULL;
			i++;
		} else {
			ssize_t offset = msgh->msg_iov[i].iov_len - bytes_sent;
			msgh->msg_iov[i].iov_base += bytes_sent;
			msgh->msg_iov[i].iov_len = offset;
			bytes_sent = sendmsg(ctx->socket, msgh, flags);

			while (-1 == bytes_sent) {
				int myerrno;
				myerrno = errno;
				if (EINTR == myerrno) {
					bytes_sent = sendmsg(ctx->socket, msgh, flags);
				} else {
					return JAL_E_NOT_CONNECTED;
				}
			}

			msgh->msg_control = NULL;
			msgh->msg_controllen = 0;
		}
	}

	return JAL_OK;
}

enum jal_status jalp_send_buffer(jalp_context *ctx, uint16_t message_type,
		void *data, uint64_t data_len, void *meta, uint64_t meta_len, int fd)
{
	struct jalp_connection_headers *connection_headers = NULL;
	enum jal_status status;

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));
	int iovlen = 8;
	if (message_type == JALP_JOURNAL_FD_MSG) {
		iovlen = 6;
	}
	struct iovec iov[iovlen];
	msgh.msg_iovlen = iovlen;
	msgh.msg_iov = iov;

	// make sure message type is one of the allowed ones
	if (message_type != JALP_LOG_MSG && message_type != JALP_AUDIT_MSG &&
			message_type != JALP_JOURNAL_MSG && message_type != JALP_JOURNAL_FD_MSG) {
		status = JAL_E_INVAL;
		goto out;
	}

	// only can send fd if message type is JALP_JOURNAL_FD_MSG
	if (message_type != JALP_JOURNAL_FD_MSG && fd != -1) {
		status = JAL_E_INVAL;
		goto out;
	}

	// if we are sending an fd, then it must be a valid fd
	if (message_type == JALP_JOURNAL_FD_MSG && fd < 0) {
		status = JAL_E_INVAL;
		goto out;
	}

	// we don't send data if this is a journal fd msg
	if (message_type == JALP_JOURNAL_FD_MSG && data != NULL) {
		status = JAL_E_INVAL;
		goto out;
	}

	// if data_len and meta_len are greater than 0, 
	// then data and meta shouldn't be NULL
	if (meta_len > 0 && meta == NULL) {
		status = JAL_E_INVAL;
		goto out;
	}
	if (message_type != JALP_JOURNAL_FD_MSG && data_len > 0 && data == NULL) {
		status = JAL_E_INVAL;
		goto out;
	}

	// oppositely, if data and meta are not null, 
	// then data_len and meta_len shouldn't be 0
	if (meta != NULL && meta_len == 0) {
		status = JAL_E_INVAL;
		goto out;
	}
	if (message_type != JALP_JOURNAL_FD_MSG && data != NULL && data_len == 0) {
		status = JAL_E_INVAL;
		goto out;
	}

	if (!ctx) {
		status = JAL_E_INVAL;
		goto out;
	}

	// if we are not connected, try to connect
	if (ctx->socket == -1) {
		status = jalp_context_connect(ctx);
		if (status != JAL_OK) {
			status = JAL_E_NOT_CONNECTED;
			goto out;
		}
	}


	connection_headers = jalp_connection_headers_create(message_type, data_len, meta_len);

	status = jalp_connection_fill_out_msghdr(iov, connection_headers, data, meta);
	if (status != JAL_OK) {
		status = JAL_E_NOT_CONNECTED;
		goto out;
	}


	// also send fd if this is a journal fd message
	if (message_type == JALP_JOURNAL_FD_MSG) {
		// this code is from man 3 cmsg
		char buffer[CMSG_SPACE(sizeof(fd))];
		struct cmsghdr *cmsg;
		int *fdptr;

		msgh.msg_control = buffer;
		msgh.msg_controllen = sizeof(buffer);

		cmsg = CMSG_FIRSTHDR(&msgh);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
		fdptr = (int *) CMSG_DATA(cmsg);
		memcpy(fdptr, &fd, sizeof(fd));
		msgh.msg_controllen = cmsg->cmsg_len;
	}


	status = jalp_sendmsg(ctx, &msgh);

out:
	jalp_connection_headers_destroy(&connection_headers);
	return status;

}
