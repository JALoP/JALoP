/**
 * @file jalls_handler.c This file contains functions to handle a connection
 * to the jalp local store.
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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/un.h>

#ifdef SCM_UCRED
#include <ucred.h>
#endif

#include "jalls_msg.h"
#include "jalls_handler.h"
#include "jalls_handle_journal.hpp"
#include "jalls_handle_log.hpp"
#include "jalls_handle_audit.hpp"
#include "jalls_handle_journal_fd.hpp"

#define JALLS_LOG_MSG 1
#define JALLS_AUDIT_MSG 2
#define JALLS_JOURNAL_MSG 3
#define JALLS_JOURNAL_FD_MSG 4
#define JALLS_BREAK_STRING "BREAK"
#define JALLS_BREAK_LEN 5

void *jalls_handler(void *thread_ctx_p) {
	if (!thread_ctx_p) {
		return NULL; //should never happen.
	}

	struct jalls_thread_context *thread_ctx = NULL;
	thread_ctx = thread_ctx_p;
	pid_t *pid = NULL;
	uid_t *uid = NULL;
	int cred_type = 0;
	int debug = thread_ctx->ctx->debug;
	int err = pthread_detach(pthread_self());
	if (err < 0) {
		if (debug) {
			fprintf(stderr, "Failed to detach the thread\n");
		}
		goto out;
	}

#if defined (SCM_CREDENTIALS)
	cred_type = SCM_CREDENTIALS;
#elif defined (SCM_UCRED)
	cred_type = SCM_UCRED;
#endif

	while (1) {

		// read protocol version, message type, data length,
		// metadata length and possible fd.
		uint16_t protocol_version;
		uint16_t message_type;
		uint64_t data_len;
		uint64_t meta_len;
		int msg_fd = -1;

		struct msghdr msgh;
		memset(&msgh, 0, sizeof(msgh));

		struct iovec iov[4];
		iov[0].iov_base = &protocol_version;
		iov[0].iov_len = sizeof(protocol_version);
		iov[1].iov_base = &message_type;
		iov[1].iov_len = sizeof(message_type);
		iov[2].iov_base = &data_len;
		iov[2].iov_len = sizeof(data_len);
		iov[3].iov_base = &meta_len;
		iov[3].iov_len = sizeof(meta_len);

		msgh.msg_iov = iov;
		msgh.msg_iovlen = 4;

		char msg_control_buffer[CMSG_SPACE(sizeof(msg_fd))];

		msgh.msg_control = msg_control_buffer;
		msgh.msg_controllen = sizeof(msg_control_buffer);

#ifdef SCM_CREDENTIALS
		struct ucred cred;
		memset(&cred, 0, sizeof(cred));
		pid = &cred.pid;
		uid = &cred.uid;
#endif
#ifdef SCM_UCRED
		ucred_t *cred = NULL;
		pid = malloc(sizeof(*pid));
		uid = malloc(sizeof(*uid));
#endif
		*pid = -1;
		*uid = 0;
		
		ssize_t bytes_recv = jalls_recvmsg_helper(thread_ctx->fd, &msgh, debug);
		if (bytes_recv < 0) {
			if (debug) {
				fprintf(stderr, "Failed to receive the message header\n");
			}
			goto out;
		}
		if (bytes_recv == 0) {
			if (debug) {
				fprintf(stderr, "The peer has shutdown\n");
			}
			goto out;
		}

		//receive fd
		struct cmsghdr *cmsg;
		cmsg = CMSG_FIRSTHDR(&msgh);
		while (cmsg != NULL) {
			if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type  == cred_type) {
				if (debug && (*uid != 0 || *pid != -1)) {
					fprintf(stderr, "received duplicate ancillary data: multiple credentials.\nFirst credentials will be overwritten\n");
				}
#ifdef SCM_CREDENTIALS
				memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
#endif
#ifdef SCM_UCRED
				memcpy(cred, CMSG_DATA(cmsg), sizeof(cred));
				*pid = ucred_getpid(cred);
				*uid = ucred_geteuid(cred);
#endif
			} else if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type  == SCM_RIGHTS
				&& cmsg->cmsg_len == CMSG_LEN(sizeof(msg_fd))) {
				if (message_type != JALLS_JOURNAL_FD_MSG) {
					if (debug) {
						fprintf(stderr, "received an fd for a message type that was not journal_fd\n");
					}
					goto out;
				}
				void *tmp_fd = CMSG_DATA(cmsg);
				if (debug && msg_fd != -1) {
					fprintf(stderr, "received duplicate ancillary data: overwrote the fd\n");
				}
				msg_fd = *((int *)tmp_fd);
				if (msg_fd < 0) {
					if (debug) {
						fprintf(stderr, "received an fd < 0\n");
					}
					goto out;
				}
			} else {
				if (debug) {
					fprintf(stderr, "received unrecognized ancillary data\n");
				}
				goto out;
			}
			cmsg = CMSG_NXTHDR(&msgh, cmsg);
		}

		thread_ctx->peer_pid = *pid;
		thread_ctx->peer_uid = *uid;
		if (debug && *pid == -1) {
			thread_ctx->peer_pid = 0;
			thread_ctx->peer_uid = 0;

			fprintf(stderr, "Did not receive credentials\n");
		}

		if (protocol_version != 1) {
			if (debug) {
				fprintf(stderr, "received protocol version != 1\n");
			}
			return NULL;
		}

		//call appropriate handler
		switch (message_type) {
			case JALLS_LOG_MSG:
				err = jalls_handle_log(thread_ctx, data_len, meta_len);
				break;
			case JALLS_AUDIT_MSG:
				err = jalls_handle_audit(thread_ctx, data_len, meta_len);
				break;
			case JALLS_JOURNAL_MSG:
				err = jalls_handle_journal(thread_ctx, data_len, meta_len);
				break;
			case JALLS_JOURNAL_FD_MSG:
				if (msg_fd < 0) {
					if (debug) {
						fprintf(stderr, "Message type is journal_fd, but no fd was received\n");
					}
					goto out;
				}
				err = jalls_handle_journal_fd(thread_ctx, data_len, meta_len, msg_fd);
				break;
			default:
				if (debug) {
					fprintf(stderr, "Message type is not legal.\n");
				}
				goto out;
		}
		if (err < 0) {
			goto out;
		}
	}

out:
#ifdef SCM_UCRED
	free(pid);
	free(uid);
#endif
	free(thread_ctx);
	return NULL;
}

int jalls_handle_app_meta(uint8_t **app_meta_buf, size_t app_meta_len, int fd, int debug) {

	*app_meta_buf = malloc(app_meta_len);

	struct iovec iov[1];
	iov[0].iov_base = *app_meta_buf;
	iov[0].iov_len = app_meta_len;

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));
	msgh.msg_iov = iov;
	msgh.msg_iovlen = 1;

	ssize_t bytes_received = jalls_recvmsg_helper(fd, &msgh, debug);

	if ((unsigned)bytes_received == app_meta_len) {
		return 0;
	}

	return -1;
}

int jalls_handle_break(int fd) {
	char break_str[JALLS_BREAK_LEN + 1];

	struct iovec iov[1];
	iov->iov_base = break_str;
	iov->iov_len = JALLS_BREAK_LEN;

	struct msghdr msgh;
	memset(&msgh, 0, sizeof(msgh));

	msgh.msg_iov = iov;
	msgh.msg_iovlen = 1;

	ssize_t bytes_received = jalls_recvmsg_helper(fd, &msgh, 0);
	if (bytes_received != JALLS_BREAK_LEN) {
		return -1;
	}

	break_str[JALLS_BREAK_LEN] = 0;

	if (0 != strcmp(JALLS_BREAK_STRING, break_str)) {
		return -1;
	}

	return 0;
}
