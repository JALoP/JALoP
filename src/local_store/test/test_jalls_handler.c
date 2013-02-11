/**
 * @file test_jalls_handler.c This file contains tests for jalls_handler functions.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2013 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <test-dept.h>
#include "jal_alloc.h"
#include "jalls_init.h"
#include "jalls_msg.h"
#include "jalls_handler.h"
#include "jalls_handle_log.hpp"

#define FAKE_MSG_SIZE 128

static int pthread_detach_always_fails(__attribute__((unused)) pthread_t thread)
{
	return -1;
}

static int fake_pthread_detach(__attribute((unused)) pthread_t thread)
{
	return 0;
}

static pthread_t fake_pthread_self(void)
{
	return 0;
}

static int recvmsg_returns_msg_type_zero(__attribute__((unused)) int fd,
					struct msghdr *msg,
					__attribute__((unused)) int flags)
{
	*(uint16_t *)msg->msg_iov[0].iov_base = 1;
	*(uint16_t *)msg->msg_iov[1].iov_base = 0;
	*(uint64_t *)msg->msg_iov[2].iov_base = 0;
	*(uint64_t *)msg->msg_iov[3].iov_base = 0;

	msg->msg_control = NULL;

	return FAKE_MSG_SIZE;
}

static int recvmsg_returns_msg_type_jalls_log_msg(__attribute__((unused)) int fd,
							struct msghdr *msg,
							__attribute__((unused)) int flags)
{
	*(uint16_t *)msg->msg_iov[0].iov_base = 1;
	*(uint16_t *)msg->msg_iov[1].iov_base = 1;
	*(uint64_t *)msg->msg_iov[2].iov_base = 0;
	*(uint64_t *)msg->msg_iov[3].iov_base = 0;

	msg->msg_control = NULL;

	return FAKE_MSG_SIZE;
}

static int recvmsg_returns_msg_type_jalls_audit_msg(__attribute__((unused)) int fd,
						struct msghdr *msg,
						__attribute__((unused)) int flags)
{
	*(uint16_t *)msg->msg_iov[0].iov_base = 1;
	*(uint16_t *)msg->msg_iov[1].iov_base = 2;
	*(uint64_t *)msg->msg_iov[2].iov_base = 0;
	*(uint64_t *)msg->msg_iov[3].iov_base = 0;

	msg->msg_control = NULL;

	return FAKE_MSG_SIZE;
}

static int recvmsg_returns_msg_type_jalls_journal_msg(__attribute__((unused)) int fd,
						struct msghdr *msg,
						__attribute__((unused)) int flags)
{
	*(uint16_t *)msg->msg_iov[0].iov_base = 1;
	*(uint16_t *)msg->msg_iov[1].iov_base = 3;
	*(uint64_t *)msg->msg_iov[2].iov_base = 0;
	*(uint64_t *)msg->msg_iov[3].iov_base = 0;

	msg->msg_control = NULL;

	return FAKE_MSG_SIZE;
}

static int recvmsg_returns_msg_type_jalls_journal_fd_msg(int fd,
							struct msghdr *msg,
							__attribute__((unused)) int flags)
{
	struct cmsghdr *cmsgh = jal_malloc(sizeof(*cmsgh));

	cmsgh->cmsg_len = CMSG_LEN(sizeof(fd));
	cmsgh->cmsg_level = SOL_SOCKET;
	cmsgh->cmsg_type = SCM_RIGHTS;

	*(uint16_t *)msg->msg_iov[0].iov_base = 1;
	*(uint16_t *)msg->msg_iov[1].iov_base = 4;
	*(uint64_t *)msg->msg_iov[2].iov_base = 0;
	*(uint64_t *)msg->msg_iov[3].iov_base = 0;

	msg->msg_control = cmsgh;

	unsigned char *data = CMSG_DATA(cmsgh);

	*data = (unsigned char)fd;

	return FAKE_MSG_SIZE;
}

static int recvmsg_returns_protocol_zero(__attribute__((unused)) int fd,
					struct msghdr *msg,
					__attribute__((unused)) int flags)
{
	*(uint16_t *)msg->msg_iov[0].iov_base = 0;
	*(uint16_t *)msg->msg_iov[1].iov_base = 4;
	*(uint64_t *)msg->msg_iov[2].iov_base = 0;
	*(uint64_t *)msg->msg_iov[3].iov_base = 0;

	msg->msg_control = NULL;

	return FAKE_MSG_SIZE;
}

static int recvmsg_returns_non_null_cmsg_len_zero(__attribute__((unused)) int fd,
							struct msghdr *msg,
							__attribute__((unused)) int flags)
{
	struct cmsghdr *cmsgh = jal_malloc(sizeof(*cmsgh));

	cmsgh->cmsg_len = 0;
	cmsgh->cmsg_level = SOL_SOCKET;
	cmsgh->cmsg_type = SCM_RIGHTS;

	*(uint16_t *)msg->msg_iov[0].iov_base = 1;
	*(uint16_t *)msg->msg_iov[1].iov_base = 4;
	*(uint64_t *)msg->msg_iov[2].iov_base = 0;
	*(uint64_t *)msg->msg_iov[3].iov_base = 0;

	msg->msg_control = cmsgh;

	unsigned char *data = CMSG_DATA(cmsgh);

	*data = (unsigned char)fd;

	return FAKE_MSG_SIZE;
}

static int recvmsg_always_fails(__attribute__((unused)) int fd,
			__attribute__((unused)) struct msghdr *msg,
			__attribute__((unused)) int flags)
{
	return -1;
}

static int fake_jalls_handle_log(__attribute__((unused)) struct jalls_thread_context *ctx,
				__attribute__((unused)) uint64_t data_len,
				__attribute__((unused)) uint64_t meta_len)
{
	return -1;
}

struct jalls_context *jalls_ctx = NULL;
struct jalls_thread_context *thread_ctx = NULL;
jaldb_context *db_ctx = NULL;

void setup()
{
	jalls_ctx = jal_calloc(1, sizeof(*jalls_ctx));
	jalls_ctx->debug = 0;

	db_ctx = jaldb_context_create();

	thread_ctx = jal_calloc(1, sizeof(*thread_ctx));
	thread_ctx->fd = 0;
	thread_ctx->ctx = jalls_ctx;
	thread_ctx->db_ctx = db_ctx;

	replace_function(pthread_self, fake_pthread_self);
	replace_function(pthread_detach, fake_pthread_detach);

	jalls_init();
}

void teardown()
{
	restore_function(pthread_self);
	restore_function(pthread_detach);
	restore_function(jalls_recvmsg_helper);

	free(jalls_ctx);
	jaldb_context_destroy(&db_ctx);
	jalls_shutdown();
}

void test_jalls_handler_returns_null_when_given_null()
{
	void *ret = jalls_handler(NULL);
	assert_equals((void *) NULL, ret);
}

void test_jalls_handler_returns_null_when_pthread_detach_fails()
{
	replace_function(pthread_detach, pthread_detach_always_fails);
	void *ret = jalls_handler(thread_ctx);
	assert_equals((void *) NULL, ret);
}

void test_jalls_handler_returns_null_when_recvmsg_fails()
{
	replace_function(jalls_recvmsg_helper, recvmsg_always_fails);
	void *ret = jalls_handler(thread_ctx);
	assert_equals((void *) NULL, ret);
}

void test_jalls_handler_msg_type_is_zero()
{
	replace_function(jalls_recvmsg_helper, recvmsg_returns_msg_type_zero);
	void *ret = jalls_handler(thread_ctx);
	assert_equals((void *) NULL, ret);
}

void test_jalls_handler_msg_type_is_jalls_log_msg()
{
	replace_function(jalls_recvmsg_helper, recvmsg_returns_msg_type_jalls_log_msg);
	replace_function(jalls_handle_log, fake_jalls_handle_log);
	void *ret = jalls_handler(thread_ctx);
	assert_equals((void *) NULL, ret);
}

void test_jalls_handler_msg_type_is_jalls_audit_msg()
{
	replace_function(jalls_recvmsg_helper, recvmsg_returns_msg_type_jalls_audit_msg);
	void *ret = jalls_handler(thread_ctx);
	assert_equals((void *) NULL, ret);
}

void test_jalls_handler_msg_type_is_jalls_journal_msg()
{
	replace_function(jalls_recvmsg_helper, recvmsg_returns_msg_type_jalls_journal_msg);
	void *ret = jalls_handler(thread_ctx);
	assert_equals((void *) NULL, ret);
}

void test_jalls_handler_msg_type_is_jalls_journal_fd_msg()
{
	replace_function(jalls_recvmsg_helper, recvmsg_returns_msg_type_jalls_journal_fd_msg);
	void *ret = jalls_handler(thread_ctx);
	assert_equals((void *) NULL, ret);
}

void test_jalls_handler_protocol_is_zero()
{
	replace_function(jalls_recvmsg_helper, recvmsg_returns_protocol_zero);
	void *ret = jalls_handler(thread_ctx);
	assert_equals((void *) NULL, ret);
}

void test_jalls_handler_exits_cleanly_when_cmsg_len_zero_and_cmsg_not_null()
{
	replace_function(jalls_recvmsg_helper, recvmsg_returns_non_null_cmsg_len_zero);
	void *ret = jalls_handler(thread_ctx);
	assert_equals((void *) NULL, ret);

}
