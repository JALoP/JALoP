/**
 * @file test_jalls_msg.c This file contains tests for jalls_msg functions.
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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <test-dept.h>
#include "jalls_msg.h"

#define FAKE_MSG_SIZE 128

void teardown()
{
	restore_function(recvmsg);
}

static ssize_t fake_recvmsg(__attribute((unused)) int fd,
			__attribute__((unused)) struct msghdr *msg,
			__attribute__((unused)) int flags)
{
	return FAKE_MSG_SIZE;
}

static ssize_t recvmsg_always_fails(__attribute((unused)) int fd,
				__attribute((unused)) struct msghdr *msg,
				__attribute((unused)) int flags)
{
	return -1;
}

static ssize_t recvmsg_always_fails_errno_EBADF(__attribute((unused)) int fd,
					__attribute((unused)) struct msghdr *msg,
					__attribute((unused)) int flags)
{
	errno = EBADF;
	return -1;
}

void test_jalls_recvmsg_returns_valid_size_given_valid_input()
{
	struct msghdr msgh;
	struct iovec iov[2];
	iov[0].iov_len = 12;
	iov[1].iov_len = FAKE_MSG_SIZE - 12;
	msgh.msg_iovlen = 2;
	msgh.msg_iov = iov;
	replace_function(recvmsg, fake_recvmsg);
	ssize_t rc = jalls_recvmsg_helper(0, &msgh, 0);
	assert_equals(FAKE_MSG_SIZE, rc);
}

void test_jalls_recvmsg_returns_error_when_recvmsg_fails()
{
	replace_function(recvmsg, recvmsg_always_fails);
	ssize_t rc = jalls_recvmsg_helper(0, NULL, 0);
	assert_equals(-1, rc);
}

void test_jalls_recvmsg_returns_error_when_recvmsg_fails_with_errno_EBADF()
{
	struct msghdr msgh;
	struct iovec iov;
	iov.iov_len = 12;
	msgh.msg_iovlen = 1;
	msgh.msg_iov = &iov;
	replace_function(recvmsg, recvmsg_always_fails_errno_EBADF);
	ssize_t rc = jalls_recvmsg_helper(0, &msgh, 0);
	assert_equals(EBADF, errno);
	assert_equals(-1, rc);
}
