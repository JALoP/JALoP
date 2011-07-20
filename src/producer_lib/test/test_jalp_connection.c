/**
 * @file This file contains tests for helper functions related to sending DATA
 * to the JAL Local store.
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

#include <test-dept.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "jalp_connection_internal.h"
#include <stdint.h>

#define DATA "some_data"
#define METADATA "some_metadata"
#define BREAK "BREAK"

#define FD 1234

int failed_version;
int failed_message_type;
int failed_data_len;
int failed_meta_len;
int failed_data_content;
int failed_data_canary;
int failed_meta_content;
int failed_meta_canary;

uint64_t expected_data_len;
uint64_t expected_meta_len;
uint64_t expected_type;

#define BUF_SIZE 1024

ssize_t fake_sendmsg(__attribute__((unused)) int sockfd, const struct msghdr *msg, __attribute__((unused)) int flags)
{
	ssize_t ret = -1;
	long int i;
	const long iov_len  = (long) msg->msg_iovlen;
	int sz = 0;
	for (i=0; i < iov_len; i++) {
		sz += msg->msg_iov[i].iov_len;
	}
	ret = sz;
	uint8_t *buffer = (uint8_t*) malloc(sz);
	int cnt = 0;
	for (i=0; i < iov_len; i++) {
		memcpy(buffer + cnt, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
		cnt += msg->msg_iov[i].iov_len;
	}

	// now need to make sure everything as it should be...
	uint8_t *cur = buffer;
	uint16_t version = *(uint16_t*)cur;
	if (version != 1) {
		failed_version = 1;
		goto out;
	}
	cur += sizeof(version);

	uint16_t message_type = *(uint16_t*)cur;
	if (message_type != expected_type) {
		failed_message_type = 1;
		goto out;
	}
	cur += sizeof(message_type);

	uint64_t data_len = *(uint64_t*)cur;
	if (data_len != expected_data_len) {
		failed_data_len = 1;
		goto out;
	}
	cur += sizeof(data_len);

	uint64_t meta_len = *(uint64_t*)cur;
	if (meta_len != expected_meta_len) {
		failed_meta_len = 1;
		goto out;
	}
	cur += sizeof(meta_len);

	if (message_type != 4) {
		// not a journal + fd
		if (0 != memcmp(cur, DATA, expected_data_len)) {
			failed_data_content = 1;
			goto out;
		}
		cur += data_len;
		if (0 != memcmp(cur, BREAK, strlen(BREAK))) {
			failed_data_canary = 1;
			goto out;
		}
		cur += strlen(BREAK);
	}

	if (meta_len != expected_meta_len) {
		failed_meta_len = 1;
		goto out;
	}

	if (0 != memcmp(cur, METADATA, meta_len)) {
		failed_data_content = 1;
		goto out;
	}
	cur += meta_len;

	if (0 != memcmp(cur, BREAK, strlen(BREAK))) {
		failed_meta_canary = 1;
		goto out;
	}

out:
	free(buffer);
	return ret;
}

jalp_context *ctx;
ssize_t sendmsg_fails_once(__attribute__((unused)) int sockfd, __attribute__((unused)) const struct msghdr *msg, __attribute__((unused)) int flags)
{
	return -1;
	replace_function(sendmsg, fake_sendmsg);
}
ssize_t sendmsg_always_fails(__attribute__((unused)) int sockfd, __attribute__((unused)) const struct msghdr *msg, __attribute__((unused)) int flags)
{
	return -1;
}
enum jal_status fake_context_connect(__attribute__((unused)) jalp_context *c)
{
	return JAL_OK;
}
void setup()
{
	replace_function(jalp_context_connect, fake_context_connect);
	replace_function(sendmsg, fake_sendmsg);
	ctx = jalp_context_create();
	jalp_context_init(ctx, NULL, NULL, NULL, NULL);

	failed_version = 0;
	failed_message_type = 0;
	failed_data_len = 0;
	failed_meta_len = 0;
	failed_data_content = 0;
	failed_data_canary = 0;
	failed_meta_content = 0;
	failed_meta_canary = 0;

	expected_data_len = strlen(DATA);
	expected_meta_len = strlen(METADATA);
	expected_type = 0;
}
void teardown()
{
	jalp_context_destroy(&ctx);
}
void test_send_buffer_fails_with_bad_input()
{
	enum jal_status ret;
	// bad inputs for log messages
	ret = jalp_send_buffer(NULL, JALP_LOG_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_LOG_MSG, NULL, strlen(DATA), METADATA, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_LOG_MSG, DATA, 0, METADATA, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_LOG_MSG, DATA, strlen(DATA), NULL, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_LOG_MSG, DATA, strlen(DATA), METADATA, 0, -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_LOG_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), 0);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_LOG_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), FD);
	//assert_not_equals(JAL_OK, ret);

	// bad inputs for audit messages
	ret = jalp_send_buffer(NULL, JALP_AUDIT_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_AUDIT_MSG, NULL, strlen(DATA), METADATA, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_AUDIT_MSG, DATA, 0, METADATA, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_AUDIT_MSG, DATA, strlen(DATA), NULL, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_AUDIT_MSG, DATA, strlen(DATA), METADATA, 0, -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_AUDIT_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), 0);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_AUDIT_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), FD);
	assert_not_equals(JAL_OK, ret);

	// bad inputs for journal messages
	ret = jalp_send_buffer(NULL, JALP_JOURNAL_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_MSG, NULL, strlen(DATA), METADATA, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_MSG, DATA, 0, METADATA, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_MSG, DATA, strlen(DATA), NULL, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_MSG, DATA, strlen(DATA), METADATA, 0, -1);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), 0);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), FD);
	assert_not_equals(JAL_OK, ret);

	// bad inputs for journal_fd message
	ret = jalp_send_buffer(NULL, JALP_JOURNAL_FD_MSG, NULL, strlen(DATA), METADATA, strlen(METADATA), FD);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_FD_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), FD);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_FD_MSG, NULL, strlen(DATA), NULL, strlen(METADATA), FD);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_FD_MSG, NULL, strlen(DATA), METADATA, 0, FD);
	assert_not_equals(JAL_OK, ret);
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_FD_MSG, NULL, strlen(DATA), METADATA, strlen(METADATA), -1);
	assert_not_equals(JAL_OK, ret);
}

void test_send_log_buffer_works_with_data_buffer_and_metadata()
{
	enum jal_status ret;
	expected_type = 1;
	ret = jalp_send_buffer(ctx, JALP_LOG_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), -1);
	assert_equals(JAL_OK, ret);
	assert_false(failed_version);
	assert_false(failed_message_type);
	assert_false(failed_data_len);
	assert_false(failed_meta_len);
	assert_false(failed_data_content);
	assert_false(failed_data_canary);
	assert_false(failed_meta_content);
	assert_false(failed_meta_canary);
}

void test_send_log_buffer_works_with_data_buffer_and_no_metadata()
{
	enum jal_status ret;
	expected_meta_len = 0;
	expected_type = 1;
	ret = jalp_send_buffer(ctx, JALP_LOG_MSG, DATA, strlen(DATA), NULL, 0, -1);
	assert_equals(JAL_OK, ret);
	assert_false(failed_version);
	assert_false(failed_message_type);
	assert_false(failed_data_len);
	assert_false(failed_meta_len);
	assert_false(failed_data_content);
	assert_false(failed_data_canary);
	assert_false(failed_meta_content);
	assert_false(failed_meta_canary);
}
void test_send_log_buffer_works_with_no_data_buffer_and_metadata()
{
	enum jal_status ret;
	expected_data_len = 0;
	expected_type = 1;
	ret = jalp_send_buffer(ctx, JALP_LOG_MSG, NULL, 0, METADATA, strlen(METADATA), -1);
	assert_equals(JAL_OK, ret);
	assert_false(failed_version);
	assert_false(failed_message_type);
	assert_false(failed_data_len);
	assert_false(failed_meta_len);
	assert_false(failed_data_content);
	assert_false(failed_data_canary);
	assert_false(failed_meta_content);
	assert_false(failed_meta_canary);
}
void test_send_audit_buffer_works_with_data_buffer_and_metadata()
{
	enum jal_status ret;
	expected_type = 2;
	ret = jalp_send_buffer(ctx, JALP_AUDIT_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), -1);
	assert_equals(JAL_OK, ret);
	assert_false(failed_version);
	assert_false(failed_message_type);
	assert_false(failed_data_len);
	assert_false(failed_meta_len);
	assert_false(failed_data_content);
	assert_false(failed_data_canary);
	assert_false(failed_meta_content);
	assert_false(failed_meta_canary);
}

void test_send_audit_buffer_works_with_data_buffer_and_no_metadata()
{
	enum jal_status ret;
	expected_meta_len = 0;
	expected_type = 2;
	ret = jalp_send_buffer(ctx, JALP_AUDIT_MSG, DATA, strlen(DATA), NULL, 0, -1);
	assert_equals(JAL_OK, ret);
	assert_false(failed_version);
	assert_false(failed_message_type);
	assert_false(failed_data_len);
	assert_false(failed_meta_len);
	assert_false(failed_data_content);
	assert_false(failed_data_canary);
	assert_false(failed_meta_content);
	assert_false(failed_meta_canary);
}
void test_send_journal_buffer_works_with_data_buffer_and_metadata()
{
	enum jal_status ret;
	expected_type = 3;
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_MSG, DATA, strlen(DATA), METADATA, strlen(METADATA), -1);
	assert_equals(JAL_OK, ret);
	assert_false(failed_version);
	assert_false(failed_message_type);
	assert_false(failed_data_len);
	assert_false(failed_meta_len);
	assert_false(failed_data_content);
	assert_false(failed_data_canary);
	assert_false(failed_meta_content);
	assert_false(failed_meta_canary);
}

void test_send_journal_buffer_works_with_data_buffer_and_no_metadata()
{
	enum jal_status ret;
	expected_meta_len = 0;
	expected_type = 3;
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_MSG, DATA, strlen(DATA), NULL, 0, -1);
	assert_equals(JAL_OK, ret);
	assert_false(failed_version);
	assert_false(failed_message_type);
	assert_false(failed_data_len);
	assert_false(failed_meta_len);
	assert_false(failed_data_content);
	assert_false(failed_data_canary);
	assert_false(failed_meta_content);
	assert_false(failed_meta_canary);
}
void test_send_journal_fd_works_with_data_buffer_and_metadata()
{
	enum jal_status ret;
	expected_type = 4;
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_FD_MSG, NULL, strlen(DATA), METADATA, strlen(METADATA), FD);
	assert_equals(JAL_OK, ret);
	assert_false(failed_version);
	assert_false(failed_message_type);
	assert_false(failed_data_len);
	assert_false(failed_meta_len);
	assert_false(failed_data_content);
	assert_false(failed_data_canary);
	assert_false(failed_meta_content);
	assert_false(failed_meta_canary);
}

void test_send_journal_fd_works_with_data_buffer_and_no_metadata()
{
	enum jal_status ret;
	expected_meta_len = 0;
	expected_type = 4;
	ret = jalp_send_buffer(ctx, JALP_JOURNAL_FD_MSG, NULL, strlen(DATA), NULL, 0, FD);
	assert_equals(JAL_OK, ret);
	assert_false(failed_version);
	assert_false(failed_message_type);
	assert_false(failed_data_len);
	assert_false(failed_meta_len);
	assert_false(failed_data_content);
	assert_false(failed_data_canary);
	assert_false(failed_meta_content);
	assert_false(failed_meta_canary);
}


void test_jalp_send_msg()
{
}
