/**
 * @file This file contains tests for jaln_message_helpers.c functions.
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

#include <inttypes.h>
#include <jalop/jal_status.h>
#include <stdint.h>
#include <stdlib.h>

#include "jal_alloc.h"

#include "jaln_message_helpers.h"

#include <test-dept.h>
#include <string.h>
#include <ctype.h>

#define sid_1_str "sid_1"

#define EXPECTED_SYNC_MSG \
	"Content-Type: application/beep+jalop\r\n" \
	"Content-Transfer-Encoding: binary\r\n" \
	"JAL-Message: sync\r\n" \
	"JAL-Serial-Id: " sid_1_str "\r\n\r\n"

void test_create_journal_resume_msg_with_valid_parameters()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialID";
	uint64_t offset = 1;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);
	assert_equals(JAL_OK, ret);
	free(msg_out);
}

void test_create_journal_resume_msg_with_valid_parameters_is_formatted_correctly()
{
	enum jal_status ret = JAL_OK;

	char *correct_msg = "Content-Type: application/beep+jalop\r\nContent-Transfer-Encoding: binary\r\nJAL-Message: journal-resume\r\nJAL-Serial-Id: 1234562\r\nJAL-Journal-Offset: 47996\r\n\r\n";

	char *serial_id = "1234562";
	uint64_t offset = 47996;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);

	assert_equals(JAL_OK, ret);
	assert_string_equals(correct_msg, msg_out);
	free(msg_out);
}

void test_create_journal_resume_msg_with_invalid_parameters_serial_id_is_null()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = NULL;
	uint64_t offset = 1;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_invalid_parameters_msg_out_not_null()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialid";
	uint64_t offset = 1;
	char *msg_out = "some text!";
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_invalid_parameters_msg_out_len_is_null()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialid";
	uint64_t offset = 1;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_invalid_parameters_offset_is_zero()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "serialid";
	uint64_t offset = 0;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);
	assert_equals(JAL_E_INVAL, ret);
}

void test_create_journal_resume_msg_with_valid_parameters_offset_is_very_large()
{
	enum jal_status ret = JAL_OK;

	char *serial_id = "1234562";
	uint64_t offset = UINT64_MAX;
	char *msg_out = NULL;
	size_t *msg_out_len = NULL;
	size_t len = sizeof(msg_out);

	msg_out_len = &len;

	ret = jaln_create_journal_resume_msg(serial_id, offset, &msg_out, msg_out_len);

	assert_equals(JAL_OK, ret);

	// Code below parses the offset string back out of the journal-resume message.
	// Format assumptions come from the JALoP Specification v1.0 document
	// 	Expects "JAL-Journal-Offset: ###..#\r\n"
	// 	Where # is a digit 0-9
	char *journal_offset = strstr(msg_out, "JAL-Journal-Offset");

	strtok(journal_offset, ":");

	char *offset_string = strtok(NULL, " ");
	char *final_offset_string = NULL;
	char *beg = NULL;
	beg = offset_string;

	while (*beg != '\0') {
		if (*beg == '\r' || *beg == '\n') {
			char *tmp = beg;
			*beg = '\0';
			final_offset_string = strdup(offset_string);
			*beg = *tmp;
			break;
		}
		beg++;
	}

	assert_equals(offset, strtoull(final_offset_string, NULL, 10));
	free(msg_out);
	free(final_offset_string);
}

void test_create_sync_msg_works()
{
	char *msg_out = NULL;
	size_t len;
	assert_equals(JAL_OK, jaln_create_sync_msg(sid_1_str, &msg_out, &len));
	assert_equals(strlen(EXPECTED_SYNC_MSG) + 1, len);
	assert_equals(0, memcmp(EXPECTED_SYNC_MSG, msg_out, len));
	free(msg_out);
}

void test_create_sync_msg_does_not_crash_on_bad_input()
{
	char *msg_out = NULL;
	size_t len;
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(NULL, &msg_out, &len));
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(sid_1_str, NULL, &len));
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(sid_1_str, &msg_out, NULL));
	msg_out = (char*)0xbadf00d;
	assert_equals(JAL_E_INVAL, jaln_create_sync_msg(sid_1_str, &msg_out, &len));
}
