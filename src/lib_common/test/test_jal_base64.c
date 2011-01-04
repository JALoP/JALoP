/**
 * @file test_jal_base64.c This file contains tests for jal_base64_enc.
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
#include <stdlib.h>
#include "jal_base64_internal.h"

void test_jal_base64_enc_null_input()
{
	char *inval = jal_base64_enc((unsigned char *)NULL, 10);
	assert_equals((char *)NULL, inval);
}

void test_jal_base64_enc_bad_lengths()
{
	char *inval = jal_base64_enc((unsigned char *)"inval", 0);
	assert_equals((char *)NULL, inval);

	inval = jal_base64_enc((unsigned char *)"inval", -200);
	assert_equals((char *)NULL, inval);
}

void test_jal_base64_enc_encodes()
{
	unsigned char bytes[4] = {(unsigned char)'a', (unsigned char)'s',
				(unsigned char)'d', (unsigned char)'f'};
	char *valid = jal_base64_enc(bytes, 4);
	assert_string_equals(valid, "YXNkZg==");
	free(valid);
}
