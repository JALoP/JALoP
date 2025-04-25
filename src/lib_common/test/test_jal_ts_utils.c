/**
 * @file test_jal_fs_utils.c This file contains functions to test jal_fs_utils.c.
 *
 * ### LICENSE
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

#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <test-dept.h>

#include "jal_ts_utils.h"
#include "test_utils.h"

void test_jal_gen_timestamp_usec_works()
{
	char *timestamp = jal_gen_timestamp_usec();
	assert_not_equals(NULL,timestamp);
	struct tm time;
	int ms;

	char *end_timestamp = strptime(timestamp, "%Y-%m-%dT%H:%M:%S", &time);

	assert_not_equals(NULL,end_timestamp);

	assert_equals(1,sscanf(end_timestamp,".%d-%*d:%*d",&ms));
}

