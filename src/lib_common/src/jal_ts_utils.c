/**
 * @file jal_ts_utils.c This file contains general timestamp utility functions.
 *
 * Copyright (C) 2025 The National Security Agency (NSA)
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "jal_alloc.h"
#include "jal_ts_utils.h"

#include <stdio.h>
#include <time.h>
#include <sys/time.h>

char *jal_gen_timestamp_usec()
{
	char *ftime = (char*)jal_malloc(34);
	struct tm *tm = (struct tm*)jal_malloc(sizeof(struct tm));

	struct timeval *tv = (struct timeval *)jal_malloc(sizeof(struct timeval));

	if (gettimeofday(tv,NULL) || !gmtime_r(&tv->tv_sec, tm)) {
		free(ftime);
		free(tm);
		free(tv);
		return NULL;
	}

	int bytes = strftime(ftime, 26, "%Y-%m-%dT%H:%M:%S", tm);

	snprintf(ftime + bytes, 8, ".%06ld", tv->tv_usec);

	free(tm);
	free(tv);

	return ftime;
}
