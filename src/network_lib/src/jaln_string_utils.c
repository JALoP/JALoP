/**
 * @file jal_string_utils.c
 *
 * Various string utilities
 *
 * @section LICENSE
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

#include <axl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jaln_string_utils.h"

axl_bool jaln_ascii_to_uint64(const char *str, uint64_t *out)
{
	char *tmp = strdup(str);
	axl_stream_trim(tmp);
	char *end;
	axl_bool ret = axl_false;
	if (tmp[0] < '1' || tmp[0] > '9') {
		goto out;
	}
	errno = 0;
	unsigned long long val = strtoull(tmp, &end, 10);
	int my_errno = errno;
	// strtoull() will stop processing at the first non-numeric
	// value, make sure there is no trailing garbage.
	if (*end != '\0') {
		goto out;
	}
	if (((val == 0) || (val == ULLONG_MAX)) &&
			(my_errno != 0)) {
		// error parsing the number
		goto out;
	}
	if (val > UINT64_MAX) {
		// add an error if the value overflows
		goto out;
	}
	*out = (uint64_t) val;
	ret = axl_true;
out:
	free(tmp);
	return ret;
}

axl_bool jal_ascii_to_size_t(const char *str, size_t *out)
{
	uint64_t tmp_out;
	if (!jaln_ascii_to_uint64(str, &tmp_out)) {
		return axl_false;
	}
	if (tmp_out > SIZE_MAX) {
		// overflow...
		return axl_false;
	}
	*out = (size_t) tmp_out;
	return axl_true;
}

