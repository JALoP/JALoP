/**
 * @file jaln_string_utils.c
 *
 * Various string utilities
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

#include <axl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "jal_alloc.h"
#include "jaln_string_utils.h"

axl_bool jaln_ascii_to_uint64(const char *str, uint64_t *out)
{
	if (!str || !out) {
		return axl_false;
	}
	char *tmp = strdup(str);
	axl_stream_trim(tmp);
	char *end;
	axl_bool ret = axl_false;
	if ('0' > tmp[0] || '9' < tmp[0]) {
		goto out;
	}
	errno = 0;
	unsigned long long val = strtoull(tmp, &end, 10);
	int my_errno = errno;
	// strtoull() will stop processing at the first non-numeric
	// value, make sure there is no trailing garbage.
	if ('\0' != *end) {
		goto out;
	}
	if (((0 == val) || (ULLONG_MAX == val)) &&
			(0 != my_errno)) {
		// error parsing the number
		goto out;
	}
	if (UINT64_MAX < val) {
		// add an error if the value overflows
		goto out;
	}
	*out = (uint64_t) val;
	ret = axl_true;
out:
	free(tmp);
	return ret;
}

axl_bool jaln_ascii_to_uint64_t(const char *str, uint64_t *out)
{
	uint64_t tmp_out;
	if (!jaln_ascii_to_uint64(str, &tmp_out)) {
		return axl_false;
	}
	if (tmp_out > SIZE_MAX) {
		// overflow...
		return axl_false;
	}
	*out = (uint64_t) tmp_out;
	return axl_true;
}

enum jal_status jaln_hex_to_bin(char c, uint8_t *out)
{
	if (!out) {
		return JAL_E_INVAL;
	}
	uint8_t val;
	switch(c) {
	case '0':
		val = 0;
		break;
	case '1':
		val = 1;
		break;
	case '2':
		val = 2;
		break;
	case '3':
		val = 3;
		break;
	case '4':
		val = 4;
		break;
	case '5':
		val = 5;
		break;
	case '6':
		val = 6;
		break;
	case '7':
		val = 7;
		break;
	case '8':
		val = 8;
		break;
	case '9':
		val = 9;
		break;
	case 'A':
	case 'a':
		val = 10;
		break;
	case 'B':
	case 'b':
		val = 11;
		break;
	case 'C':
	case 'c':
		val = 12;
		break;
	case 'D':
	case 'd':
		val = 13;
		break;
	case 'E':
	case 'e':
		val = 14;
		break;
	case 'F':
	case 'f':
		val = 15;
		break;
	default:
		return JAL_E_INVAL;
	}
	*out = val;
	return JAL_OK;
}

enum jal_status jaln_hex_str_to_bin_buf(const char *hex_buf, uint64_t hex_buf_len, uint8_t **dgst_buf_out, uint64_t *dgst_buf_len_out)
{
	if (!hex_buf || (0 == hex_buf_len) || !dgst_buf_out || *dgst_buf_out || !dgst_buf_len_out) {
		return JAL_E_INVAL;
	}
	int res_off = 0;
	uint64_t res_len = hex_buf_len / 2;
	unsigned src_mod_check = 0;
	// Need to adjust the offset/length if the input isn't a multiple of 2
	if (hex_buf_len % 2) {
		res_len += 1;
		src_mod_check = 1;
	}
	
	uint8_t *result = jal_calloc(res_len, sizeof(*result));
	for (uint64_t src_off = 0; src_off < hex_buf_len; src_off++) {
		uint8_t val;
		if (JAL_OK != jaln_hex_to_bin(hex_buf[src_off], &val)) {
			goto err_out;
		}
		if ((src_off % 2) == src_mod_check) {
			result[res_off] |= val << 4;
		} else {
			result[res_off] |= val;
			res_off++;
		}
	}
	*dgst_buf_out = result;
	*dgst_buf_len_out = res_len;
	return JAL_OK;
err_out:
	free(result);
	return JAL_E_INVAL;
}


