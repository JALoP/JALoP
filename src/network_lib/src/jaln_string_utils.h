/**
 * @file jaln_string_utils.h
 *
 * APIs for implementing and registering additional digest algorithms
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
#ifndef _JALN_STRING_UTILS_H_
#define _JALN_STRING_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <axl.h>
#include <jalop/jal_status.h>
#include <stddef.h> // for size_t
#include <stdint.h>

/**
 * Convert an ASCII string to a uint64_t.
 * This will fail if the string contains any non-numeric values, or
 * leading/trailing garbage. However, leading and trailing whitespace are
 * ignored. A valid string begins with a numeric value between 1 and 9 (0 is
 * not allowed) followed by additional digits. Sign characters are not allowed.
 *
 * @param[in] str The string to convert
 * @param[out] out The converted value
 *
 * @return axl_true on success, axl_false otherwise.
 */
axl_bool jaln_ascii_to_uint64(const char *str, uint64_t *out);

/**
 * Convert an ascii string to a size_t
 * The same rules apply as for jal_ascii_to_uint64, with the exception that the
 * output is limited to a size_t type.
 *
 * @param[in] str The string to convert
 * @param[out] The converted value
 * @return axl_true on success, axl_false otherwise
 */
axl_bool jaln_ascii_to_size_t(const char *str, size_t *out);

/**
 * Helper function to convert a hex character to a uint8_t value.
 *
 * @param [in] c The character to convert (0-9, a-f, or A-F)
 * @param [out] out The corresponding hex value.
 *
 * @return JAL_OK on success, or JAL_E_INVAL
 */
enum jal_status jaln_hex_to_bin(char c, uint8_t *out);

/**
 * Helper function to convert a buffer of hex characters to a buffer of uint8_t
 * values. The input buffer is not treated as a string, but as an array of
 * hex characters. That is to say, there should be no leading '0x' specifier,
 * and not trailing garbage (a '\0' is considered garbage).
 *
 * @param [in] hex_buf A buffer containing hex characters to convert.
 * @param [in] hex_buf_len The length of \p hex_buf
 * @param [out] dgst_buf_out The results of the conversion will be stored in
 * dgst_buf_out.
 * @param [out] dgst_buf_len_out The length of \p dgst_buf_out
 *
 * @return JAL_OK on success, or JAL_E_INVAL if any of the characters in the
 * string are not valid hex characters.
 */
enum jal_status jaln_hex_str_to_bin_buf(const char *hex_buf, size_t hex_buf_len,
		uint8_t **dgst_buf_out, size_t *dgst_buf_len_out);

#endif // _JALN_STRING_UTILS_H_
