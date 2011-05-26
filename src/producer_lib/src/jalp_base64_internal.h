/**
 * @file jalop_base64.c
 * Defines base64 encoding function.
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
#ifndef _JALP_BASE64_INTERNAL_H_
#define _JALP_BASE64_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Base 64 encodes.
 * If \p input is encoded with no issues, return a char * buffer with the
 * encoded data.  If there were errors encoding data, NULL is returned.  If
 * there were errors allocating memory jalp_error_handler() is called.
 *
 * @param[in] input The input to encode.
 * @param[in] length The length of input, not counting the \0 at the end of
 *		a string.
 *
 * @return a char pointer to the encoded input, to be freed with free().
 *			If \p input is NULL or length is less than or equal to 0,
 *			then NULL will be returned.
 */
char *jalp_base64_enc(const unsigned char *input, int length);

#ifdef __cplusplus
}
#endif

#endif //_JALP_BASE64_INTERNAL_H_

