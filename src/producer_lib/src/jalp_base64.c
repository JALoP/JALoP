/*
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

#include <string.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <jalop/jal_status.h>

#include "jal_alloc.h"
#include "jalp_base64_internal.h"
#include "jal_error_callback_internal.h"


char *jalp_base64_enc(const unsigned char *input, int length)
{
	// Openssl runtime allocates memory that needs to be freed with
	// a call to CRYPTO_cleanup_all_ex_data() before ending the program.

	BIO *b64 = NULL;
	BIO *bmem = NULL;
	BUF_MEM *bptr;
	int ret;
	char *buff = NULL;

	if (!input || length <= 0) {
		goto b64_out;
	}

	b64 = BIO_new(BIO_f_base64());
	if (!b64) {
		jal_error_handler(JAL_E_NO_MEM);
	}

	bmem = BIO_new(BIO_s_mem());
	if (!bmem) {
		jal_error_handler(JAL_E_NO_MEM);
	}

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(b64, bmem);
	ret = BIO_write(b64, input, length);
	if (ret <= 0) {
		// This should never happen.  BIO_write only returns an error
		// if a write fails, but since we are just writing to memory
		// that has already been allocated, we shouldn't have any problem.
		goto b64_out;
	}

	ret = BIO_flush(b64);
	if (ret <= 0) {
		// As above, this should never happen.
		goto b64_out;
	}

	BIO_get_mem_ptr(bmem, &bptr);

	size_t malloc_amount = bptr->length;
	buff = jal_malloc(malloc_amount + 1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = 0;

b64_out:
	BIO_free(bmem);
	BIO_free(b64);
	return buff;
}
