/**
 * @file jalp_context_crypto.c This file defines the JALoP context crypto
 * functions.
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

#include <stdio.h>
#include <openssl/pem.h>

#include <jalop/jal_status.h>
#include <jalop/jalp_context.h>
#include "jalp_context_internal.h"

enum jal_status jalp_context_load_pem_rsa(jalp_context *ctx,
		const char *keyfile,
		pem_password_cb *cb)
{
	if (!ctx || !keyfile) {
		return JAL_E_INVAL;
	}

	FILE *fp;
	RSA *key;

	if (ctx->signing_key) {
		return JAL_E_EXISTS;
	}
	fp = fopen(keyfile, "r");
	if (!fp) {
		return JAL_E_FILE_OPEN;
	}
	key = PEM_read_RSAPrivateKey(fp, NULL, cb, NULL);
	fclose(fp);
	if (!key) {
		return JAL_E_READ_PRIVKEY;
	}
	ctx->signing_key = key;
	return JAL_OK;
}

enum jal_status jalp_context_load_pem_cert(jalp_context *ctx,
		const char *certfile)
{
	if (!ctx || !certfile) {
		return JAL_E_INVAL;
	}

	FILE *fp;
	X509 *cert;

	fp = fopen(certfile, "r");
	if (!fp) {
		return JAL_E_FILE_OPEN;
	}
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!cert) {
		return JAL_E_READ_X509;
	}
	if (ctx->signing_cert) {
		X509_free(ctx->signing_cert);
	}
	ctx->signing_cert = cert;
	return JAL_OK;
}
