/**
 * @file jalp_init.cpp This file defines the Producer Library
 * init and shutdown functions.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <xmlsec/xmlsec.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <jalop/jal_status.h>
#include <jalop/jalp_context.h>

enum jal_status jalp_init()
{
	SSL_library_init();
	xmlSecInit();
	xmlSecCryptoDLLoadLibrary(BAD_CAST "openssl");
	xmlSecCryptoAppInit(NULL);
	xmlSecCryptoInit();

	return JAL_OK;
}

void jalp_shutdown()
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	xmlSecCryptoShutdown();
	xmlSecCryptoAppShutdown();
	xmlSecShutdown();
}
