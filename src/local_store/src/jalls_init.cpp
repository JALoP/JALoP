/**
 * @file jalls_init.cpp This file contains the definition of functions to
 * initialize/cleanup libraries used by the local store.
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

#include "jalls_init.h"

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/crypto.h>

int jalls_init()
{
	SSL_library_init();
	xmlSecInit();
	xmlSecCryptoDLLoadLibrary((xmlChar*) "openssl");
	(void)xmlIsMainThread();

	xmlSecCryptoAppInit(NULL);
	xmlSecCryptoInit();


	return 0;
}

void jalls_shutdown()
{
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();

	xmlCleanupParser();
	xmlCleanupGlobals();
}


