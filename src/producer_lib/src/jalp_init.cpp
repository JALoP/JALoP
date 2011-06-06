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

#include <xercesc/util/PlatformUtils.hpp>
#include <openssl/evp.h>

#include <jalop/jal_status.h>
#include <jalop/jalp_context.h>


XERCES_CPP_NAMESPACE_USE

enum jal_status jalp_init()
{

	try {
		XMLPlatformUtils::Initialize();
	}

	catch(...) {
		return JAL_E_UNINITIALIZED;
	}

	return JAL_OK;
}

void jalp_shutdown()
{
	XMLPlatformUtils::Terminate();

	CRYPTO_cleanup_all_ex_data();

}
