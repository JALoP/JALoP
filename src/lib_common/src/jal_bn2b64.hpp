/*
 * @section LICENSE
 * Copyright 2002-2010 The Apache Software Foundation.
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
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _JAL_BN2B64_HPP_
#define _JAL_BN2B64_HPP_

#include <jalop/jal_status.h>

// XML-Security-C (XSEC)
#include <xsec/framework/XSECProvider.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>

/**
 * Convert an OpenSSL BIGNUM to a Xerces XMLCh pointer of the base 64 representation
 * of the BIGNUM.
 *
 * @param[in] bn The BIGNUM to convert.
 *
 * @return XMLCh pointer to the b64 representation of the BIGNUM.  This needs
 * to be free'd with XMLString::release().
 */
XMLCh * jal_BN2b64(BIGNUM * bn);

#endif // _JAL_BN2B64_HPP_
