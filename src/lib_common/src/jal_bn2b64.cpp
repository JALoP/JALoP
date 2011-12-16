/*
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

/** 
 * This function is from 
 * xml-security-c-1.6.0/xsec/tools/xklient/xklient.cpp.
 */

#include <openssl/x509.h>
#include <xsec/enc/XSCrypt/XSCryptCryptoBase64.hpp>

#include "jal_alloc.h"

XERCES_CPP_NAMESPACE_USE

XMLCh * jal_BN2b64(BIGNUM * bn)
{
	int bytes = BN_num_bytes(bn);
	unsigned char * binbuf = (unsigned char *) jal_calloc(1, bytes + 1);

	bytes = BN_bn2bin(bn, binbuf);

	int bufLen = bytes * 4;
	int len = bufLen;
	unsigned char * buf = (unsigned char *) jal_calloc(1, bufLen);

	XSCryptCryptoBase64 b64;

	b64.encodeInit();
	bufLen = b64.encode(binbuf, bytes, buf, bufLen);
	bufLen += b64.encodeFinish(&buf[bufLen], len-bufLen);
	buf[bufLen] = '\0';

	XMLCh *b64xmlbuf = XMLString::transcode((char *) buf);

	free(binbuf);
	free(buf);

	return b64xmlbuf;
}
