/**
 * @file jal_byteswap.h This file contains macros for performing byteswaps.
 * When possible, the macros use existing library functions/macros.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
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

#ifndef __JAL_BYTESWAP_H_
#define __JAL_BYTESWAP_H_

#ifdef HAVE_BYTESWAP_H
#include <byteswap.h>
#define jal_bswap_16(x) bswap_16(x)
#define jal_bswap_32(x) bswap_32(x)
#define jal_bswap_64(x) bswap_64(x)
#else
#define jal_bswap_16(x) __jal_bswap_16(x)
#define jal_bswap_32(x) __jal_bswap_32(x)
#define jal_bswap_64(x) __jal_bswap_64(x)
#endif


#define __jal_bswap_16(x) \
	((((x >> 8 ) & 0xFF) << 0) | \
	 (((x >> 0 ) & 0xFF) << 8) )

#define __jal_bswap_32(x) \
	((((x >> 0 ) & 0xFF) << 24) | \
	 (((x >> 8 ) & 0xFF) << 16) | \
	 (((x >> 16) & 0xFF) << 8 ) | \
	 (((x >> 24) & 0xFF) << 0 ))

#define __jal_bswap_64(x) \
	((((x >> 0 ) & 0xFF) << 56) | \
	 (((x >> 8 ) & 0xFF) << 48) | \
	 (((x >> 16) & 0xFF) << 40) | \
	 (((x >> 24) & 0xFF) << 32) | \
	 (((x >> 32) & 0xFF) << 24) | \
	 (((x >> 40) & 0xFF) << 16) | \
	 (((x >> 48) & 0xFF) << 8 ) | \
	 (((x >> 56) & 0xFF) << 0 ))

#endif // __JAL_BYTESWAP_H_
