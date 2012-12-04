/**
 * @file test_jal_byteswap.c This file contains tests for byte swap functions
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

#include <test-dept.h>
#include <stdint.h>

#include "jal_byteswap.h"

#define b0 0xF0  // bit pattern 11110000
#define b1 0x0F  // bit pattern 00001111
#define b2 0xAA  // bit pattern 10101010
#define b3 0x55  // bit pattern 01010101
#define b4 0xCC  // bit pattern 11001100
#define b5 0xCC  // bit pattern 11001100
#define b6 0x33  // bit pattern 00110011
#define b7 0xFF  // bit pattern 11111111
#define b8 0x00  // bit pattern 00000000
#define BYTE_PATTERNS 9

static const uint8_t bytes[BYTE_PATTERNS] = { b0, b1, b2, b3, b4, b5, b6, b7, b8 };

void test_bs16() {
	uint8_t byte0;
	uint8_t byte1;
	for(byte0 = 0; byte0 < BYTE_PATTERNS; byte0++) {
	for(byte1 = 0; byte1 < BYTE_PATTERNS; byte1++) {
		uint16_t orig = bytes[byte0] << 8 | bytes[byte1];
		uint16_t exp = bytes[byte1] << 8 | bytes[byte0];
		assert_equals(exp, __jal_bswap_16(orig));
	}
	}
}

void test_bs32() {
	uint8_t byte0;
	uint8_t byte1;
	uint8_t byte2;
	uint8_t byte3;

	for(byte0 = 0; byte0 < BYTE_PATTERNS; byte0++) {
	for(byte1 = 0; byte1 < BYTE_PATTERNS; byte1++) {
	for(byte2 = 0; byte2 < BYTE_PATTERNS; byte2++) {
	for(byte3 = 0; byte3 < BYTE_PATTERNS; byte3++) {
		uint32_t orig = (uint32_t) bytes[byte0] << 24 | (uint32_t) bytes[byte1] << 16 |
				(uint32_t) bytes[byte2] << 8  | (uint32_t) bytes[byte3];

		uint32_t exp =  (uint32_t) bytes[byte3] << 24 | (uint32_t) bytes[byte2] << 16 |
				(uint32_t) bytes[byte1] << 8  | (uint32_t) bytes[byte0];
		assert_equals(exp, __jal_bswap_32(orig));
	}
	}
	}
	}
}

void test_bs64() {
	uint8_t byte0;
	uint8_t byte1;
	uint8_t byte2;
	uint8_t byte3;
	uint8_t byte4;
	uint8_t byte5;

	for(byte0 = 0; byte0 < BYTE_PATTERNS; byte0++) {
	for(byte1 = 0; byte1 < BYTE_PATTERNS; byte1++) {
	for(byte2 = 0; byte2 < BYTE_PATTERNS; byte2++) {
	for(byte3 = 0; byte3 < BYTE_PATTERNS; byte3++) {
	for(byte4 = 0; byte4 < BYTE_PATTERNS; byte4++) {
	for(byte5 = 0; byte5 < BYTE_PATTERNS; byte5++) {
		uint64_t orig = (uint64_t) bytes[byte0] << 56 | (uint64_t) bytes[byte1] << 48 |
				(uint64_t) bytes[byte2] << 40 | (uint64_t) bytes[byte3] << 32 |
				(uint64_t) bytes[byte4] << 24 | (uint64_t) bytes[byte5] << 16 |
				(uint64_t) bytes[byte0] << 8 | (uint64_t) bytes[byte1];

		uint64_t exp =  (uint64_t) bytes[byte1] << 56 | (uint64_t) bytes[byte0] << 48 |
				(uint64_t) bytes[byte5] << 40 | (uint64_t) bytes[byte4] << 32 |
				(uint64_t) bytes[byte3] << 24 | (uint64_t) bytes[byte2] << 16 |
				(uint64_t) bytes[byte1] << 8 | (uint64_t) bytes[byte0];
		
		assert_equals(exp, __jal_bswap_64(orig));
	}
	}
	}
	}
	}
	}
}

