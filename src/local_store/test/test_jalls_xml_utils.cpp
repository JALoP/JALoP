/**
 * @file test_jalls_xml_utils.cpp This file contains functions to test the
 * jalls xml utils functions..
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

// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// c++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
extern "C" {
#include <test-dept.h>
}

#include <xercesc/dom/DOM.hpp>
#include <xercesc/framework/MemBufInputSource.hpp>
#include <xercesc/framework/Wrapper4InputSource.hpp>
#include <stdio.h>
#include <openssl/pem.h>
#include "jalls_xml_utils.hpp"
#include "jalls_handler.h"

XERCES_CPP_NAMESPACE_USE

#define BAD_BUFFER "<qwerty/>"

DOMDocument *doc = NULL;
uint8_t *buffer = NULL;
long buff_len = 0;

extern "C" void setup()
{
	XMLPlatformUtils::Initialize();
}

extern "C" void teardown()
{
	delete doc;
	free(buffer);
	XMLPlatformUtils::Terminate();
}

extern "C" void test_jalls_parse_audit_returns_success_given_good_input()
{
	int ret = 0;
	FILE *f = NULL;

	f = fopen(TEST_INPUT_ROOT "good_input.xml", "rb");
	assert_not_equals(NULL, f);

	ret = fseek(f, 0, SEEK_END);
	assert_equals(0, ret);

	buff_len = ftell(f);
	assert_true(buff_len > 0);

	ret = fseek(f, 0, SEEK_SET);
	assert_equals(0, ret);

	buffer = (uint8_t *)malloc(buff_len);
	assert_not_equals(NULL, buffer);

	ret = fread(buffer, buff_len, 1, f);
	assert_not_equals(ret, 0);

	fclose(f);

	ret = jalls_parse_audit(buffer, (size_t)buff_len, (char *)SCHEMAS_ROOT, &doc, 0);
	assert_equals(0, ret);
	assert_not_equals(NULL, doc);
}

extern "C" void test_jalls_parse_audit_returns_failure_given_bad_input()
{
	int ret = jalls_parse_audit((uint8_t *)BAD_BUFFER, strlen(BAD_BUFFER), (char *)SCHEMAS_ROOT, &doc, 0);
	assert_equals(-1, ret);
	assert_pointer_equals((void *)NULL, doc);
}
