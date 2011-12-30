/**
* @file test_jsub_parse.cpp This file contains functions to test
* jsub_parse.cpp.
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
// C++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif

extern "C" {
#include <test-dept.h>
}

#include <string.h>
#include "jsub_parse.hpp"
#include "jal_alloc.h"

extern "C" void setup()
{
}

extern "C" void teardown()
{
}

extern "C" void test_jsub_parse_get_schema_path_works()
{
	char *dest1 = NULL;
	char *dest2 = NULL;
	char *dest3 = NULL;
	char *root1 = jal_strdup("my/root/dir");
	char *root2 = jal_strdup("my/root/dir/");
	char *root3 = jal_strdup("a");
	char *schema = jal_strdup("schema");

	jsub_get_schema_path(&dest1, root1, schema);
	assert(0 == strcmp(dest1, "my/root/dir/schema"));

	jsub_get_schema_path(&dest2, root2, schema);
	assert(0 == strcmp(dest2, "my/root/dir/schema"));

	jsub_get_schema_path(&dest3, root3, schema);
	assert(0 == strcmp(dest3, "a/schema"));

	free(dest1);
	free(dest2);
	free(dest3);
	free(root1);
	free(root2);
	free(root3);
	free(schema);
}
