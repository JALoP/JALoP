/**
 * @file test_jalp_param.c This file contains tests for jalp_param functions.
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

#include <stdlib.h>
#include <stdio.h>
#include <test-dept.h>
#include <jalop/jalp_structured_data.h>
#include "jal_alloc.h"

void test_jalp_param_append_returns_null_when_name_is_null()
{
	struct jalp_param *param = NULL;
	assert_equals((void*)NULL, jalp_param_append(param, NULL, "value"));
}

void test_jalp_param_append_returns_null_when_value_is_null()
{
	struct jalp_param *param = NULL;
	assert_equals((void*)NULL, jalp_param_append(param, "name", NULL));
}

void test_jalp_param_append_return_new_param_when_param_is_null()
{
	struct jalp_param *param = NULL;
	param = jalp_param_append(param, "name", "value");
	assert_not_equals(NULL, param);
	assert_string_equals("name", param->key);
	assert_string_equals("value", param->value);
	jalp_param_destroy(&param);
}

void test_jalp_param_append_return_list_when_param_is_not_null()
{
	struct jalp_param *next_param = NULL;
	struct jalp_param *param = jal_malloc(sizeof(*param));
	param->key = jal_strdup("name");
	param->value = jal_strdup("value");
	param->next = NULL;
	next_param = jalp_param_append(param, "name2", "value2");
	assert_not_equals(NULL, param);
	assert_not_equals(NULL, next_param);
	assert_string_equals("name2", next_param->key);
	assert_string_equals("value2", next_param->value);
	assert_string_equals("name2", param->next->key);
	assert_string_equals("value2", param->next->value);
	jalp_param_destroy(&param);
}

void test_jalp_param_append_return_list_with_param_inserted_center()
{
	struct jalp_param *frst_param = jal_malloc(sizeof(*frst_param));
	struct jalp_param *scnd_param = jal_malloc(sizeof(*scnd_param));
	struct jalp_param *new_scnd = NULL;
	frst_param->next = NULL;
	scnd_param->next = NULL;
	frst_param->key = jal_strdup("name");
	frst_param->value = jal_strdup("value");
	frst_param->next = scnd_param;
	scnd_param->key = jal_strdup("name2");
	scnd_param->value = jal_strdup("value2");
	new_scnd = jalp_param_append(frst_param, "name1", "value1");
	assert_not_equals(NULL, frst_param);
	assert_not_equals(NULL, scnd_param);
	assert_not_equals(NULL, new_scnd);
	assert_string_equals("name", frst_param->key);
	assert_string_equals("value", frst_param->value);
	assert_string_equals("name1", new_scnd->key);
	assert_string_equals("value1", new_scnd->value);
	assert_string_equals("name2", scnd_param->key);
	assert_string_equals("value2", scnd_param->value);
	assert_string_equals("name1", frst_param->next->key);
	assert_string_equals("value1", frst_param->next->value);
	assert_equals(frst_param->next, new_scnd);
	assert_string_equals("name2", new_scnd->next->key);
	assert_string_equals("value2", new_scnd->next->value);
	assert_equals(new_scnd->next, scnd_param);
	jalp_param_destroy(&frst_param);
}

void test_jalp_param_destroy_destroys_single_node_param_list()
{
	struct jalp_param *param = jal_malloc(sizeof(*param));
	param->key = jal_strdup("name");
	param->value = jal_strdup("value");
	param->next = NULL;
	jalp_param_destroy(&param);
	assert_equals((void*)NULL, param);
}

void test_jalp_param_destroy_destroys_multinode_param_list()
{
	struct jalp_param *frst_param = jal_malloc(sizeof(*frst_param));
	struct jalp_param *scnd_param = jal_malloc(sizeof(*scnd_param));
	struct jalp_param *thrd_param = jal_malloc(sizeof(*thrd_param));
	frst_param->key = jal_strdup("name");
	frst_param->value = jal_strdup("value");
	frst_param->next = scnd_param;
	scnd_param->key = jal_strdup("name2");
	scnd_param->value = jal_strdup("value2");
	scnd_param->next = thrd_param;
	thrd_param->key = jal_strdup("name3");
	thrd_param->value = jal_strdup("value3");
	thrd_param->next = NULL;
	jalp_param_destroy(&frst_param);
	assert_equals((void*)NULL, frst_param);
}

void test_jalp_param_destroy_param_list_is_null()
{
	struct jalp_param *null_param = NULL;

	jalp_param_destroy(&null_param);
}
