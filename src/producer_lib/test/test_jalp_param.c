#include <stdlib.h>
#include <stdio.h>
#include <test-dept.h>
#include <jalop/jalp_structured_data.h>
#include "jalp_alloc.h"

void test_jalp_param_insert_returns_null_when_name_is_null()
{
	struct jalp_param *param = NULL;
	assert_equals(NULL, jalp_param_insert(param, NULL, "value"));
}

void test_jalp_param_insert_returns_null_when_value_is_null()
{
	struct jalp_param *param = NULL;
	assert_equals(NULL, jalp_param_insert(param, "name", NULL));
}

void test_jalp_param_insert_return_new_param_when_param_is_null()
{
	struct jalp_param *param = NULL;
	param = jalp_param_insert(param, "name", "value");
	assert_not_equals(NULL, param);
	assert_string_equals("name", param->key);
	assert_string_equals("value", param->value);
}

void test_jalp_param_insert_return_list_when_param_is_not_null()
{
	struct jalp_param *next_param = NULL;
	struct jalp_param *param = jalp_malloc(sizeof(*param));
	param->key = jalp_strdup("name");
	param->value = jalp_strdup("value");
	param->next = NULL;
	next_param = jalp_param_insert(param, "name2", "value2");
	assert_not_equals(NULL, param);
	assert_not_equals(NULL, next_param);
	assert_string_equals("name2", next_param->key);
	assert_string_equals("value2", next_param->value);
	assert_string_equals("name2", param->next->key);
	assert_string_equals("value2", param->next->value);
}

void test_jalp_param_insert_return_list_with_param_inserted_center()
{
	struct jalp_param *frst_param = jalp_malloc(sizeof(*frst_param));
	struct jalp_param *scnd_param = jalp_malloc(sizeof(*scnd_param));
	struct jalp_param *new_scnd = NULL;
	frst_param->key = jalp_strdup("name");
	frst_param->value = jalp_strdup("value");
	frst_param->next = scnd_param;
	scnd_param->key = "name2";
	scnd_param->value = "value2";
	new_scnd = jalp_param_insert(frst_param, "name1", "value1");
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
}

void test_jalp_param_destroy_destroys_single_node_param_list()
{
	struct jalp_param *param = jalp_malloc(sizeof(*param));
	param->key = jalp_strdup("name");
	param->value = jalp_strdup("value");
	param->next = NULL;
	jalp_param_destroy(&param);
	assert_equals(NULL, param);
}
void test_jalp_param_destroy_destroys_multinode_param_list()
{
	struct jalp_param *frst_param = jalp_malloc(sizeof(*frst_param));
	struct jalp_param *scnd_param = jalp_malloc(sizeof(*scnd_param));
	struct jalp_param *thrd_param = jalp_malloc(sizeof(*thrd_param));
	frst_param->key = jalp_strdup("name");
	frst_param->value = jalp_strdup("value");
	frst_param->next = scnd_param;
	scnd_param->key = jalp_strdup("name2");
	scnd_param->value = jalp_strdup("value2");
	scnd_param->next = thrd_param;
	thrd_param->key = jalp_strdup("name3");
	thrd_param->value = jalp_strdup("value3");
	thrd_param->next = NULL;
	jalp_param_destroy(&frst_param);
	assert_equals(NULL, frst_param);
}

void test_jalp_param_destroy_destroys_only_given_param_and_after()
{
	struct jalp_param *frst_param = jalp_malloc(sizeof(*frst_param));
	struct jalp_param *scnd_param = jalp_malloc(sizeof(*scnd_param));
	struct jalp_param *thrd_param = jalp_malloc(sizeof(*thrd_param));
	frst_param->key = jalp_strdup("name");
	frst_param->value = jalp_strdup("value");
	frst_param->next = scnd_param;
	scnd_param->key = jalp_strdup("name2");
	scnd_param->value = jalp_strdup("value2");
	scnd_param->next = thrd_param;
	thrd_param->key = jalp_strdup("name3");
	thrd_param->value = jalp_strdup("value3");
	jalp_param_destroy(&scnd_param);
	assert_not_equals(NULL, frst_param);
	assert_equals(NULL, scnd_param);
}

void test_jalp_param_destroy_param_list_is_null()
{
	struct jalp_param *null_param = NULL;

	jalp_param_destroy(&null_param);
}

