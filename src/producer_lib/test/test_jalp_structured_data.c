#include <test-dept.h>
#include <jalop/jalp_structured_data.h>
#include "jalp_alloc.h"

void test_jalp_structured_data_append_returns_null_when_sd_id_is_null()
{
	struct jalp_structured_data *ptr = jalp_structured_data_append(NULL, NULL);
	assert_equals((void *) NULL, ptr);

	struct jalp_structured_data *good_ptr = jalp_structured_data_append(NULL, "test");
	struct jalp_structured_data *bad_ptr = jalp_structured_data_append(good_ptr, NULL);
	assert_equals((void *) NULL, bad_ptr);

	jalp_structured_data_destroy(&good_ptr);
}

void test_jalp_structured_data_append_sets_sd_id_correctly()
{
	struct jalp_structured_data *ptr = jalp_structured_data_append(NULL, "string");
	assert_string_equals("string", ptr->sd_id);
	jalp_structured_data_destroy(&ptr);
}

void test_jalp_structured_data_append_create_in_correct_order()
{
	struct jalp_structured_data *first = jalp_structured_data_append(NULL, "first");
	assert_not_equals((void *) NULL, first);
	assert_equals((void *) NULL, first->next);

	struct jalp_structured_data *last = jalp_structured_data_append(first, "last");
	assert_not_equals((void *) NULL, last);
	assert_equals(first->next, last);
	assert_equals((void *) NULL, last->next);

	struct jalp_structured_data *middle = jalp_structured_data_append(first, "middle");
	assert_not_equals((void *) NULL, middle);
	assert_equals(first->next, middle);
	assert_equals(middle->next, last);
	assert_equals((void *) NULL, last->next);

	jalp_structured_data_destroy(&first);
}

void test_jalp_structured_data_append_sd_id_in_correct_order()
{
	struct jalp_structured_data *first = jalp_structured_data_append(NULL, "first");
	struct jalp_structured_data *last = jalp_structured_data_append(first, "last");
	struct jalp_structured_data *middle = jalp_structured_data_append(first, "middle");

	assert_string_equals(first->sd_id, "first");
	assert_string_equals(last->sd_id, "last");
	assert_string_equals(middle->sd_id, "middle");

	jalp_structured_data_destroy(&first);
}

void test_jalp_structured_data_destroy_do_not_crash_if_passed_NULL()
{
	jalp_structured_data_destroy(NULL);
	struct jalp_structured_data *ptr = NULL;
	jalp_structured_data_destroy(&ptr);
}

void test_jalp_structured_data_destroy_one()
{
	struct jalp_structured_data *first = jalp_structured_data_append(NULL, "first");
	jalp_structured_data_destroy(&first);
	assert_equals((void *) NULL, first);
}

void test_jalp_structured_data_destroy_list()
{
	struct jalp_structured_data *first = jalp_structured_data_append(NULL, "first");
	struct jalp_structured_data *second = jalp_structured_data_append(first, "second");
	struct jalp_structured_data *third __attribute__((unused)) =
		jalp_structured_data_append(second, "third");

	jalp_structured_data_destroy(&first);
	assert_equals((void *) NULL, first);
}

void test_jalp_structured_data_destroy_do_not_destroy_previous()
{
	struct jalp_structured_data *first = jalp_structured_data_append(NULL, "first");
	struct jalp_structured_data *second = jalp_structured_data_append(first, "second");

	jalp_structured_data_destroy(&second);
	assert_equals((void *) NULL, second);
	assert_not_equals((void *) NULL, first);

	first->next = NULL;
	jalp_structured_data_destroy(&first);
}


