#include <test-dept.h>
#include <stdlib.h>
#include <jalop/jalp_journal_metadata.h>
#include <jalop/jalp_structured_data.h>
#include "jalp_alloc.h"

void test_jalp_content_type_create_returns_struct_with_zeroed_fields()
{
	struct jalp_content_type *ptr = jalp_content_type_create();
	assert_not_equals(NULL, ptr);
	assert_equals(JALP_MT_APPLICATION, ptr->media_type);
	assert_equals((char *) NULL, ptr->subtype);
	assert_equals((struct jalp_param *) NULL, ptr->params);
	jalp_content_type_destroy(&ptr);
}

void test_jalp_content_type_destroy_does_not_crash_on_null()
{
	// test to make sure the test doesn't crash
	jalp_content_type_destroy(NULL);
	struct jalp_content_type *ptr = NULL;
	jalp_content_type_destroy(&ptr);
}
void test_jalp_content_type_destroy_frees_struct()
{
	struct jalp_content_type *ptr = jalp_content_type_create();
	assert_not_equals(NULL, ptr);
	jalp_content_type_destroy(&ptr);
	assert_equals((struct jalp_content_type *) NULL, ptr);
}
void test_jalp_content_type_destroy_frees_members()
{
	// run under valgrind to check for leaks
	struct jalp_content_type *ptr = jalp_content_type_create();
	ptr->subtype = jalp_strdup("foobar");
	ptr->params = jalp_param_append(NULL, "key", "value");
	jalp_param_append(ptr->params, "key2", "value2");
	jalp_content_type_destroy(&ptr);
	assert_equals((struct jalp_content_type *) NULL, ptr);
}

