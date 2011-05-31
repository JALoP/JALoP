#include <test-dept.h>
#include <stdlib.h>
#include <jalop/jalp_logger_metadata.h>
#include "jalp_alloc.h"

void test_jalp_log_severity_create_returns_struct_with_zeroed_fields()
{
	struct jalp_log_severity *ptr = jalp_log_severity_create();
	assert_not_equals(NULL, ptr);
	assert_equals(0, ptr->level_val);
	assert_equals((char *) NULL, ptr->level_str);
	jalp_log_severity_destroy(&ptr);
}

void test_jalp_log_severity_destroy_frees_struct()
{
	// test to make sure the test doesn't crash
	jalp_log_severity_destroy(NULL);
	struct jalp_log_severity *ptr = NULL;
	jalp_log_severity_destroy(&ptr);

	ptr = jalp_log_severity_create();
	jalp_log_severity_destroy(&ptr);
	assert_equals((struct jalp_log_severity *) NULL, ptr);

	ptr = jalp_log_severity_create();
	ptr->level_val = 100;
	ptr->level_str = jalp_calloc(5, sizeof(char));
	jalp_log_severity_destroy(&ptr);
	assert_equals((struct jalp_log_severity *) NULL, ptr);
}


