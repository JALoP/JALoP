#include <test-dept.h>
#include <jalop/jalp_context.h>
#include "jalp_context_internal.h"

void test_jalp_context_create_returns_struct_with_zeroed_fields()
{
	struct jalp_context_t *ptr = jalp_context_create();
	assert_not_equals(NULL, ptr);

	assert_equals(-1, ptr->socket);
	assert_equals((char *) NULL, ptr->path);
	assert_equals((char *) NULL, ptr->hostname);
	assert_equals((char *) NULL, ptr->app_name);
	jalp_context_destroy(&ptr);
}

