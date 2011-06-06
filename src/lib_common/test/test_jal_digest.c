#include <test-dept.h>
#include <jalop/jal_digest.h>
#include "jal_alloc.h"

void test_jal_digest_ctx_create_returns_struct_with_zeroed_fields()
{
	struct jal_digest_ctx *ptr = jal_digest_ctx_create();
	assert_not_equals(NULL, ptr);
	assert_equals(0, ptr->len);
	assert_equals((void*)NULL, ptr->create);
	assert_equals((void*)NULL, ptr->init);
	assert_equals((void*)NULL, ptr->update);
	assert_equals((void*)NULL, ptr->final);
	assert_equals((void*)NULL, ptr->destroy);
	jal_digest_ctx_destroy(&ptr);
}

void test_jal_digest_destroy_does_not_crash_on_null()
{
	jal_digest_ctx_destroy(NULL);
	struct jal_digest_ctx *ptr = NULL;
	jal_digest_ctx_destroy(&ptr);
}
void test_jal_digest_destroy_frees_struct()
{
	// run under valgrind to check for leaks
	struct jal_digest_ctx *ptr = jal_digest_ctx_create();
	assert_not_equals(NULL, ptr);
	jal_digest_ctx_destroy(&ptr);
	assert_equals((struct jal_digest_ctx *) NULL, ptr);
}

