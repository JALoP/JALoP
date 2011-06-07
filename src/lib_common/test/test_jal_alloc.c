#include <stdlib.h>
#include <stdio.h>
#include <test-dept.h>

#include "jal_alloc.h"
#include "jal_error_callback_internal.h"

static int error_handler_called = 0;

void *malloc_always_fails(__attribute__((unused))size_t size)
{
	return NULL;
}
void *calloc_always_fails(__attribute__((unused))size_t nmemb, __attribute__((unused))size_t size)
{
	return NULL;
}
void *realloc_always_fails(__attribute__((unused))void *ptr, __attribute__((unused))size_t size)
{
	return NULL;
}
void mocked_error_handler(__attribute__((unused))int err)
{
	error_handler_called = 1;
}
void setup()
{
	error_handler_called = 0;
}
void teardown()
{
	restore_function(&malloc);
	restore_function(&calloc);
	restore_function(&realloc);
	restore_function(&jal_error_handler);
}
void test_jal_malloc_calls_error_handler_on_malloc_failure()
{
	assert_equals(0, error_handler_called);
	replace_function(&malloc, &malloc_always_fails);
	replace_function(&jal_error_handler, &mocked_error_handler);
	jal_malloc(1);
	assert_equals(1, error_handler_called);
}

void test_jal_malloc_success_for_zero_allocation()
{
	void *ptr = jal_malloc(0);
	assert_not_equals(NULL, ptr);
	free(ptr);
}
void test_jal_malloc_success_for_non_zero_allocation()
{
	void *ptr = jal_malloc(sizeof(int));
	assert_not_equals(NULL, ptr);
	free(ptr);
}

void test_jal_calloc_calls_error_handler_on_calloc_failure()
{
	assert_equals(0, error_handler_called);
	replace_function(&calloc, &calloc_always_fails);
	replace_function(&jal_error_handler, &mocked_error_handler);

	jal_calloc(1, sizeof(int));
	assert_equals(1, error_handler_called);
}
void test_jal_calloc_success_for_zero_elements_zero_size_allocation()
{
	void *ptr = jal_calloc(0, 0);
	assert_not_equals(NULL, ptr);
	free(ptr);
}

void test_jal_calloc_success_for_zero_elements_non_zero_size_allocation()
{
	void *ptr = jal_calloc(0, sizeof(int));
	assert_not_equals(NULL, ptr);
	free(ptr);
}

void test_jal_calloc_success_for_non_zero_elements_zero_size_allocation()
{
	void *ptr = jal_calloc(1, 0);
	assert_not_equals(NULL, ptr);
	free(ptr);
}

void test_jal_calloc_success_for_non_zero_elements_non_zero_size_allocation() 
{
	void *ptr = jal_calloc(1, sizeof(int));
	assert_not_equals(NULL, ptr);
	free(ptr);
}

void test_jal_realloc_calls_error_handler_on_realloc_failure()
{
	assert_equals(0, error_handler_called);
	replace_function(&realloc, &realloc_always_fails);
	replace_function(&jal_error_handler, &mocked_error_handler);
	void *ptr = malloc(10);
	assert_not_equals(NULL, ptr);
	jal_realloc(ptr, 20);
	assert_equals(1, error_handler_called);
	free(ptr);
}

void test_jal_realloc_success_null_pointer_zero_size()
{
	// for realloc(NULL, 0), realloc should act like malloc(0), which should always return a valid pointer
	void *ptr = jal_realloc(NULL, 0);
	assert_not_equals(NULL, ptr);
	free(ptr);
}
void test_jal_realloc_returns_null_with_non_null_pointer_and_zero_size()
{
	// for realloc(ptr, 0), where ptr is a valid, non-null, pointer, realloc 
	// should act like free, and return NULL.
	void *ptr = malloc(10);
	assert_not_equals(NULL, ptr);

	ptr = jal_realloc(ptr, 0);
	assert_pointer_equals((void*)NULL, ptr);
	free(ptr);
}

void test_jal_realloc_success_null_pointer_non_zero_size()
{
	// for realloc(NULL, x), where x > 0, realloc should act like malloc(x)
	void *ptr = jal_realloc(NULL, 1);
	assert_not_equals(NULL, ptr);
	free(ptr);
}

void test_jal_realloc_success_with_non_null_pointer_and_non_zero_size()
{
	// for realloc(ptr, x), where ptr is a valid, non-null, pointer,  and
	// x is > 0, realloc should should return a valid pointer
	void *ptr = malloc(10);
	assert_not_equals(NULL, ptr);

	ptr = jal_realloc(ptr, 20);
	assert_not_equals(NULL, ptr);
	free(ptr);
}

void test_jal_strdup_return_null_if_passed_null()
{
	assert_equals((char *) NULL, jal_strdup(NULL));
}

void test_jal_strdup_success()
{
	char *string = jal_strdup("test");
	assert_not_equals((char *) NULL, string);
	free(string);
}
