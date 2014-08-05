/**
 * @file test_jal_alloc.c This file contains tests for jal_alloc functions.
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
#include <errno.h>

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

/* ----------------- */
/* jal_strndup tests */
/* ----------------- */
void test_jal_strndup_success_full()
{
	/* Create a string with the full character set - less \0 */
	int i=0;
	char source[256];
	for (i = 0; i < 255; i++) {
		source[i] = i+1; 
	}
	source[i] = '\0';

	char *ptr = jal_strndup(source, 256);

	/* Check for no errors */ 
	assert_not_equals(NULL, ptr);
	assert_not_equals(ENOMEM, errno);

	/* Check for content and length */
	assert_equals(0, strcmp(ptr, source));
	assert_equals(255, strlen(ptr));

	free(ptr);
}

void test_jal_strndup_success_buffer_bigger()
{
	char *source = "Howdy";
	char *ptr = jal_strndup(source, 6);

	/* Check for no errors */ 
	assert_not_equals(NULL, ptr);
	assert_not_equals(ENOMEM, errno);

	/* Check for content and length */
	assert_equals(0, strcmp(ptr, source));
	assert_equals(5, strlen(ptr));

	free(ptr);
}

void test_jal_strndup_success_buffer_exact()
{
	char *source = "Howdy";
	char *ptr = jal_strndup(source, 5); 

	/* Check for no errors */ 
	assert_not_equals(NULL, ptr);
	assert_not_equals(ENOMEM, errno);

	/* Check for content and length */
	assert_equals(0, strcmp(ptr, source));
	assert_equals(5, strlen(ptr));

	free(ptr);
}

void test_jal_strndup_success_buffer_short()
{
	char *source = "Howdy";
	char *ptr = jal_strndup(source, 4); 

	/* Check for no errors */ 
	assert_not_equals(NULL, ptr);
	assert_not_equals(ENOMEM, errno);

	/* Check for content and length */
	assert_equals(0, strcmp(ptr, "Howd"));
	assert_equals(4, strlen(ptr));

	free(ptr);
}

void test_jal_strndup_source_null()
{
	char *ptr = jal_strndup(NULL, 100);
	/* Cast of NULL below required for Solaris */
	assert_equals((char *)NULL, ptr);
}

void test_jal_strndup_size_zero()
{
	char *ptr = jal_strndup("Test string....", 0);
	/* Cast of NULL below required for Solaris */
	assert_equals((char *)NULL, ptr);
}

/* ---------------- */
/* jal_memdup tests */
/* ---------------- */
void test_jal_memdup_success_full()
{
	/* Create a string with the full character set, including \0 */
	int i=0;
	char source[256];
	for (i = 0; i <= 255; i++) {
		source[i] = i; 
	}

	char *ptr = jal_memdup(source, 256);

	/* Check for no errors */ 
	assert_not_equals(NULL, ptr);
	assert_not_equals(ENOMEM, errno);

	/* Check for content and length */
	assert_equals(0, memcmp(ptr, source, 256));

	free(ptr);
}

/* Can't test the buffer bigger than source as we expect the calling function to pass the length to us. */

void test_jal_memdup_success_buffer_exact()
{
	char *source = "Howdy";
	char *ptr = jal_memdup(source, 5); 

	/* Check for no errors */ 
	assert_not_equals(NULL, ptr);
	assert_not_equals(ENOMEM, errno);

	/* Check for content and length */
	assert_equals(0, memcmp(ptr, source, 5));

	free(ptr);
}

void test_jal_memdup_success_buffer_short()
{
	char *source = "Howdy";
	char *ptr = jal_memdup(source, 4); 

	/* Check for no errors */ 
	assert_not_equals(NULL, ptr);
	assert_not_equals(ENOMEM, errno);

	/* Check for content and length */
	assert_equals(0, memcmp(ptr, source, 4));

	free(ptr);
}

void test_jal_memdup_source_null()
{
	char *ptr = jal_memdup(NULL, 100);
	/* Cast of NULL below required for Solaris */
	assert_equals((char *)NULL, ptr);
}

void test_jal_memdup_size_zero()
{
	char *ptr = jal_memdup("Test string....", 0);
	/* Cast of NULL below required for Solaris */
	assert_equals((char *)NULL, ptr);
}
