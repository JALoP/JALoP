#include <stdlib.h>
#include <test-dept.h>
#include <stdio.h>
#include <jalop/jalp_app_metadata.h>
#include <jalop/jalp_syslog_metadata.h>
#include <jalop/jalp_logger_metadata.h>
#include "jal_alloc.h"

void test_jalp_app_metadata_create_returns_a_non_null_pointer_to_a_struct_with_zeroed_fields()
{	struct jalp_app_metadata *ptr = jalp_app_metadata_create();
	assert_not_equals(NULL, ptr);
	assert_equals(JALP_METADATA_NONE, ptr->type);
	assert_equals((char *) NULL, ptr->event_id);
	assert_equals((char *) NULL, ptr->custom);
	assert_equals((struct jalp_journal_metadata *) NULL, ptr->file_metadata);
	jalp_app_metadata_destroy(&ptr);
}

void test_jalp_app_metadata_destroy_does_nothing_on_null_calls()
{
	// make sure this doesn't crash
	jalp_app_metadata_destroy(NULL);
	struct jalp_app_metadata *ptr = NULL;
	jalp_app_metadata_destroy(&ptr);
}

void test_jalp_app_metadata_sets_pointer_to_null()
{
	struct jalp_app_metadata *ptr = jalp_app_metadata_create();
	assert_not_equals(NULL, ptr);
	jalp_app_metadata_destroy(&ptr);
	assert_equals((struct jalp_app_metadata *) NULL, ptr);
}


void test_jalp_app_metadata_destroy_does_not_leak_syslog_metadata()
{
	//run through valgrind and check for leaks
	struct jalp_app_metadata *ptr = jalp_app_metadata_create();
	assert_not_equals(NULL, ptr);
	ptr->type = JALP_METADATA_SYSLOG;
	ptr->sys = jalp_syslog_metadata_create();
	jalp_app_metadata_destroy(&ptr);
}



void test_jalp_app_metadata_destroy_does_not_leak_app_metadata()
{
	//run through valgrind and check for leaks
	struct jalp_app_metadata *ptr = jalp_app_metadata_create();
	assert_not_equals(NULL, ptr);
	ptr->type = JALP_METADATA_LOGGER;
	ptr->log = jalp_logger_metadata_create();
	jalp_app_metadata_destroy(&ptr);
}

void test_jalp_app_metadata_destroy_does_not_leak_custom()
{
	//run through valgrind and check for leaks
	struct jalp_app_metadata *ptr = jalp_app_metadata_create();
	assert_not_equals(NULL, ptr);
	ptr->type = JALP_METADATA_CUSTOM;
	ptr->custom = jal_malloc(4);
	jalp_app_metadata_destroy(&ptr);
}
