#include <test-dept.h>
#include <jalop/jalp_syslog_metadata.h>
#include "jal_alloc.h"

void test_jalp_syslog_metadata_create_returns_struct_with_zeroed_fields()
{
	struct jalp_syslog_metadata *ptr = jalp_syslog_metadata_create();
	assert_not_equals(NULL, ptr);
	assert_equals((void*) NULL, ptr->timestamp);
	assert_equals((void*) NULL, ptr->message_id);
	assert_equals((void*) NULL, ptr->sd_head);
	assert_equals(-1, ptr->facility);
	assert_equals(-1, ptr->severity);
	jalp_syslog_metadata_destroy(&ptr);
}

void test_jalp_syslog_metadata_destroy_with_null_does_not_crash()
{
	// test to make sure the test doesn't crash
	jalp_syslog_metadata_destroy(NULL);
	struct jalp_syslog_metadata *ptr = NULL;
	jalp_syslog_metadata_destroy(&ptr);

	ptr = jalp_syslog_metadata_create();
	jalp_syslog_metadata_destroy(&ptr);
	assert_equals((struct jalp_syslog_metadata *) NULL, ptr);

}
void test_jalp_syslog_metadata_destroy_frees_struct()
{
	// run under valgrind to check
	struct jalp_syslog_metadata *ptr = jalp_syslog_metadata_create();
	ptr->timestamp = jal_strdup("12:00:23.123");
	ptr->message_id = jal_strdup("foo");
	ptr->sd_head = jalp_structured_data_append(NULL, "some_sd_id");
	jalp_syslog_metadata_destroy(&ptr);
	assert_equals((struct jalp_syslog_metadata *) NULL, ptr);
}
