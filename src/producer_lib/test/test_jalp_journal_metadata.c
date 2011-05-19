#include <stdlib.h>
#include <stdio.h>
#include <test-dept.h>

#include <jalop/jalp_journal_metadata.h>

void setup()
{
	// nothing to do
}
void teardown()
{
	// nothing to do
}
void test_jalp_journal_metadata_create_initializes_new_object_to_all_zeros()
{
	struct jalp_journal_metadata *jm = jalp_journal_metadata_create();
	assert_not_equals((void*)NULL, jm);
	assert_pointer_equals((void*)NULL, jm->file_info);
	assert_pointer_equals((void*)NULL, jm->transforms);
	jalp_journal_metadata_destroy(&jm);
}
void test_jalp_journal_metadata_destroy_works_with_null_input()
{
	jalp_journal_metadata_destroy(NULL);
}
void test_jalp_journal_metadata_destroy_works_with_pointer_to_null()
{
	struct jalp_journal_metadata *jm = NULL;
	jalp_journal_metadata_destroy(&jm);
	assert_pointer_equals((void*)NULL, jm);
}
void test_jalp_journal_metadata_destroy_sets_pointer_to_null()
{
	struct jalp_journal_metadata *jm = jalp_journal_metadata_create();
	jalp_journal_metadata_destroy(&jm);
	assert_pointer_equals((void*)NULL, jm);
}
