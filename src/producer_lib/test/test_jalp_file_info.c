#include <test-dept.h>
#include <jalop/jalp_journal_metadata.h>
#include "jal_alloc.h"


void test_jalp_file_info_create_initializes_new_jalp_file_info()
{
	struct jalp_file_info *new_file_info;
	new_file_info = jalp_file_info_create();
	assert_not_equals((struct jalp_file_info *)NULL, new_file_info);
	assert_equals(0, new_file_info->original_size);
	assert_equals((char *)NULL, new_file_info->filename);
	assert_equals(JAL_THREAT_UNKNOWN, new_file_info->threat_level);
	assert_equals((struct jalp_content_type *)NULL, new_file_info->content_type);
}

void test_jalp_file_info_destroy_null()
{
	struct jalp_file_info *inval = NULL;
	jalp_file_info_destroy(NULL);
	jalp_file_info_destroy(&inval);
	assert_equals((struct jalp_file_info *)NULL, inval);
}

void test_jalp_file_info_destroy_null_fields()
{
	struct jalp_file_info *new_file_info;
	new_file_info = jalp_file_info_create();
	jalp_file_info_destroy(&new_file_info);
	assert_equals((struct jalp_file_info *)NULL, new_file_info);
}

void test_jalp_file_info_destroy_initialized_fields()
{
	struct jalp_file_info *new_file_info;
	new_file_info = jalp_file_info_create();

	new_file_info->content_type = jalp_content_type_create();
	new_file_info->filename = jal_strdup("name");

	jalp_file_info_destroy(&new_file_info);
	assert_equals((struct jalp_file_info *)NULL, new_file_info);
}
