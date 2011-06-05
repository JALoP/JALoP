#include <stdlib.h>
#include <stdio.h>
#include <test-dept.h>
#include <jalop/jalp_journal_metadata.h>

void test_jalp_transform_append_return_new_transform_when_prev_is_null()
{
	struct jalp_transform *transform;
	transform = jalp_transform_append(NULL, "uri", "snippet");

	assert_not_equals(NULL, transform);
	assert_string_equals("uri", transform->uri);
	assert_string_equals("snippet", transform->xml);
	assert_equals((struct jalp_transform *)NULL, transform->next);

	jalp_transform_destroy(&transform);
}

void test_jalp_transform_append_returns_null_when_uri_is_null()
{
	assert_equals((struct jalp_transform *)NULL, jalp_transform_append(NULL, NULL, "value"));
}

void test_jalp_transform_append_return_new_transform_when_xml_snippet_is_null()
{
	struct jalp_transform *transform;
	transform = jalp_transform_append(NULL, "uri", NULL);
	assert_not_equals(NULL, transform);

	jalp_transform_destroy(&transform);
}

void test_jalp_transform_append_return_list_when_prev_is_not_null()
{
	struct jalp_transform *prev_transform;
	prev_transform = jalp_transform_append(NULL, "uri", "snippet");
	struct jalp_transform *transform;
	transform = jalp_transform_append(prev_transform, "uri2", "snippet2");
	assert_not_equals(NULL, prev_transform);
	assert_not_equals(NULL, transform);
	assert_string_equals("uri2", transform->uri);
	assert_string_equals("snippet2", transform->xml);
	assert_string_equals("uri2", prev_transform->next->uri);
	assert_string_equals("snippet2", prev_transform->next->xml);
	assert_equals((struct jalp_transform *)NULL, transform->next);

	jalp_transform_destroy(&prev_transform);
}

void test_jalp_transform_append_return_list_with_transform_inserted_center()
{
	struct jalp_transform *frst_transform;
	struct jalp_transform *scnd_transform;
	struct jalp_transform *new_scnd;

	frst_transform = jalp_transform_append(NULL, "uri", "snippet");
	scnd_transform = jalp_transform_append(frst_transform, "uri2", "snippet2");
	new_scnd = jalp_transform_append(frst_transform, "uri1", "snippet1");

	assert_not_equals(NULL, frst_transform);
	assert_not_equals(NULL, scnd_transform);
	assert_not_equals(NULL, new_scnd);
	assert_string_equals("uri", frst_transform->uri);
	assert_string_equals("snippet", frst_transform->xml);
	assert_string_equals("uri1", new_scnd->uri);
	assert_string_equals("snippet1", new_scnd->xml);
	assert_string_equals("uri2", scnd_transform->uri);
	assert_string_equals("snippet2", scnd_transform->xml);
	assert_string_equals("uri1", frst_transform->next->uri);
	assert_string_equals("snippet1", frst_transform->next->xml);
	assert_equals(frst_transform->next, new_scnd);
	assert_string_equals("uri2", new_scnd->next->uri);
	assert_string_equals("snippet2", new_scnd->next->xml);
	assert_equals(new_scnd->next, scnd_transform);

	jalp_transform_destroy(&frst_transform);
}

void test_jalp_transform_destroy_transform_list_is_null()
{
	struct jalp_transform *null_transform = NULL;
	jalp_transform_destroy(&null_transform);
}

void test_jalp_transform_destroy_destroys_single_node_transform_list()
{
	struct jalp_transform *transform;
	transform = jalp_transform_append(NULL, "uri", "snippet");

	jalp_transform_destroy(&transform);
	assert_equals((struct jalp_transform *)NULL, transform);
}

void test_jalp_transform_destroy_destroys_multinode_transform_list()
{
	struct jalp_transform *frst_transform;
	struct jalp_transform *scnd_transform;
	struct jalp_transform *thrd_transform;
	frst_transform = jalp_transform_append(NULL, "uri", "snippet");
	scnd_transform = jalp_transform_append(frst_transform, "uri2", "snippet2");
	thrd_transform = jalp_transform_append(scnd_transform, "uri3", "snippet3");

	jalp_transform_destroy(&frst_transform);
	assert_equals((struct jalp_transform *)NULL, frst_transform);
}

