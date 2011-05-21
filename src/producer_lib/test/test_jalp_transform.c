#include <stdlib.h>
#include <stdio.h>
#include <test-dept.h>
#include <jalop/jalp_journal_metadata.h>
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jalp_base64_internal.h"

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

void test_jalp_transform_append_deflate_appends_deflate()
{
	struct jalp_transform *deflate_transform;
	struct jalp_transform *deflate_transform2;
	deflate_transform = jalp_transform_append_deflate(NULL);

	deflate_transform2 = jalp_transform_append_deflate(deflate_transform);
	assert_not_equals(NULL, deflate_transform);
	assert_not_equals(NULL, deflate_transform2);
	assert_equals(deflate_transform->next, deflate_transform2);
	assert_equals((struct jalp_transform *)NULL, deflate_transform2->next);

	jalp_transform_destroy(&deflate_transform);
}

void test_jalp_transform_append_deflate_has_correct_fields()
{
	struct jalp_transform *deflate_transform;
	deflate_transform = jalp_transform_append_deflate(NULL);
	assert_string_equals("http://www.dod.mil/algorithms/compression#deflate", deflate_transform->uri);
	assert_equals((char *)NULL, deflate_transform->xml);
	jalp_transform_destroy(&deflate_transform);
}

void test_jalp_transform_append_aes_inval_key_size()
{
	struct jalp_transform *invalid_aes_transform;
	invalid_aes_transform = jalp_transform_append_aes(NULL, -50, NULL, NULL);
	assert_equals((struct jalp_transform *)NULL, invalid_aes_transform);
}

void test_jalp_transform_append_aes_null_key_and_iv()
{
	struct jalp_transform *valid_aes_transform;
	valid_aes_transform = jalp_transform_append_aes(NULL, JALP_AES128, NULL, NULL);
	assert_not_equals(NULL, valid_aes_transform);
	jalp_transform_destroy(&valid_aes_transform);
}

void test_jalp_transform_append_aes_appends_to_null()
{
	uint8_t *key;
	uint8_t *iv;
	unsigned int i[32];
	unsigned int j[32];
	key = (uint8_t *)i;
	iv = (uint8_t *)j;
	struct jalp_transform *aes_transform;
	aes_transform = jalp_transform_append_aes(NULL, JALP_AES128, key, iv);
	assert_not_equals(NULL, aes_transform);
	jalp_transform_destroy(&aes_transform);
}

void test_jalp_transform_append_aes_appends_to_prev()
{
	struct jalp_transform *first = jalp_transform_append(NULL, "uri", "xml");
	uint8_t *key;
	uint8_t *iv;
	unsigned int i[32];
	unsigned int j[32];
	key = (uint8_t *)i;
	iv = (uint8_t *)j;
	struct jalp_transform *aes_transform;
	aes_transform = jalp_transform_append_aes(first, JALP_AES128, key, iv);
	assert_not_equals(NULL, aes_transform);
	assert_equals(first->next, aes_transform);
	jalp_transform_destroy(&first);
}

void test_jalp_transform_append_aes_correctly_encodes_data()
{
	int i;
	struct jalp_transform *aes_transform;
	uint8_t key[128];
	uint8_t iv[128];

	/* fill key and iv with arbitrary data */
	for(i = 0; i < 128; i++) {
		key[i] = (uint8_t)i;
		iv[i] = (uint8_t)(128 - i);
	}

	aes_transform = jalp_transform_append_aes(NULL, JALP_AES128, key, iv);

	unsigned char *char_key = jal_malloc(128);
	unsigned char *char_iv = jal_malloc(128);
	memcpy(char_key, key, 128);
	memcpy(char_iv, iv, 128);

	char *b64_key = jalp_base64_enc(char_key, 128);
	char *b64_iv = jalp_base64_enc(char_iv, 128);

	char *xml_snippet;

	jal_asprintf(&xml_snippet, "<Key128>%s</Key128><IV128>%s</IV128>", b64_key, b64_iv);

	assert_equals(0, strcmp(xml_snippet, aes_transform->xml));
	assert_string_equals(aes_transform->uri, "http://www.w3.org/2001/04/xmlenc#aes128-cbc");

	free(xml_snippet);
	jalp_transform_destroy(&aes_transform);
}

void test_jalp_transform_append_aes_works_with_different_keysizes()
{
	int i;
	struct jalp_transform *aes_transform_128;
	struct jalp_transform *aes_transform_192;
	struct jalp_transform *aes_transform_256;
	uint8_t key[256];

	/* fill key and iv with arbitrary data */
	for(i = 0; i < 256; i++) {
		key[i] = (uint8_t)i;
	}

	aes_transform_128 = jalp_transform_append_aes(NULL, JALP_AES128, key, NULL);
	aes_transform_192 = jalp_transform_append_aes(NULL, JALP_AES192, key, NULL);
	aes_transform_256 = jalp_transform_append_aes(NULL, JALP_AES256, key, NULL);

	unsigned char *char_key = jal_malloc(256);
	memcpy(char_key, key, 256);

	char *b64_key_128 = jalp_base64_enc(char_key, 128);
	char *b64_key_192 = jalp_base64_enc(char_key, 192);
	char *b64_key_256 = jalp_base64_enc(char_key, 256);

	char *xml_snippet_128;
	char *xml_snippet_192;
	char *xml_snippet_256;

	jal_asprintf(&xml_snippet_128, "<Key128>%s</Key128>", b64_key_128);
	jal_asprintf(&xml_snippet_192, "<Key192>%s</Key192>", b64_key_192);
	jal_asprintf(&xml_snippet_256, "<Key256>%s</Key256>", b64_key_256);

	assert_equals(0, strcmp(xml_snippet_128, aes_transform_128->xml));
	assert_equals(0, strcmp(xml_snippet_192, aes_transform_192->xml));
	assert_equals(0, strcmp(xml_snippet_256, aes_transform_256->xml));

	free(xml_snippet_128);
	free(xml_snippet_192);
	free(xml_snippet_256);

	jalp_transform_destroy(&aes_transform_128);
	jalp_transform_destroy(&aes_transform_192);
	jalp_transform_destroy(&aes_transform_256);
}
