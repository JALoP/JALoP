#include <test-dept.h>
#include <stdlib.h>
#include "jalp_base64_internal.h"

void test_jalp_base64_enc_null_input()
{
	char *inval = jalp_base64_enc((unsigned char *)NULL, 10);
	assert_equals((char *)NULL, inval);
}

void test_jalp_base64_enc_bad_lengths()
{
	char *inval = jalp_base64_enc((unsigned char *)"inval", 0);
	assert_equals((char *)NULL, inval);

	inval = jalp_base64_enc((unsigned char *)"inval", -200);
	assert_equals((char *)NULL, inval);
}

void test_jalp_base64_enc_encodes()
{
	unsigned char bytes[4] = {(unsigned char)'a', (unsigned char)'s',
				(unsigned char)'d', (unsigned char)'f'};
	char *valid = jalp_base64_enc(bytes, 4);
	assert_string_equals(valid, "YXNkZg==");
	free(valid);
}
