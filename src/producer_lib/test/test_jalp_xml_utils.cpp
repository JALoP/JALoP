// The test-dept code doesn't work very well in C++ when __STRICT_ANSI__ is
// not defined. It tries to use some gcc extensions that don't work well with
// c++.

#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
extern "C" {
#include <test-dept.h>
}
#include <jalop/jalp_context.h>
#include <jalop/jal_namespaces.h>
#include <jalop/jal_status.h>

#include "xml_test_utils.hpp"
#include "jalp_xml_utils.hpp"
#include "jalp_base64_internal.h"

XERCES_CPP_NAMESPACE_USE

static DOMDocument *doc = NULL;

static const char *string = "asdf";
static const char *base64_string = "YXNkZg==";

static XMLCh *tag = NULL;

#define TAG "SomeTag"

#define ALGORITHM "Algorithm"
#define DIGEST_METHOD "DigestMethod"
#define DIGEST_VALUE "DigestValue"
#define REFERENCE "Reference"
#define URI "URI"

#define EXAMPLE_URI "file:///somefile"
#define EXAMPLE_BAD_URI "bad uri"
#define EXAMPLE_DIGEST_METHOD "some digest method"

XMLCh *namespace_uri;

std::list<const char*> schemas;

extern "C" void setup()
{
	jalp_init();

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();

	namespace_uri = XMLString::transcode(JALP_APP_META_TYPES_NAMESPACE_URI);

	tag = XMLString::transcode(TAG);

	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);
}

extern "C" void teardown()
{
	schemas.clear();
	XMLString::release(&tag);
	XMLString::release(&namespace_uri);
	delete doc;
	jalp_shutdown();
}

extern "C" void test_create_base64_element_returns_null_with_null_inputs()
{
	DOMElement *new_elem = NULL;
	jal_status ret;

	ret = create_base64_element(NULL, (uint8_t *) string, strlen(string), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = create_base64_element(doc, NULL, strlen(string), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = create_base64_element(doc, (uint8_t *) string, 0, namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), NULL, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), namespace_uri, NULL, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);

	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), namespace_uri, tag, NULL);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(NULL, new_elem);
}

extern "C" void test_create_base64_element_fails_does_not_overwrite_existing_elm_pointer()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret;

	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), namespace_uri, tag, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	DOMElement *orig = new_elem;
	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), namespace_uri, tag, &new_elem);
	assert_equals(JAL_E_INVAL, ret);
	assert_equals(orig, new_elem);
}

extern "C" void test_create_base64_element_works_with_normal_value()
{
	// <SomeTag>YXNkZg==</SomeTag>
	DOMElement *new_elem = NULL;
	enum jal_status ret;

	ret = create_base64_element(doc, (uint8_t *) string, strlen(string), namespace_uri, tag, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_tag_equals(TAG, new_elem);
	assert_content_equals(base64_string, new_elem);
	assert_namespace_equals(JALP_APP_META_TYPES_NAMESPACE_URI, new_elem);
}

extern "C" void test_jal_create_reference_elem_returns_null_with_null_inputs()
{
	DOMElement *new_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem(NULL, NULL, NULL, 0, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, NULL,
			(uint8_t *)string, strlen(string), doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, (char *) EXAMPLE_DIGEST_METHOD,
			NULL, strlen(string), doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);
}

extern "C" void test_jal_create_reference_elem_succeeds_with_good_input()
{
	DOMElement *reference_elem = NULL;
	DOMElement *digest_method_elem = NULL;
	DOMElement *digest_value_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)string, strlen(string), doc, &reference_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, reference_elem);
	assert_tag_equals(REFERENCE, reference_elem);
	assert_attr_equals(URI, EXAMPLE_URI, reference_elem);
	assert_equals(reference_elem->getChildElementCount(), 2);

	digest_method_elem = reference_elem->getFirstElementChild();
	assert_not_equals(NULL, digest_method_elem);
	assert_tag_equals(DIGEST_METHOD, digest_method_elem);
	assert_attr_equals(ALGORITHM, EXAMPLE_DIGEST_METHOD, digest_method_elem);

	digest_value_elem = digest_method_elem->getNextElementSibling();
	assert_not_equals(NULL, digest_value_elem);
	assert_tag_equals(DIGEST_VALUE, digest_value_elem);
	assert_content_equals(base64_string, digest_value_elem);

	doc->appendChild(reference_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_jal_create_reference_elem_succeeds_with_no_uri()
{
	DOMElement *reference_elem = NULL;
	DOMElement *digest_method_elem = NULL;
	DOMElement *digest_value_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem(NULL, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)string, strlen(string), doc, &reference_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, reference_elem);
	assert_tag_equals(REFERENCE, reference_elem);
	assert_equals(reference_elem->getChildElementCount(), 2);

	digest_method_elem = reference_elem->getFirstElementChild();
	assert_not_equals(NULL, digest_method_elem);
	assert_tag_equals(DIGEST_METHOD, digest_method_elem);
	assert_attr_equals(ALGORITHM, EXAMPLE_DIGEST_METHOD, digest_method_elem);

	digest_value_elem = digest_method_elem->getNextElementSibling();
	assert_not_equals(NULL, digest_value_elem);
	assert_tag_equals(DIGEST_VALUE, digest_value_elem);
	assert_content_equals(base64_string, digest_value_elem);

	doc->appendChild(reference_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_jal_create_reference_elem_fails_does_not_overwrite_existing_pointer()
{
	DOMElement *reference_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)string, strlen(string), doc, &reference_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, reference_elem);

	ret = jal_create_reference_elem((char *) EXAMPLE_URI, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)string, strlen(string), doc, &reference_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_not_equals(NULL, reference_elem);
}

extern "C" void test_jal_create_reference_elem_fails_bad_url()
{
	DOMElement *reference_elem = NULL;
	jal_status ret;

	ret = jal_create_reference_elem((char *) EXAMPLE_BAD_URI, (char *) EXAMPLE_DIGEST_METHOD,
			(uint8_t *)string, strlen(string), doc, &reference_elem);
	assert_equals(JAL_E_INVAL_URI, ret);
	assert_equals(NULL, reference_elem);
}
