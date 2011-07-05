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

XMLCh *namespace_uri;

extern "C" void setup()
{
	jalp_init();

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();

	namespace_uri = XMLString::transcode(JALP_APP_META_TYPES_NAMESPACE_URI);

	tag = XMLString::transcode(TAG);
}

extern "C" void teardown()
{
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
