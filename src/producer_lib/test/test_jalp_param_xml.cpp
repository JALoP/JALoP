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
#include <jalop/jalp_logger_metadata.h>

#include "xml_test_utils.hpp"
#include "jalp_param_xml.hpp"
#include "jal_alloc.h"

XERCES_CPP_NAMESPACE_USE

struct jalp_param *param1 = NULL;
struct jalp_param *param2 = NULL;

static DOMDocument *doc = NULL;

static XMLCh *xml_p1_tag = NULL;
static XMLCh *xml_p1_attr = NULL;
static XMLCh *xml_p2_tag = NULL;
static XMLCh *xml_p2_attr = NULL;
std::list<const char*> schemas;

#define P1_TAG "Field"
#define P1_ATTR "Key"
#define P1_ATTR_VAL "key1"
#define P1_CONTENT "val1"

#define P2_TAG "Parameter"
#define P2_ATTR "Name"
#define P2_ATTR_VAL "key2"
#define P2_CONTENT "val2"

extern "C" void setup()
{
	jalp_init();
	xml_p1_tag = XMLString::transcode(P1_TAG);
	xml_p1_attr = XMLString::transcode(P1_ATTR);

	xml_p2_tag = XMLString::transcode(P2_TAG);
	xml_p2_attr = XMLString::transcode(P2_ATTR);

	param1 = jalp_param_append(NULL, P1_ATTR_VAL, P1_CONTENT);
	param2 = jalp_param_append(param1, P2_ATTR_VAL, P2_CONTENT);

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();

	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);
}

extern "C" void teardown()
{
	jalp_param_destroy(&param1);
	delete doc;
	schemas.clear();
	jalp_shutdown();
}

extern "C" void test_param_to_elem_returns_null_with_null_inputs()
{
	DOMElement *new_elem = NULL;
	jal_status ret = jalp_param_to_elem(NULL, NULL, NULL, NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);

	ret = jalp_param_to_elem(param2, xml_p1_tag, xml_p1_attr, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jalp_param_to_elem(param2, xml_p1_tag, xml_p1_attr, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jalp_param_to_elem(param2, xml_p1_tag, NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jalp_param_to_elem(param2, NULL, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);

	ret = jalp_param_to_elem(NULL, xml_p1_tag, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(NULL, new_elem);
}

extern "C" void test_param_to_elem_fails_does_not_overwrite_existing_elm_pointer()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param1, xml_p1_tag, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	DOMElement *orig = new_elem;
	ret = jalp_param_to_elem(param1, xml_p1_tag, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
}
extern "C" void test_param_to_elem_with_bad_inputs_does_not_overwrite_existing_elm_pointer()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param1, xml_p1_tag, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	DOMElement *orig = new_elem;
	ret = jalp_param_to_elem(param1, xml_p1_tag, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_param_to_elem(param2, xml_p1_tag, xml_p1_attr, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_param_to_elem(param2, xml_p1_tag, NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_param_to_elem(param2, NULL, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);

	ret = jalp_param_to_elem(NULL, xml_p1_tag, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals(orig, new_elem);
}
extern "C" void test_param_to_elem_fails_with_missing_key()
{
	free(param1->key);
	param1->key = NULL;

	DOMElement *new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param1, xml_p1_tag, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_E_INVAL_PARAM, ret);
	assert_equals(NULL, new_elem);
}
extern "C" void test_param_to_elem_works_with_normal_param()
{
	// <Field Key="key1"/>val1</Field>
	DOMElement *new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param1, xml_p1_tag, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_attr_equals(P1_ATTR, P1_ATTR_VAL, new_elem);
	assert_tag_equals(P1_TAG, new_elem);
	assert_content_equals(P1_CONTENT, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
extern "C" void test_param_to_elem_works_with_normal_param_different_values()
{
	// <Field Key="key1"/>val1</Field>
	DOMElement *new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param2, xml_p2_tag, xml_p2_attr, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_attr_equals(P2_ATTR, P2_ATTR_VAL, new_elem);
	assert_tag_equals(P2_TAG, new_elem);
	assert_content_equals(P2_CONTENT, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_param_to_elem_works_with_missing_value()
{
	free(param1->value);
	param1->value = NULL;
	// should create
	// <Field Key="key1"/>
	DOMElement *new_elem = NULL;
	enum jal_status ret = jalp_param_to_elem(param1, xml_p1_tag, xml_p1_attr, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);
	assert_attr_equals(P1_ATTR, P1_ATTR_VAL, new_elem);
	assert_content_equals("", new_elem);
	assert_tag_equals(P1_TAG, new_elem);
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
