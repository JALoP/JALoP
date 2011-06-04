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

#include "xml_test_utils.hpp"
#include "jalp_log_severity_xml.hpp"
#include "jalp_alloc.h"

XERCES_CPP_NAMESPACE_USE
struct jalp_log_severity *severity = NULL;
DOMDocument *doc = NULL;
XMLCh *expected_name_attr = NULL;
XMLCh *expectedLevelVal = NULL;
std::list<const char*> schemas;

#define LEVEL_NUM 1
#define LEVEL_NAME "test-level"

extern "C" void setup()
{
	jalp_init();
	severity = jalp_log_severity_create();
	severity->level_val = LEVEL_NUM;
	severity->level_str = jalp_strdup(LEVEL_NAME);
	expected_name_attr = XMLString::transcode("Name");

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();


	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);
}

extern "C" void teardown()
{
	jalp_log_severity_destroy(&severity);
	delete doc;
	XMLString::release(&expected_name_attr);
	schemas.clear();
	jalp_shutdown();
}

extern "C" void test_log_severity_to_elem_returns_null_for_null()
{
	DOMElement *new_elem = jalp_log_severity_to_elem(NULL, NULL);
	assert_equals(NULL, new_elem);

	new_elem = jalp_log_severity_to_elem(severity, NULL);
	assert_equals(NULL, new_elem);

	new_elem = jalp_log_severity_to_elem(NULL, doc);
	assert_equals(NULL, new_elem);
}

extern "C" void test_log_severity_to_elem_returns_valid_element_when_name_is_not_empty()
{
	DOMElement *new_elem = jalp_log_severity_to_elem(severity, doc);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals("Name", LEVEL_NAME, new_elem);
	assert_equals(LEVEL_NUM, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
extern "C" void test_log_severity_to_elem_returns_valid_element_when_name_is_empty()
{
	free(severity->level_str);
	severity->level_str = strdup("");
	DOMElement *new_elem = jalp_log_severity_to_elem(severity, doc);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals("Name", "", new_elem);
	assert_equals(LEVEL_NUM, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
extern "C" void test_log_severity_to_elem_works_when_name_is_null()
{
	free(severity->level_str);
	severity->level_str = NULL;
	DOMElement *new_elem = jalp_log_severity_to_elem(severity, doc);
	assert_not_equals(NULL, new_elem);
	assert_attr_equals("Name", NULL, new_elem);
	assert_equals(LEVEL_NUM, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_log_severity_to_elem_works_with_negative_levels()
{
	severity->level_val = -10;
	DOMElement *new_elem = jalp_log_severity_to_elem(severity, doc);
	assert_not_equals(NULL, new_elem);
	assert_equals(-10, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_log_severity_to_elem_works_with_int_max()
{
	severity->level_val = INT_MAX;
	DOMElement *new_elem = jalp_log_severity_to_elem(severity, doc);
	assert_not_equals(NULL, new_elem);
	assert_equals(INT_MAX, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}

extern "C" void test_log_severity_to_elem_works_with_int_min()
{
	severity->level_val = INT_MIN;
	DOMElement *new_elem = jalp_log_severity_to_elem(severity, doc);
	assert_not_equals(NULL, new_elem);
	assert_equals(INT_MIN, XMLString::parseInt(new_elem->getTextContent()));
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
