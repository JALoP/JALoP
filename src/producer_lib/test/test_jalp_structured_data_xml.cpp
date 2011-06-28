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
#include <jalop/jalp_structured_data.h>

#include "xml_test_utils.hpp"
#include "jalp_structured_data_xml.hpp"
#include "jal_alloc.h"

XERCES_CPP_NAMESPACE_USE
struct jalp_structured_data *sd = NULL;
DOMDocument *doc = NULL;
std::list<const char*> schemas;

#define SD_ID "test-sd-id"
#define SD_ID_ATTR_NAME "SD_ID"
#define P1_NAME "p1_name"
#define P1_VALUE "p1_value"
#define P2_NAME "p2_name"
#define P2_VALUE "p2_value"
#define P3_NAME "p3_name"
#define P3_VALUE "p3_value"

extern "C" void setup()
{
	jalp_init();
	sd = jalp_structured_data_append(NULL, SD_ID);
	sd->param_list = jalp_param_append(NULL, P1_NAME, P1_VALUE);
	struct jalp_param *tmp_param = jalp_param_append(sd->param_list, P2_NAME, P2_VALUE);
	jalp_param_append(tmp_param, P3_NAME, P3_VALUE);

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(TEST_XML_CORE);
	doc = impl->createDocument();

	schemas.push_back(TEST_XML_DSIG_SCHEMA);
	schemas.push_back(TEST_XML_APP_META_TYPES_SCHEMA);
}

extern "C" void teardown()
{
	jalp_structured_data_destroy(&sd);
	delete doc;
	schemas.clear();
	jalp_shutdown();
}

extern "C" void test_structured_data_to_elem_fails_with_null_inputs()
{
	enum jal_status ret = jalp_structured_data_to_elem(NULL, NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_structured_data_to_elem(sd, NULL, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_structured_data_to_elem(NULL, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	ret = jalp_structured_data_to_elem(sd, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
}
extern "C" void test_structured_data_to_elem_fails_when_new_elem_already_points_somewhere()
{
	DOMElement *new_elem = (DOMElement*) 0x8badf00d;
	enum jal_status ret = jalp_structured_data_to_elem(NULL, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)0x8badf00d, new_elem);
	ret = jalp_structured_data_to_elem(sd, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)0x8badf00d, new_elem);
	ret = jalp_structured_data_to_elem(NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)0x8badf00d, new_elem);
	ret = jalp_structured_data_to_elem(sd, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)0x8badf00d, new_elem);
}
extern "C" void test_structured_data_to_elem_fails_with_illegal_structured_data()
{
	// structured data elements must have an ID and at least one jalp_param.
	DOMElement *new_elem = NULL;
	char *sd_id = sd->sd_id;
	sd->sd_id = NULL;
	enum jal_status ret = jalp_structured_data_to_elem(sd, doc, &new_elem);
	assert_equals(JAL_E_INVAL_STRUCTURED_DATA, ret);
	assert_equals((void*)NULL, new_elem);

	sd->sd_id = sd_id;
	jalp_param_destroy(&(sd->param_list));
	ret = jalp_structured_data_to_elem(sd, doc, &new_elem);
	assert_equals(JAL_E_INVAL_STRUCTURED_DATA, ret);
	assert_equals((void*)NULL, new_elem);
}

extern "C" void test_structured_data_to_elem_fails_when_jalp_param_to_elem_fails()
{
	// jalp_param elements must have a 'key'
	free(sd->param_list->key);
	sd->param_list->key = NULL;
	DOMElement *new_elem = NULL;
	enum jal_status ret = jalp_structured_data_to_elem(sd, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);
}

extern "C" void test_structured_data_to_elem_returns_valid_element()
{
	DOMElement *new_elem = NULL;
	enum jal_status ret = jalp_structured_data_to_elem(sd, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_attr_equals(SD_ID_ATTR_NAME, SD_ID, new_elem);
	// make sure there are only 3 params in the list.
	assert_not_equals(NULL, new_elem->getFirstChild());
	assert_not_equals(NULL, new_elem->getFirstChild()->getNextSibling());
	assert_not_equals(NULL, new_elem->getFirstChild()->getNextSibling()->getNextSibling());
	assert_equals((void*) NULL, new_elem->getFirstChild()->getNextSibling()->getNextSibling()->getNextSibling());
	doc->appendChild(new_elem);
	assert_equals(true, validate(doc, __FUNCTION__, schemas));
}
