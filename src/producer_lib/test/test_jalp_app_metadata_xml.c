/**
 * @file test_jalp_app_metadata_xml.cpp This file contains functions to test jalp_app_metadata_to_elem().
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011-2012 Tresys Technology LLC, Columbia, Maryland, USA
 *
 * This software was developed by Tresys Technology LLC
 * with U.S. Government sponsorship.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <test-dept.h>

// this is needed so that UINT64_MAX is defined
#define __STDC_LIMIT_MACROS
#include <stdint.h>

#include <ctype.h>
#include <uuid/uuid.h>
#include <jalop/jalp_context.h>
#include "jalp_app_metadata_xml.h"
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jal_xml_utils.h"
#include "xml_test_utils2.h"

#define EVENT_ID "event-123-xyz"
//#define CUSTOM_XML "<foo:tag xmlns:foo='some:uri'>blah blah</foo:tag><!--And a comment for good measure -->"
#define CUSTOM_XML "<foo:tag xmlns:foo='some:uri'>blah blah</foo:tag>"
#define BAD_CUSTOM_XML "<foo:tag></tag><!--tag mismatch, should fail to parse...-->"
#define CUSTOM_TAG "Custom"
#define SYSLOG_TAG "Syslog"
#define LOGGER_TAG "Logger"
#define JOURNAL_TAG "JournalMetadata"
#define APP_META_TAG "ApplicationMetadata"
#define EVENT_ID_TAG "EventID"
#define FOO_TAG "tag"
#define JID_ATTR_NAME "JID"
#define JID_PREFIX "UUID-"

static xmlDocPtr doc = NULL;

static jalp_context *ctx;
static struct jalp_app_metadata *app_meta;
static struct jalp_journal_metadata *journal_meta;
static struct jalp_syslog_metadata *syslog_meta;
static struct jalp_logger_metadata *logger_meta;

xmlChar* xml_jid_attr_name;

void setup()
{
	jalp_init();
	app_meta = jalp_app_metadata_create();
	app_meta->type = JALP_METADATA_NONE;
	app_meta->event_id = jal_strdup(EVENT_ID);

	ctx = jalp_context_create();
	jalp_context_init(ctx, NULL, NULL, NULL, NULL);
	journal_meta = jalp_journal_metadata_create();
	journal_meta->file_info = jalp_file_info_create();
	journal_meta->file_info->filename = jal_strdup(__FILE__);

	syslog_meta = jalp_syslog_metadata_create();
	logger_meta = jalp_logger_metadata_create();

	doc =  xmlNewDoc((xmlChar *)"1.0");

	xml_jid_attr_name = (xmlChar *)JID_ATTR_NAME;
}

void teardown()
{
	xmlFreeDoc(doc);

	app_meta->type = JALP_METADATA_NONE;
	jalp_app_metadata_destroy(&app_meta);
	jalp_syslog_metadata_destroy(&syslog_meta);
	jalp_logger_metadata_destroy(&logger_meta);
	jalp_journal_metadata_destroy(&journal_meta);
	jalp_context_destroy(&ctx);

	jalp_shutdown();
}

void test_app_metadata_to_elem_fails_with_invalid_input()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;

	ret = jalp_app_metadata_to_elem(NULL, ctx, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jalp_app_metadata_to_elem(app_meta, NULL, doc, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jalp_app_metadata_to_elem(app_meta, ctx, NULL, &new_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);

	ret = jalp_app_metadata_to_elem(app_meta, ctx, doc, NULL);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);

	xmlNodePtr bad_elem = (xmlNodePtr) 0xbadf00d;
	ret = jalp_app_metadata_to_elem(app_meta, ctx, doc, &bad_elem);
	assert_equals(JAL_E_XML_CONVERSION, ret);
	assert_equals((void*)NULL, new_elem);
}
void test_app_metadata_to_elem_works_for_custom()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;
	app_meta->type = JALP_METADATA_CUSTOM;
	app_meta->custom = jal_strdup(CUSTOM_XML);
	ret = jalp_app_metadata_to_elem(app_meta, ctx, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_tag_equals(APP_META_TAG, new_elem);
	xmlDocSetRootElement(doc, new_elem);
	assert_true(0 == validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	xmlChar *jid = xmlGetProp(new_elem, xml_jid_attr_name);
	assert_true(0 == strncmp(JID_PREFIX, (char *)jid, strlen(JID_PREFIX)));
	char *uuidstr = (char *)jid + strlen(JID_PREFIX);
	uuid_t uuid;
	assert_true(0 == uuid_parse(uuidstr, uuid));
	xmlFree(jid);

	xmlNodePtr event_id = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, event_id);
	assert_tag_equals(EVENT_ID_TAG, event_id);
	assert_content_equals(EVENT_ID, event_id);

	xmlNodePtr custom = event_id->next;
	assert_not_equals(NULL, custom);
	assert_tag_equals(CUSTOM_TAG, custom);

	xmlNodePtr foobar = jal_get_first_element_child(custom);
	assert_tag_equals(FOO_TAG, foobar);

	xmlNodePtr should_be_null = custom->next;
	assert_pointer_equals((void*)NULL, should_be_null);
	free(app_meta->custom);
	app_meta->custom = NULL;
}

void test_app_metadata_to_elem_fails_with_bad_xml_for_custom()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;
	app_meta->type = JALP_METADATA_CUSTOM;
	app_meta->custom = jal_strdup(BAD_CUSTOM_XML);
	ret = jalp_app_metadata_to_elem(app_meta, ctx, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);

	free(app_meta->custom);
	app_meta->custom = NULL;
}

void test_app_metadata_to_elem_works_without_event_id()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;
	free(app_meta->event_id);
	app_meta->event_id = NULL;
	ret = jalp_app_metadata_to_elem(app_meta, ctx, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_tag_equals(APP_META_TAG, new_elem);
	xmlDocSetRootElement(doc, new_elem);
	assert_true(0 == validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	xmlChar *jid = xmlGetProp(new_elem, xml_jid_attr_name);
	assert_true(0 == strncmp(JID_PREFIX, (char *)jid, strlen(JID_PREFIX)));
	char *uuidstr = (char *)jid + strlen(JID_PREFIX);
	uuid_t uuid;
	assert_true(0 == uuid_parse(uuidstr, uuid));
	xmlFree(jid);

	xmlNodePtr custom = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, custom);
	assert_tag_equals(CUSTOM_TAG, custom);

	xmlNodePtr should_be_null = custom->next;
	assert_pointer_equals((void*)NULL, should_be_null);
}

void test_app_metadata_to_elem_fails_with_bad_syslog()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;
	app_meta->type = JALP_METADATA_SYSLOG;
	syslog_meta->facility = INT8_MAX; // this should be an illegal facility`
	app_meta->sys = syslog_meta;
	ret = jalp_app_metadata_to_elem(app_meta, ctx, doc, &new_elem);
	assert_not_equals(JAL_OK, ret);
	assert_pointer_equals((void*) NULL, new_elem);
}

void test_app_metadata_to_elem_works_for_syslog()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;
	app_meta->type = JALP_METADATA_SYSLOG;
	app_meta->sys = syslog_meta;
	ret = jalp_app_metadata_to_elem(app_meta, ctx, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_tag_equals(APP_META_TAG, new_elem);
	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	xmlChar *jid = xmlGetProp(new_elem, xml_jid_attr_name);
	assert_true(0 == strncmp(JID_PREFIX, (char *)jid, strlen(JID_PREFIX)));
	char *uuidstr = (char *)jid + strlen(JID_PREFIX);
	uuid_t uuid;
	assert_true(0 == uuid_parse(uuidstr, uuid));
	xmlFree(jid);

	xmlNodePtr event_id = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, event_id);
	assert_tag_equals(EVENT_ID_TAG, event_id);
	assert_content_equals(EVENT_ID, event_id);

	xmlNodePtr syslog = event_id->next;
	assert_not_equals(NULL, syslog);
	assert_tag_equals(SYSLOG_TAG, syslog);

	xmlNodePtr should_be_null = syslog->next;
	assert_pointer_equals((void*)NULL, should_be_null);

	app_meta->sys = NULL;
}

void test_app_metadata_to_elem_works_for_logger()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;
	app_meta->type = JALP_METADATA_LOGGER;
	app_meta->log = logger_meta;
	ret = jalp_app_metadata_to_elem(app_meta, ctx, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_tag_equals(APP_META_TAG, new_elem);
	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));
	
	xmlChar *jid = xmlGetProp(new_elem, xml_jid_attr_name);
	assert_equals(0, strncmp(JID_PREFIX, (char *)jid, strlen(JID_PREFIX)));
	char *uuidstr = (char *)jid + strlen(JID_PREFIX);
	uuid_t uuid;
	assert_true(0 == uuid_parse(uuidstr, uuid));
	xmlFree(jid);

	xmlNodePtr event_id = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, event_id);
	assert_tag_equals(EVENT_ID_TAG, event_id);
	assert_content_equals(EVENT_ID, event_id);

	xmlNodePtr logger = event_id->next;
	assert_not_equals(NULL, logger);
	assert_tag_equals(LOGGER_TAG, logger);

	xmlNodePtr should_be_null = logger->next;
	assert_pointer_equals((void*)NULL, should_be_null);

	app_meta->sys = NULL;
}

void test_app_metadata_to_elem_works_with_journal_meta()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;
	app_meta->file_metadata = journal_meta;
	ret = jalp_app_metadata_to_elem(app_meta, ctx, doc, &new_elem);
	app_meta->file_metadata = NULL;
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	assert_tag_equals(APP_META_TAG, new_elem);
	xmlDocSetRootElement(doc, new_elem);
	assert_equals(0, validate(doc, __FUNCTION__, TEST_XML_APP_META_TYPES_SCHEMA, 0));

	xmlChar *jid = xmlGetProp(new_elem, xml_jid_attr_name);
	assert_equals(0, strncmp(JID_PREFIX, (char *)jid, strlen(JID_PREFIX)));
	char *uuidstr = (char *)jid + strlen(JID_PREFIX);
	uuid_t uuid;
	assert_true(0 == uuid_parse(uuidstr, uuid));
	xmlFree(jid);

	xmlNodePtr event_id = jal_get_first_element_child(new_elem);
	assert_not_equals(NULL, event_id);
	assert_tag_equals(EVENT_ID_TAG, event_id);
	assert_content_equals(EVENT_ID, event_id);

	xmlNodePtr custom = event_id->next;
	assert_not_equals(NULL, custom);
	assert_tag_equals(CUSTOM_TAG, custom);

	xmlNodePtr journal = custom->next;
	assert_not_equals(NULL, journal);
	assert_tag_equals(JOURNAL_TAG, journal);

	xmlNodePtr should_be_null = journal->next;
	assert_pointer_equals((void*)NULL, should_be_null);
}

void test_app_metadata_to_elem_fails_with_invalid_journal_meta()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;
	app_meta->file_metadata = journal_meta;
	free(journal_meta->file_info->filename);
	journal_meta->file_info->filename = NULL;

	ret = jalp_app_metadata_to_elem(app_meta, ctx, doc, &new_elem);
	app_meta->file_metadata = NULL;
	assert_not_equals(JAL_OK, ret);
	assert_equals((void*)NULL, new_elem);
}
