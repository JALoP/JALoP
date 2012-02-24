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
 * Copyright (c) 2011 Tresys Technology LLC, Columbia, Maryland, USA
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
#include "jalpx_app_metadata_xml.h"
#include "jal_alloc.h"
#include "jal_asprintf_internal.h"

#define EVENT_ID "event-123-xyz"
#define CUSTOM_XML "<foo:tag xmlns:foo='some:uri'>blah blah</foo:tag><!--And a comment for good measure -->"
#define BAD_CUSTOM_XML "<foo:tag></tag><!--tag mismatch, should fail to parse...-->"
#define CUSTOM_TAG "Custom"
#define SYSLOG_TAG "Syslog"
#define LOGGER_TAG "Logger"
#define JOURNAL_TAG "JournalMetadata"
#define APP_META_TAG "ApplicationMetadata"
#define EVENT_ID_TAG "EventID"
#define FOO_TAG "foo:tag"
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

	//XMLString::release(&xml_jid_attr_name);

	jalp_shutdown();
}

void test_app_metadata_to_elem_works_for_custom()
{
	xmlNodePtr new_elem = NULL;
	enum jal_status ret;
	app_meta->type = JALP_METADATA_CUSTOM;
	app_meta->custom = jal_strdup(CUSTOM_XML);
	ret = jalpx_app_metadata_to_elem(app_meta, ctx, doc, &new_elem);
	assert_equals(JAL_OK, ret);
	assert_not_equals(NULL, new_elem);

	printf("\nNEW_APP_METADATA\n");
	xmlDocSetRootElement(doc, new_elem);

	xmlChar *xmlbuff;
	int buffersize;

	/*
	* Dump the document to a buffer and print it
	* for demonstration purposes.
	*/
	xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);
	printf("%s", (char *) xmlbuff);

	/*
	* Free associated memory.
	*/
	xmlFree(xmlbuff);
}
