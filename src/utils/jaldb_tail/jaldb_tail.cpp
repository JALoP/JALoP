/**
* @file jaldb_tail.cpp This file contains the implementation for the
* jaldb_tail utility.
*
* @section LICENSE
*
* Source code in 3rd-party is licensed and owned by their respective
* copyright holders.
*
* All other source code is copyright Tresys Technology and licensed as below.
*
* Copyright (c) 2011-2013 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <libconfig.h>
#include <unistd.h>	// sleep
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>	// strtol
#include <string.h>
#include <fcntl.h>
#include <list>
#include <iostream>
#include <fstream>
#include <signal.h>	/** For SIGABRT, SIGTERM, SIGINT **/
#include <errno.h>	// errno
#include <limits.h>	// LONG_MAX, LONG_MIN

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <jal_alloc.h>
#include <jal_asprintf_internal.h>

#include <jaldb_status.h>
#include <jalop/jal_version.h>
#include "jaldb_context.hpp"
#include "jaldb_segment.h"

#define JALDB_TAIL_THREAD_SLEEP_SECONDS 1
#define JALDB_TAIL_DEFAULT_NUM_RECORDS 20
#define JALDB_TAIL_DEFAULT_HOME "/var/lib/jalop/db"
#define JALDB_TAIL_DEFAULT_TYPE "l"
#define JALDB_TAIL_DEFAULT_DATA "i"
#define JALDB_TAIL_DEFAULT_LAST_UUID "0"
#define BUF_SIZE 4096

#define DEBUG_LOG(args...) \
do { \
	fprintf(stderr, "(jaldb_tail) %s[%d] ", __FUNCTION__, __LINE__); \
	fprintf(stderr, ##args); \
	fprintf(stderr, "\n"); \
	} while(0)

using namespace std;

static volatile int exit_flag = 0;

struct global_members_t {
	int follow_flag;
	long int num_rec;
	char *type;
	char *data;
	char *home;
	jaldb_context *ctx;
	enum jaldb_rec_type rtype;
} gbl;

static void parse_cmdline(int argc, char **argv);
static int setup_signals();
static void sig_handler(int sig);

static void print_usage();
static void print_version();
static void print_error(enum jaldb_status error);
static void print_settings(int follow, long int num_rec, char *type,
				char *data, char *home);
static void do_work(void *ptr);
static void display_records(list<string> &uuid_list, struct global_members_t *mbrs);

static int print_record(jaldb_context *ctx, char data, struct jaldb_record *rec);
static int dump_record_by_nonce(jaldb_context *ctx, enum jaldb_rec_type rtype, char data, char *nonce,
		enum jaldb_status *ret_status);
static int get_nodeset_by_expression(xmlDoc *doc,
		const xmlChar *expression, xmlNodeSetPtr *nset,
		xmlXPathObjectPtr *xpo);
static char *get_single_element_string(xmlDoc *doc, char *element);
static char *get_single_attribute_string(xmlDoc *doc, char *element, char *attr);

int main(int argc, char **argv) {
	int ret = 0;
	enum jaldb_status jaldb_ret = JALDB_OK;

	gbl.ctx = NULL;
	gbl.follow_flag = 0;
	gbl.num_rec = (long) JALDB_TAIL_DEFAULT_NUM_RECORDS;
	gbl.type = NULL;
	gbl.home = NULL;
	gbl.data = NULL;

	parse_cmdline(argc, argv);

	if (exit_flag) {
		goto out;
	}

	// Setup defaults if necessary.
	if (!gbl.home) {
		gbl.home = jal_strdup(JALDB_TAIL_DEFAULT_HOME);
	}

	if (!gbl.type) {
		gbl.type = jal_strdup(JALDB_TAIL_DEFAULT_TYPE);
	}

	if (!gbl.data) {
		gbl.data = jal_strdup(JALDB_TAIL_DEFAULT_DATA);
	}

	print_settings(gbl.follow_flag, gbl.num_rec, gbl.type, gbl.data, gbl.home);

	gbl.ctx = jaldb_context_create();

	jaldb_ret = jaldb_context_init(gbl.ctx, gbl.home, NULL, 1);

	if (jaldb_ret != JALDB_OK) {
		printf("\nContext could not be made.\n");
		print_error(jaldb_ret);
		goto err_out;
	}

	// Perform signal hookups
	if ( 0 != setup_signals()) {
		goto err_out;
	}

	do_work((void *) &gbl);

	/* deconstruct this util */
	goto out;

err_out:
	ret = -1;
	printf("You have hit error out. Closing out.\n");
out:
	// Clean-up
	if (gbl.type) {
		free(gbl.type);
	}
	if (gbl.data) {
		free(gbl.data);
	}
	if (gbl.home) {
		free(gbl.home);
	}
	if (gbl.ctx) {
		jaldb_context_destroy(&gbl.ctx);
	}
	return ret;
}

static void parse_cmdline(int argc, char **argv)
{
	static const char *optstring = "fn:vt:h:d:";
	static const struct option long_options[] = {
		{"follow", no_argument, NULL, 'f'},
		{"records", required_argument, NULL, 'n'},
		{"version", no_argument, NULL, 'v'},
		{"type", required_argument, NULL, 't'},
		{"data", required_argument, NULL, 'd'},
		{"home", required_argument, NULL, 'h'}, {0,0,0,0} };

	int ret_opt;
	while (EOF != (ret_opt = getopt_long(argc, argv, optstring, long_options, NULL))) {
		switch (ret_opt) {
			case 'f':
				// Set follow flag
				gbl.follow_flag = 1;
				break;
			case 'n':
				int my_err_no;
				errno = 0;
				gbl.num_rec = strtol(optarg, NULL, 10);
				my_err_no = errno;
				if ((LONG_MAX == gbl.num_rec || LONG_MIN == gbl.num_rec) &&
					ERANGE == my_err_no) {
					printf("Size of number entered was outside of the representable range.\n");
					exit_flag = 1;
				}
				if (0 == gbl.num_rec && my_err_no) {
					// Probably couldn't convert the value
					// to a long (errno was set).
					printf("No valid conversion could be found for \
					the value entered for the number of records.\n");
					exit_flag = 1;
				}
				if (0 > gbl.num_rec && !my_err_no) {
					// User probably entered 0 (errno was not set).
					printf("Number of records should be a positive value.\n");
					exit_flag = 1;
				}
				break;
			case 't':
				if (('j' != *optarg) && ('a' != *optarg) && ('l' != *optarg)) {
					printf("Type invalid\n");
					goto err_usage;
				}
				gbl.type = jal_strdup(optarg);
				break;
			case 'd':
				if (('i' != *optarg) && ('a' != *optarg) && ('s' != *optarg) && ('p' != *optarg) && ('z' != *optarg)) {
					printf("Data invalid\n");
					goto err_usage;
				}
				gbl.data = jal_strdup(optarg);
				break;
			case 'v':
				// Display Version info and exit
				print_version();
				exit_flag = 1;
				break;
			case 'h':
				gbl.home = jal_strdup(optarg);
				break;
			default:
				goto err_usage;
		}//switch
	}//while
	return;

err_usage:
	print_usage();
	exit_flag = 1;
	return;
}

static int setup_signals()
{
	struct sigaction action_on_sig;
	action_on_sig.sa_handler = &sig_handler;
	sigemptyset(&action_on_sig.sa_mask);
	action_on_sig.sa_flags = 0;

	if (0 != sigaction(SIGABRT, &action_on_sig, NULL)) {
		fprintf(stderr, "failed to register SIGABRT.\n");
		goto err_out;
	}
	if (0 != sigaction(SIGTERM, &action_on_sig, NULL)) {
		fprintf(stderr, "failed to register SIGTERM.\n");
		goto err_out;
	}
	if (0 != sigaction(SIGINT, &action_on_sig, NULL)) {
		fprintf(stderr, "failed to register SIGINT.\n");
		goto err_out;
	}
	return 0;

	err_out:
	return -1;
}

static void sig_handler(__attribute__((unused)) int sig)
{
	exit_flag = 1;	// Global Flag will cause main
			// to exit.
}

static void print_usage()
{
	static const char *usage =
	"Usage:\n\
	-f, --follow		Output additional records as the database grows.\n\
	-n K, --records=K	Output the most recent K records. Selecting '0' outputs all records.\n\
	-v, --version		Output the version information and exit.\n\
	-t T, --type=T		Select JALoP record type to output.\n\
				T may be: \"j\" (journal record), \"a\" (audit record), or \"l\" (log record).\n\
				Defaults to log records.\n\
	-d D, --data=D		Specifies which section of the data should be outputted, options are \"a\" for application\n\
				metadata, \"s\" for system metadata, \"p\" for the payload (raw journal, audit, or log\n\
				data), or \"i\" for record ID (UUID-Timestamp) only. \n\
				The default is to output the record ID only. To retrieve all portions of a record,\n\
				use \"z\".\n\
	-h H, --home=H		Specify the root of the JALoP database,\n\
				Defaults to /var/lib/jalop/db.\n\n";

	printf("%s\n", usage);
}

static void print_version()
{
	printf("jaldb_tail v%s\n\n", jal_version_as_string());
}

static void print_error(enum jaldb_status error)
{
	switch (error) {
		case JALDB_E_INVAL:
			printf("JALDB_E_INVAL");
			break;
		case JALDB_E_REJECT:
			printf("JALDB_E_REJECT");
			break;
		case JALDB_E_UNKNOWN:
			printf("JALDB_E_UNKNOWN");
			break;
		case JALDB_E_DB:
			printf("JALDB_E_DB");
			break;
		case JALDB_E_ALREADY_CONFED:
			printf("JALDB_E_ALREADY_CONFED");
			break;
		case JALDB_E_NO_MEM:
			printf("JALDB_E_NO_MEM");
			break;
		case JALDB_E_UNINITIALIZED:
			printf("JALDB_E_UNINITIALIZED");
			break;
		case JALDB_E_INTERNAL_ERROR:
			printf("JALDB_E_INTERNAL_ERROR");
			break;
		case JALDB_E_INITIALIZED:
			printf("JALDB_E_INITIALIZED");
			break;
		case JALDB_E_CORRUPTED:
			printf("JALDB_E_CORRUPTED");
			break;
		case JALDB_E_NONCE:
			printf("JALDB_E_NONCE");
			break;
		case JALDB_E_NOT_FOUND:
			printf("JALDB_E_NOT_FOUND");
			break;
		case JALDB_OK:
			break;
		default:
			printf("UNKNOWN_ERROR");
			break;
	}
	printf("\n");
}

static void print_settings(int follow, long int num_rec, char *type, char *data, char *home)
{
	std::string s_true = "true";
	std::string s_false = "false";
	printf("\nJALDB_TAIL\n====\nSETTINGS:\n");
	printf("\tFollow:\t\t%s\n",
		follow == 1 ? s_true.c_str() : s_false.c_str());
	printf("\tRecords:\t%ld\n", num_rec);
	printf("\tType:\t\t%s\n", type);
	printf("\tData:\t\t%s\n", data);
	printf("\tHome:\t\t%s\n", home);
	printf("\n\n");
}

static void do_work(void *ptr)
{
	struct global_members_t *mbrs = (struct global_members_t *) ptr;
	enum jaldb_status ret = JALDB_OK;
	list<string> uuid_list;
	std::string last_uuid = JALDB_TAIL_DEFAULT_LAST_UUID;
	enum jaldb_rec_type type;

	if (0 == strcmp(mbrs->type, "a")) {
		printf("\nTAILING AUDIT\n====\n");
		type = JALDB_RTYPE_AUDIT;
	}
	else if (0 == strcmp(mbrs->type, "j")) {
		printf("\nTAILING JOURNAL\n====\n");
		type = JALDB_RTYPE_JOURNAL;
	}
	else {
		printf("\nTAILING LOG\n====\n");
		type = JALDB_RTYPE_LOG;
	}
	mbrs->rtype = type;

	ret = jaldb_get_last_k_records(mbrs->ctx,
			mbrs->num_rec, uuid_list, type, (mbrs->num_rec == 0));

	if (JALDB_OK != ret) {
		printf("Error retrieving last %ld records for '%s' record.\n",
			mbrs->num_rec, mbrs->type);
		print_error(ret);
	}
	if (0 < uuid_list.size()) {
		display_records(uuid_list, mbrs);
		last_uuid = uuid_list.back();
	}
	uuid_list.clear();

	while (mbrs->follow_flag && !exit_flag){
		ret = jaldb_get_records_since_last_nonce(mbrs->ctx,
						(char *) last_uuid.c_str(),
						uuid_list,
						type);

		if (ret == JALDB_E_NOT_FOUND) {
			printf("Warning: Last displayed record not found. Displaying all records.\n");
		} 

		if (0 < uuid_list.size()) {
			display_records(uuid_list, mbrs);
			last_uuid = uuid_list.back();
		}

		uuid_list.clear();
		sleep(JALDB_TAIL_THREAD_SLEEP_SECONDS);
	}
	return;
}

static void display_records(list<string> &uuid_list, struct global_members_t *mbrs)
{
	int ret;
	enum jaldb_status jaldb_ret = JALDB_OK;

	list<string>::iterator it;
	for (it = uuid_list.begin(); it != uuid_list.end(); it++) {
		std::string uuid = *it;
		if (!(mbrs->data) || !strcmp(mbrs->data, "i")) {
			// record ID (i.e. nonce) only
			printf("\t%s\n", uuid.c_str());
			continue;
		}
		printf("\n=>%s\n", uuid.c_str());
		ret = dump_record_by_nonce(mbrs->ctx, mbrs->rtype, *mbrs->data, (char *) uuid.c_str(), &jaldb_ret);
		if (jaldb_ret != JALDB_OK) {
			printf("failed to retrieve record, err\n");
			print_error(jaldb_ret);
			return ;
		}
		if (0 > ret) {
			printf("Error in printing\n");
			return;
		}
	}
}

static int dump_record_by_nonce(jaldb_context *ctx, enum jaldb_rec_type rtype, char data, char *nonce,
		enum jaldb_status *ret_status)
{
	int ret_err = 0;
	struct jaldb_record *rec = NULL;

	*ret_status = jaldb_get_record(ctx, rtype, nonce, &rec);
	if (*ret_status != JALDB_OK) {
		ret_err = -1;
		return ret_err;
	}

	ret_err = print_record(ctx, data, rec);

	if (0 > ret_err) {
		ret_err = -2;
		return ret_err;
	}

	jaldb_destroy_record(&rec);

	return ret_err;
}

static int jal_dump_write(jaldb_context *ctx, int fd, struct jaldb_segment *s)
{
	uint8_t buf[BUF_SIZE];
	ssize_t ret = 0;

	if (!s) {
		return 0;
	}
	if (s->on_disk) {
		/* dump the file path (for journal files) */
		if (s->payload) {
			char msg[BUF_SIZE];
			if (strstr((char *) s->payload, "journal_payload")) {
				snprintf(msg, sizeof(msg), "##journal file path: %s/journal/%s", gbl.home, (char *) s->payload);
			} else {
				snprintf(msg, sizeof(msg), "##relative file path: %s", (char *) s->payload);
			}
			ret = write(fd, msg, strlen(msg));
			if (-1 == ret) {
				return -1;
			}
		} else {
			if (JALDB_OK != jaldb_open_segment_for_read(ctx, s)) {
				return -1;
			}
			while(1) {
				ret = read(s->fd, buf, BUF_SIZE);
				if (-1 == ret) {
					return -1;
				} else if (0 == ret) {
					break;
				}
				ret = write(fd, buf, ret);
				if (-1 == ret) {
					return -1;
				}
			}
		}
	} else {
		ret = write(fd, s->payload, s->length);
		if (-1 == ret) {
			return -1;
		}
	}
	return 1;
}

static int print_record(jaldb_context *ctx, char data, struct jaldb_record *rec)
{
	ssize_t ret = 0;
	char journal_msg[BUF_SIZE]={0};

	/* for journal record, we extract and display more info from the record: logger name,
	   payload id, file subtype, threat level, relating to the specific journal file.
	   */
	if ((rec->type == JALDB_RTYPE_JOURNAL) && (rec->app_meta != NULL)) {
		/* xml doc */
		xmlDoc *doc;
		char *logger_name = NULL;
		char *pyld_id = NULL;
		char *file_type = NULL;
		char *threat_level = NULL;
		doc = xmlReadMemory((const char *) rec->app_meta->payload, rec->app_meta->length, NULL, NULL, XML_PARSE_NONET);
		if ( doc != NULL) {
			logger_name = get_single_element_string(doc, (char *) "LoggerName");
			pyld_id = get_single_element_string(doc, (char *) "Field[4]");
			threat_level = get_single_attribute_string(doc, (char *) "FileInfo", (char *) "ThreatLevel");
			file_type = get_single_attribute_string(doc, (char *) "Content-Type", (char *) "SubType");
			snprintf(journal_msg, sizeof(journal_msg), " (payloadID='%s',loggerName='%s',threatLevel='%s',fileType='%s')",
					pyld_id, logger_name, threat_level, file_type);
			xmlFreeDoc(doc);
		} else {
			printf("Error:failed to parse applicate metadata for journal record.\n");
		}
	}

	if (('a' == data || 'z' == data)) {
		printf("##application metadata:\n");
		if (0 > jal_dump_write(ctx, fileno(stdout), rec->app_meta)) {
			ret = -1;
			goto out;
		}
	}
	if (('s' == data || 'z' == data)) {
		printf("##system metadata:\n");
		if (0 > jal_dump_write(ctx, fileno(stdout), rec->sys_meta)) {
			ret = -1;
			goto out;
		}
	}
	if (('p' == data) || ('z' == data)) {
		printf("##payload%s:\n", journal_msg);
		if (0 > jal_dump_write(ctx, fileno(stdout), rec->payload)) {
			ret = -1;
			goto out;
		}
	}

	printf("\n");

out:
	return ret;
}

static int get_nodeset_by_expression(xmlDoc *doc,
		const xmlChar *expression, xmlNodeSetPtr *nset,
		xmlXPathObjectPtr *xpo)
{
	xmlXPathContextPtr xpath_ctx;
	xmlXPathObjectPtr xpath_obj;
	int rc;

	xpath_ctx = xmlXPathNewContext(doc);
	if (xpath_ctx == (xmlXPathContextPtr) NULL) {
		return 0;
	}

	rc = xmlXPathRegisterNs(xpath_ctx, BAD_CAST "ApplicationMetadata",
			BAD_CAST "http://www.dod.mil/jalop-1.0/applicationMetadataTypes");
	if (rc != 0) {
		xmlXPathFreeContext(xpath_ctx);
		return 0;
	}

	xpath_obj = xmlXPathEvalExpression((const xmlChar *) expression,
			xpath_ctx);
	if (xpath_obj == NULL) {
		xmlXPathFreeContext(xpath_ctx);
		return 0;
	}

	xmlXPathFreeContext(xpath_ctx);

	*xpo = xpath_obj;
	*nset = xpath_obj->nodesetval;

	return 1;
}

static char *get_single_element_string(xmlDoc *doc, char *element)
{
	xmlNodeSetPtr nset;
	xmlXPathObjectPtr xpath_obj;
	xmlChar *value = NULL;
	int rb;
	char *rv = NULL;
	char element_name[2048];

	snprintf(element_name, sizeof(element_name), "//ApplicationMetadata:%s", element);

	rb = get_nodeset_by_expression(doc, (const xmlChar *) element_name, &nset, &xpath_obj);
	if (rb == 0) {
		return NULL;
	}

	if (nset->nodeNr != 1) {
		xmlXPathFreeObject(xpath_obj);
		return NULL;
	}

	value = xmlNodeListGetString(doc, nset->nodeTab[0]->xmlChildrenNode, 1);
	if (value == NULL)
	{
		xmlXPathFreeObject(xpath_obj);
		return NULL;
	}

	if (value) {
		rv = strdup((const char *) value);
		xmlFree(value);
	}

	xmlXPathFreeObject(xpath_obj);

	return rv;
}

static char *get_single_attribute_string(xmlDoc *doc, char *element, char *attr)
{
	xmlNodeSetPtr nset;
	xmlXPathObjectPtr xpath_obj;
	xmlChar *value = NULL;
	int rb;
	char *rv =NULL;
	char element_name[2048];

	snprintf(element_name, sizeof(element_name), "//ApplicationMetadata:%s", element);

	rb = get_nodeset_by_expression(doc, (const xmlChar *) element_name, &nset, &xpath_obj);
	if (rb == 0) {
		return NULL;
	}

	if (nset->nodeNr != 1) {
		xmlXPathFreeObject(xpath_obj);
		return NULL;
	}

	xmlAttr *attribute = nset->nodeTab[0]->properties;
	while(attribute && attribute->name && attribute->children)
	{
		if (strcmp(attr, (char *) attribute->name) == 0) {
			value = xmlNodeListGetString(doc, attribute->children, 1);
			break;
		}
		attribute = attribute->next;
	}

	if (value) {
		rv = strdup((const char *) value);
		xmlFree(value);
	}

	xmlXPathFreeObject(xpath_obj);

	return rv;
}
