/**
* @file jal_tail.cpp This file contains the implementation for the
* jal_tail utility.
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

#include <libconfig.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>	// atof
#include <string.h>
#include <fcntl.h>
#include <list>
#include <iostream>
#include <fstream>
#include <pthread.h>
#include <signal.h>	/** For SIGABRT, SIGTERM, SIGINT **/

#include <jal_alloc.h>
#include <jal_asprintf_internal.h>

#include <jaldb_status.h>
#include "jaldb_context.hpp"

#define JAL_TAIL_THREAD_SLEEP_SECONDS 10
#define JAL_TAIL_DEFAULT_HOME "/var/lib/jalop/db"
#define JAL_TAIL_DEFAULT_NUM_RECORDS 20
#define JAL_TAIL_DEFAULT_TYPE "l"
#define JAL_TAIL_DEFAULT_LAST_SID "0"
#define JAL_TAIL_VERSION "1.0"

#define DEBUG_LOG(args...) \
do { \
	fprintf(stderr, "(jal_tail) %s[%d] ", __FUNCTION__, __LINE__); \
	fprintf(stderr, ##args); \
	fprintf(stderr, "\n"); \
	} while(0)

using namespace std;

static volatile int exit_flag = 0;
//static int follow_flag = 0;

struct global_members_t {
	int follow_flag;
	double num_rec;
	char *type;
	char *home;
	jaldb_context *ctx;
} gbl;

static void parse_cmdline(int argc, char **argv, double &num_rec,
				char **type, char **home, int &follow_flag);
static int setup_signals();
static void sig_handler(int sig);

static void print_usage();
static void print_version();
static void print_error(enum jaldb_status error);
static void print_settings(int follow, double num_rec, char *type,
				char *home);
void *do_work(void *ptr);
void display_records(list<string> *doc_list);

int main(int argc, char **argv) {
	pthread_t thread_work;
	int ret = 0;
	enum jaldb_status jaldb_ret = JALDB_OK;

	gbl.ctx = NULL;
	gbl.num_rec = NULL;
	gbl.follow_flag = 0;
	gbl.type = NULL;
	gbl.home = NULL;

	parse_cmdline(argc, argv, gbl.num_rec, &gbl.type,
			&gbl.home, gbl.follow_flag);

	if (exit_flag) {
		printf("EXIT_FLAG_SET!\n");
		goto out;
	}

	// Setup defaults if necessary.
	if (!gbl.type) {
		gbl.type = jal_strdup(JAL_TAIL_DEFAULT_TYPE);
	}
	if (!gbl.home) {
		gbl.home = jal_strdup(JAL_TAIL_DEFAULT_HOME);
	}
	if (!gbl.num_rec) {
		gbl.num_rec = (double) JAL_TAIL_DEFAULT_NUM_RECORDS;
	}

	print_settings(gbl.follow_flag, gbl.num_rec, gbl.type, gbl.home);

	gbl.ctx = jaldb_context_create();

	jaldb_ret = jaldb_context_init(gbl.ctx, gbl.home, NULL, 0, 1);

	if (jaldb_ret != JALDB_OK) {
		printf("\nContext could not be made.\n");
		print_error(jaldb_ret);
		goto err_out;
	}

	// Perform signal hookups
	if ( 0 != setup_signals()) {
		goto err_out;
	}

	ret = pthread_create(&thread_work, NULL, do_work, (void *) &gbl);
	pthread_join(thread_work, NULL);

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
	if (gbl.home) {
		free(gbl.home);
	}
	if (gbl.ctx) {
		jaldb_context_destroy(&gbl.ctx);
	}
	return ret;
}

static void parse_cmdline(int argc, char **argv, double &num_rec,
			char **type, char **home, int &follow_flag)
{
	// Explanation
	//	optstring
	//		"fn:t:h:"
	//		Colon ':' specifies that the option requires
	//			an argument.
	//		No colon means that the option does not take
	//			an argument.
	//
	//	long_options
	//		{"follow", 0, 0, 'f'}
	//			"follow" - name of the option (string).
	//			0 - has_arg (int).
	//			0 - flag
	//			'f' - val
	//		If flag is NULL pointer, val identifies the option.
	//		If flag is not a NULL pointer, should be adress of
	//			an int variable which is the flag for this option.
	//			The value in val is the value to store in the flag.
	//
	static const char *optstring = "fn:t:h:";
	static const struct option long_options[] = {
		{"follow", 0, 0, 'f'}, {"records",1,0,'n'},
		{"version",0,0,'v'}, {"type",1,0,'t'},
		{"home",1,0,'h'}, { 0,0,0,0} };

	int ret_opt;
	while (EOF != (ret_opt = getopt_long(argc, argv, optstring, long_options, NULL))) {
		switch (ret_opt) {
			case 'f':
				// Set follow flag
				follow_flag = 1;
				break;
			case 'n':
				// Leave as char*, could be a large value
				num_rec = atof(optarg);
				break;
			case 't':
				if (('j' != *optarg) && ('a' != *optarg) && ('l' != *optarg)) {
					printf("Type invalid\n");
					goto err_usage;
				}
				*type = jal_strdup(optarg);
				break;
			case 'v':
				// Display Version info and exit
				print_version();
				exit_flag = 1;
				break;
			case 'h':
				*home = jal_strdup(optarg);
				break;
			case ':':		//Missing argument
			case '?':		//Unknown option
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
	printf("\nALERT!!! Quit signal received.  Please wait while we shutdown.\n");
	printf("Shutting down in approx. %d seconds.\n",
	       JAL_TAIL_THREAD_SLEEP_SECONDS);
	exit_flag = 1;	// Global Flag will cause main
			// to exit.
}

static void print_usage()
{
	static const char *usage =
	"Usage:\n\
	-f, --follow		Output additional records as the database grows.\n\
	-n, --records=K		Output the most recent K records. jal_tail uses the serial ID\n\
				of the JAL record that the JALoP Local Store or\n\
				JALoP Network Store assigns to determine the most recent\n\
				records.\n\
	--version		Output the version information and exit.\n\
	-t, --type=T		Show only records of a particular type. \n\
				T may be: \"j\" (journal record), \"a\" (audit record),\n\
				or \"l\" (log record).\n\
	-h, --home=H		Specify the root of the JALoP database,\n\
				defaults to /var/lib/jalop/db.\n\n";

	printf("%s\n", usage);
}

static void print_version()
{
	printf("jal_tail v%s\n\n", JAL_TAIL_VERSION);
}

static void print_error(enum jaldb_status error)
{
	switch (error) {
		case JALDB_E_INVAL:
			printf("JALDB_E_INVAL");
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
		case JALDB_E_SID:
			printf("JALDB_E_SID");
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

static void print_settings(int follow, double num_rec, char *type, char *home)
{
	std::string s_true = "true";
	std::string s_false = "false";
	printf("\nJAL_TAIL\n====\nSETTINGS:\n");
	printf("\tFollow:\t\t%s\n",
		follow == 1 ? s_true.c_str() : s_false.c_str());
	printf("\tRecords:\t%d\n", (int) num_rec);
	printf("\tType:\t\t%s\n", type);
	printf("\tHome:\t\t%s\n", home);
	printf("\n\n");
}

void *do_work(void *ptr)
{
	struct global_members_t *mbrs = (struct global_members_t *) ptr;
	enum jaldb_status ret = JALDB_OK;
	list<string> *doc_list = NULL;
	DbXml::XmlContainer *cont = NULL;
	std::string last_sid = JAL_TAIL_DEFAULT_LAST_SID;

	if (0 == strcmp(mbrs->type, "a")) {
		printf("\nTAILING AUDIT\n====\n");
		cont = mbrs->ctx->audit_sys_cont;
	}
	else if (0 == strcmp(mbrs->type, "j")) {
		printf("\nTAILING JOURNAL\n====\n");
		cont = mbrs->ctx->journal_sys_cont;
	}
	else {
		printf("\nTAILING LOG\n====\n");
		cont = mbrs->ctx->log_sys_cont;
	}
	ret = jaldb_get_last_k_records(cont, mbrs->ctx->manager,
					mbrs->num_rec, &doc_list);
	if (JALDB_OK != ret) {
		printf("Error retrieving last %f records for '%s' record.\n",
			mbrs->num_rec, mbrs->type);
		print_error(ret);
	}
	if (doc_list && 0 < doc_list->size()) {
		display_records(doc_list);
		list<string>::iterator it = doc_list->end();
		it--;
		last_sid = *it;
	}
	delete doc_list;
	doc_list = NULL;

	while (mbrs->follow_flag && !exit_flag){
		ret = jaldb_get_records_since_last_sid(cont,
			mbrs->ctx->manager, (char *) last_sid.c_str(), &doc_list);
		if (doc_list && (0 < doc_list->size())) {
			display_records(doc_list);
			list<string>::iterator it = doc_list->end();
			it--;
			last_sid = *it;
		}
		if (doc_list) {
			delete doc_list;
			doc_list = NULL;
		}
		sleep(JAL_TAIL_THREAD_SLEEP_SECONDS);
	}
	return NULL;
}

void display_records(list<string> *doc_list)
{
	if (doc_list) {
		list<string>::iterator it;
		for (it = doc_list->begin(); it != doc_list->end(); it++) {
			std::string doc_name = *it;
			printf("\t%s\n", doc_name.c_str());
		}
	}
}
