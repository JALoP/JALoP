/**
 * @file jal_query.cpp This file provides some query utility functions.
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


#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dbxml/DbXml.hpp>

#include <jaldb_status.h>
#include <jaldb_query.hpp>
#include <jaldb_context.h>
#include <jalop/jal_version.h>
#include "jal_asprintf_internal.h"

#define ARRAY_MULTIPLIER 20

using namespace DbXml;

static void parse_cmdline(int argc, char **argv, char ***sid, int *num_sid, char ***uuid, int *num_uuid,
	char *type, char **query, char **home);

static void print_usage();

static void print_error(enum jaldb_status error);

static void free_id_arr(char **arr, int num_arr);

static void print_results(const char *name, enum jaldb_status status, const char *query_result);

int main(int argc, char **argv) {
	char **sid = NULL;
	char **uuid = NULL;
	char type = 0;
	char *query = NULL;
	char *home = NULL;
	int num_sid = 0;
	int num_uuid = 0;
	int ret = 0;
	char *name;

	char *query_result = NULL;

	parse_cmdline(argc, argv, &sid, &num_sid, &uuid, &num_uuid, &type,
			&query, &home);

	enum jaldb_status jaldb_ret = JALDB_OK;
	jaldb_context *ctx = jaldb_context_create();

	jaldb_ret = jaldb_context_init(ctx, home, NULL, true);

	if (jaldb_ret != JALDB_OK) {
		printf("\nContext could not be made.\n");
		print_error(jaldb_ret);
		goto err_out;
	}

	try {

		for (int i = 0; i < num_sid; i++) {
			//querying by SID
			if (type == 'j' || type == 'z') {
				jaldb_ret = jaldb_query_journal_sid(ctx, sid[i], &query_result);
				jal_asprintf(&name, "Query Journal SID %s", sid[i]);
				print_results(name, jaldb_ret, query_result);
				free(name);
				free(query_result);
				query_result = NULL;

				if (jaldb_ret != JALDB_OK && jaldb_ret != JALDB_E_NOT_FOUND
						&& jaldb_ret != JALDB_E_QUERY_EVAL) {
					goto err_out;
				}
			}
			if (type == 'a' || type == 'z') {
				jaldb_ret = jaldb_query_audit_sid(ctx, sid[i], &query_result);
				jal_asprintf(&name, "Query Audit SID %s", sid[i]);
				print_results(name, jaldb_ret, query_result);
				free(name);
				free(query_result);
				query_result = NULL;

				if (jaldb_ret != JALDB_OK && jaldb_ret != JALDB_E_NOT_FOUND
						&& jaldb_ret != JALDB_E_QUERY_EVAL) {
					goto err_out;
				}
			}
			if (type == 'l'|| type == 'z') {
				jaldb_ret = jaldb_query_log_sid(ctx, sid[i], &query_result);
				jal_asprintf(&name, "Query Log SID %s", sid[i]);
				print_results(name, jaldb_ret, query_result);
				free(name);
				free(query_result);
				query_result = NULL;

				if (jaldb_ret != JALDB_OK && jaldb_ret != JALDB_E_NOT_FOUND
						&& jaldb_ret != JALDB_E_QUERY_EVAL) {
					goto err_out;
				}

			}
		}
		for (int i = 0; i < num_uuid; i++) {
			//querying by UUID
			if (type == 'j' || type == 'z') {
				jaldb_ret = jaldb_query_journal_uuid(ctx, uuid[i], &query_result);
				jal_asprintf(&name, "Query Journal UUID %s", uuid[i]);
				print_results(name, jaldb_ret, query_result);
				free(name);
				free(query_result);
				query_result = NULL;

				if (jaldb_ret != JALDB_OK && jaldb_ret != JALDB_E_NOT_FOUND
						&& jaldb_ret != JALDB_E_QUERY_EVAL) {
					goto err_out;
				}
			}
			if (type == 'a' || type == 'z') {
				jaldb_ret = jaldb_query_audit_uuid(ctx, uuid[i], &query_result);
				jal_asprintf(&name, "Query Audit UUID %s", uuid[i]);
				print_results(name, jaldb_ret, query_result);
				free(name);
				free(query_result);
				query_result = NULL;

				if (jaldb_ret != JALDB_OK && jaldb_ret != JALDB_E_NOT_FOUND
						&& jaldb_ret != JALDB_E_QUERY_EVAL) {
					goto err_out;
				}
			}
			if (type == 'l'|| type == 'z') {
				jaldb_ret = jaldb_query_log_uuid(ctx, uuid[i], &query_result);
				jal_asprintf(&name, "Query Log UUID %s", uuid[i]);
				print_results(name, jaldb_ret, query_result);
				free(name);
				free(query_result);
				query_result = NULL;

				if (jaldb_ret != JALDB_OK && jaldb_ret != JALDB_E_NOT_FOUND
						&& jaldb_ret != JALDB_E_QUERY_EVAL) {
					goto err_out;
				}

			}
		}

		if (query != NULL) {
			//XQuery
			if (type == 'j' || type == 'z') {
				jaldb_ret = jaldb_journal_xquery(ctx, query, &query_result);
				print_results("Journal XQuery: ", jaldb_ret, query_result);
				free(query_result);
				query_result = NULL;

				if (jaldb_ret != JALDB_OK && jaldb_ret != JALDB_E_NOT_FOUND
						&& jaldb_ret != JALDB_E_QUERY_EVAL) {
					goto err_out;
				}
			} else if (type == 'a' || type == 'z') {
				jaldb_ret = jaldb_audit_xquery(ctx, query, &query_result);
				print_results("Audit XQuery: ", jaldb_ret, query_result);
				free(query_result);
				query_result = NULL;

				if (jaldb_ret != JALDB_OK && jaldb_ret != JALDB_E_NOT_FOUND
						&& jaldb_ret != JALDB_E_QUERY_EVAL) {
					goto err_out;
				}
			} else if (type == 'l' || type == 'z') {
				jaldb_ret = jaldb_log_xquery(ctx, query, &query_result);
				print_results("Log XQuery: ", jaldb_ret, query_result);
				free(query_result);
				query_result = NULL;

				if (jaldb_ret != JALDB_OK && jaldb_ret != JALDB_E_NOT_FOUND
						&& jaldb_ret != JALDB_E_QUERY_EVAL) {
					goto err_out;
				}
			}
		}
	} catch (XmlException &e) {
		printf("%s", e.what());
		goto err_out;
	}

	goto out;

err_out:
	ret = -1;
	printf("You have hit error out. Closing out.\n");
out:
	free_id_arr(sid, num_sid);
	free_id_arr(uuid, num_uuid);
	free(query);
	free(home);
	jaldb_context_destroy(&ctx);

	return ret;
}

static void parse_cmdline(int argc, char **argv, char ***sid, int *num_sid, char ***uuid, int *num_uuid,
		char *type, char **query, char **home) {

	static const char *optstring = "s:u:t:h:q:v:";

	static const struct option long_options[] = { {"type", 1, NULL, 't'}, {"sid", 1, NULL, 's'},
			{"uuid", 1, NULL, 'u'}, {"home", 1, NULL, 'h'}, {"query", 1, NULL, 'q'}, 
			{"version", 1, NULL, 'v'}, { 0,0,0,0}};

	*type = 0;

	if (4 > argc) {
		if (argc == 2 && strcmp(argv[1], "--version") == 0)
			goto version_out;
		goto err_usage;
	}

	*sid = (char **) malloc(ARRAY_MULTIPLIER *sizeof(char *));

	if (!sid) {
		printf("Insufficient memory\n");
		exit(-1);
	}
	*uuid = (char **) malloc(ARRAY_MULTIPLIER *sizeof(char *));
	if (!uuid) {
		free(*sid);
		printf("Insufficient memory for uuid storage. Closing.\n");
		exit(-1);
	}


	int ret_opt;
	while (EOF != (ret_opt = getopt_long(argc, argv, optstring, long_options, NULL))) {
		switch (ret_opt) {
			case 's':
				if (0 == ((1 + *num_sid) % ARRAY_MULTIPLIER)) {
					char **tmp = (char**) realloc(*sid, sizeof(char *) * (1 + *num_sid + ARRAY_MULTIPLIER));
					if (!tmp) {
						printf("Insufficient Memory\n");
						goto err_out;
					} else {
						*sid = tmp;
					}
				}
				*(*sid + *num_sid) = strdup(optarg);
				(*num_sid)++;
				break;
			case 'u':
				if (0 == ((1 + *num_uuid) % ARRAY_MULTIPLIER)) {
					char **tmp = (char**) realloc(*uuid, sizeof (char *) * (1 + *num_uuid + ARRAY_MULTIPLIER));
					if (!tmp) {
						printf("Insufficient Memory\n");
						goto err_out;
					} else {
						*uuid = tmp;
					}
				}
				*(*uuid + *num_uuid) = strdup(optarg);
				(*num_uuid)++;
				break;
			case 't':
				if (('j' != *optarg) && ('a' != *optarg) && ('l' != *optarg) && ('z' != *optarg)) {
					printf("\nType invalid\n");
					goto err_usage;
				}
				*type = *optarg;
				break;
			case 'h':
				if (!optarg) {
					printf("Home directory not specified\n");
					goto err_usage;
				} else {
					*home = strdup(optarg);
				}
				break;
			case 'q':
				if (!optarg) {
					printf("\nXQuery invalid\n");
					goto err_usage;
				}
				*query = strdup(optarg);
				break;
			case 'v':
				goto version_out;
			default:
				goto err_usage;
		}//switch
	}//while

	//check usage
	if (*type == 0) {
		goto err_usage;
	}
	return;
err_usage:

	printf("\nError: Usage\n");
	print_usage();

err_out:

	free_id_arr(*sid, *num_sid);
	free_id_arr(*uuid, *num_uuid);

	if ((home != NULL) && (*home != NULL)) {
		free(*home);
	}

	exit(-1);

version_out:

	printf("%s", jal_version_as_string());
	free_id_arr(*sid, *num_sid);
	free_id_arr(*uuid, *num_uuid);

	if ((home != NULL) && (*home != NULL)) {
		free(*home);
	}

	exit(0);
}

static void print_usage()
{
	static const char *usage =
	"Usage:\n\
		The jal_query tool is used to look up complete information about a single JAL record. \n\
		It reports the JAL timestamp, UUID, sequence number, and if a record was successfully \n\
		delivered to a JALoP Network Store.\n\
	-s, --sid=S     Search using the sequence ID \"s\".\n\
	-u, --uuid      Search using the UUID \"u\".\n\
	-t, --type=T    Search within the specified type. T may be: \"j\" (journal record), \"a\" (audit record),\n\
			\"l\" (log record), or \"z\" (all).\n\
	-q, --query=	Execute an arbitrary XQuery search.\n\
	-h, --home=P	Specify the root of the JALoP database, defaults to /var/lib/jalop/db\n\
	--version	Output the version information and exit.\n\
\n\
	Type and at least 1 sid or uuid must be specified.\n\
	Multiple ‘-s’ and ‘-u’ options may be specified.\n\n";

	printf("%s\n", usage);
}

static void free_id_arr(char ** arr, int num_arr) {
	if (arr) {
		for (int counter = 0; counter < (num_arr); counter++) {
			free(*(arr + counter));
		}
	free(arr);
	}
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


static void print_results(const char *name, enum jaldb_status status, const char *query_result) {

	if (status != JALDB_OK) {
		if (status != JALDB_E_NOT_FOUND && status != JALDB_E_QUERY_EVAL) {
			print_error(status);
		} else if (status == JALDB_E_QUERY_EVAL) {
			printf("%s:\n%s\n\n", name, query_result);
		} else {
			printf("No documents found for %s\n", name);
		}
	} else {
		printf("%s:\n%s\n\n", name, query_result);
	}

}

