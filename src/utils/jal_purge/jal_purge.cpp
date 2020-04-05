/**
 * @file jal_purge.cpp This file contains the source for jal_purge
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012-2014 Tresys Technology LLC, Columbia, Maryland, USA
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

#include <getopt.h>
#include <iostream>
#include <list>
#include <jalop/jal_version.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jaldb_context.hpp"
#include "jaldb_traverse.h"
#include "jaldb_status.h"
#include "jaldb_strings.h"
#include "jaldb_record.h"

#include "jal_alloc.h"

using namespace std;

enum purge_action {
	JAL_PURGE_KEEP,
	JAL_PURGE_DELETE,
	JAL_PURGE_FORCE,
};

const char *send_str[] = { "UNSENT", " SENT ", "SYNCED" };
const char *recv_str[] = { "UNCONF", " CONF " };
const char *action_str[] = {"Keep  ", "Delete", "Force "};

static struct global_args_t {
	int del;
	int force;
	int verbose;
	int detail;
	int skip_clean;
	int compact;
	char *nonce;
	list<string> uuids;
	char type;
	char *before;
	char *home;
} global_args;

static void process_options(int argc, char **argv);
static void global_args_free();
static void usage();

extern "C" enum jaldb_iter_status iter_cb(const char *nonce, struct jaldb_record *rec, void *up);

int main(int argc, char **argv)
{
	enum jaldb_status dbret = (enum jaldb_status)-1;
	jaldb_context *ctx = NULL;

	process_options(argc, argv);

	ctx = jaldb_context_create();
	if (!ctx) {
		fprintf(stderr, "Failed to create jaldb context\n");
		goto out;
	}

	dbret = jaldb_context_init(ctx, global_args.home, NULL, 0);
	if (JALDB_OK != dbret) {
		fprintf(stderr, "Failed to initialize jaldb context\n");
		goto out;
	}

	enum jaldb_rec_type type;
	switch (global_args.type) {
	case 'j':
		type = JALDB_RTYPE_JOURNAL;
		break;
	case 'a':
		type = JALDB_RTYPE_AUDIT;
		break;
	case 'l':
		type = JALDB_RTYPE_LOG;
		break;
	default:
		goto out;
	}

	if (global_args.detail) {
		// Output the new detailed format
		printf("\nJAL_PURGE\n"); 
		printf("============\n");
		printf("SETTINGS:\n");

		if (type == JALDB_RTYPE_JOURNAL ) {
			printf("Journal records\n");
		} else if (type == JALDB_RTYPE_AUDIT) {
			printf("Audit records\n");
		} else if (type == JALDB_RTYPE_LOG) {
			printf("Log records\n");
		}

		if (global_args.del) {
			printf("Delete\n");
		} else {
			printf("Preview (no deletion)\n");
		}

		if (global_args.force) {
			printf("Synced + unsynced records\n");
		} else {
			printf("Synced records only\n");
		}

	} else {
		// Otherwise output the old format that works with the test harness
		if (global_args.del) {
			cout << "Deleted the following records:" << endl;
		} else {
			cout << "Would delete the following records:" << endl;
		}
	}

	if (!global_args.uuids.empty()) {
		struct jaldb_record *rec = NULL;
		uuid_t uuid;
		char *nonce = NULL;
		list<string>::iterator iter;
		for(iter = global_args.uuids.begin(); iter != global_args.uuids.end(); iter++) {
#ifdef sun
			char * uuid_string = jal_strdup(iter->c_str());
			if (0 != uuid_parse(uuid_string, uuid)) {
				free(uuid_string);
#else
			if (0 != uuid_parse(iter->c_str(), uuid)) {
#endif
				fprintf(stderr, "ERROR: Invalid UUID: %s \n", iter->c_str() );
				goto out;
			}
#ifdef sun
			free(uuid_string);
#endif
			dbret = jaldb_get_record_by_uuid(ctx, type, uuid, &nonce, &rec);
			if (dbret != 0) {
				fprintf(stderr,"Cannot get record for UUID: %s\n", iter->c_str());
				// Treat UUID not found as a non-error condition
				dbret = JALDB_OK;
			} else {
				/* Inbound: records should be confirmed. Outbound: records should be synced. */
				/* Force flag causes sync flag to be ignored. */

				enum purge_action record_action = JAL_PURGE_KEEP;

				if (rec->confirmed && (rec->synced == JALDB_SYNCED)) {
					record_action = JAL_PURGE_DELETE;
				} else if (rec->confirmed && (rec->synced != JALDB_SYNCED) && global_args.force) {
					record_action = JAL_PURGE_FORCE;
				} else {
					record_action = JAL_PURGE_KEEP;
				}

				// If the detail flag is set, output the new detailed format, otherwise use the old format to prevent test harness from breaking
				if (global_args.detail) {
					// Print status of all records whether to be deleted or not
					if (global_args.del) {
						printf("%s %s %s %26s %s\n", action_str[record_action], recv_str[int(rec->confirmed)], send_str[int(rec->synced)], rec->timestamp, nonce); 
					}
					else {
						printf("Preview: %s %s %s %26s %s\n", action_str[record_action], recv_str[int(rec->confirmed)], send_str[int(rec->synced)], rec->timestamp, nonce);
					}
				} else {
					printf("UUID: %s\n", iter->c_str());
				}

				// Remove the record.
				if (global_args.del && rec->confirmed && (global_args.force || rec->synced == JALDB_SYNCED)) {
					dbret = jaldb_remove_record(ctx, type, nonce);
					if (dbret != 0) {
						fprintf(stderr, "ERROR: Cannot remove record: %s\n", nonce);
					}
				}

				jaldb_destroy_record(&rec);
				free(nonce);
				nonce = NULL;
			}
		}
	} else if (global_args.before) {
		if (global_args.detail) {
			printf("Records before: %s\n\n", global_args.before);
		}
		dbret = jaldb_iterate_by_timestamp(ctx, type, global_args.before, iter_cb, &global_args);
		goto out;
	} else {
		fprintf(stderr, "ERROR: Purging without a before time or uuid specified is currently not supported.\n");
		dbret = (enum jaldb_status)-1;
		goto out;
		// TODO: No arguments/filter specified
	}

out:
	if (!global_args.skip_clean) {
		jaldb_remove_db_logs(ctx);
	}

	if (global_args.detail) {
		printf("\n");
	}

	if (global_args.compact) {
		fprintf(stdout, "Running DB->compact\n");
		dbret = jaldb_compact_dbs(ctx, type);
		if (dbret != 0) {
			fprintf(stderr, "ERROR: Compact failed on one or more databases.");
		}
	}

	global_args_free();
	jaldb_context_destroy(&ctx);
	return dbret;
}

extern "C" enum jaldb_iter_status iter_cb(const char *nonce, struct jaldb_record *rec, void *)
{

	/* Inbound: records should be confirmed. Outbound: records should be synced. */
	/* Force flag causes sync flag to be ignored. */

	enum purge_action record_action = JAL_PURGE_KEEP;
	enum jaldb_iter_status ret_val = JALDB_ITER_CONT;

	if (rec->confirmed && (rec->synced == JALDB_SYNCED)) {
		record_action = JAL_PURGE_DELETE;
		ret_val = JALDB_ITER_REM;
	} else if (rec->confirmed && (rec->synced != JALDB_SYNCED) && global_args.force) {
		record_action = JAL_PURGE_FORCE;
		ret_val = JALDB_ITER_REM;
	} else {
		record_action = JAL_PURGE_KEEP;
		ret_val = JALDB_ITER_CONT;
	}
	// If the detail flag is set, output the new detailed format, otherwise use the old format to prevent test harness from breaking
	if (global_args.detail) {
		// Print status of all records whether to be deleted or not
		if (global_args.del) {
			printf("%s %s %s %26s %s\n", action_str[record_action], recv_str[int(rec->confirmed)], send_str[int(rec->synced)], rec->timestamp, nonce); 
		}
		else {
			printf("Preview: %s %s %s %26s %s\n", action_str[record_action], recv_str[int(rec->confirmed)], send_str[int(rec->synced)], rec->timestamp, nonce);
		}
	} else {
		printf("NONCE: %s\n", nonce);

		if (global_args.verbose) {
			char uuid[37]; // UUID are always 36 characters + the NULL terminator
			uuid_unparse(rec->uuid, uuid);
			printf("UUID: %s\n", uuid);
		}
	}


	// If delete flag was not set, force iterator to return continue
	if (!global_args.del) {
		ret_val = JALDB_ITER_CONT;
	}

	return ret_val;
}

static void process_options(int argc, char **argv)
{
	int opt = 0;

	static const char *opt_string = "s:u:t:b:dfnvxh:pc";
	static const struct option long_options[] = {
		{"type", required_argument, NULL, 't'},
		{"before", required_argument, NULL, 'b'},
		{"delete", no_argument, NULL, 'd'},
		{"force", no_argument, NULL, 'f'},
		{"preserve-history", no_argument, NULL, 'p'},
		{"home", required_argument, NULL, 'h'},
		{"version", no_argument, NULL, 'n'},
		{"verbose", no_argument, NULL, 'v'},
		{"detail", no_argument, NULL, 'x'},
		{"compact", no_argument, NULL, 'c'},
		{0, 0, 0, 0}
	};

	while (EOF != (opt = getopt_long(argc, argv, opt_string, long_options, NULL))) {
		switch (opt) {
		case 't':
			if ('j' != *optarg && 'a' != *optarg && 'l' != *optarg) {
				fprintf(stderr, "Invalid type\n");
				goto err_out;
			}
			global_args.type = *optarg;
			break;
		case 'b':
			global_args.before = strdup(optarg);
			break;
		case 'd':
			global_args.del = 1;
			break;
		case 'f':
			global_args.force = 1;
			break;
		case 'h':
			global_args.home = strdup(optarg);
			break;
		case 'n':
			printf("%s", jal_version_as_string());
			goto version_out;
		case 'p':
			global_args.skip_clean = 1;
			break;
		case 'v':
			global_args.verbose = 1;
			break;
		case 'x':
			global_args.detail = 1;
			break;
		case 'c':
			global_args.compact = 1;
			break;
		default:
			goto err_out;
		}
	}

	/* Process UUIDS */
	while (optind < argc) {
		global_args.uuids.push_front(string(argv[optind++]));
	}

	if ((!global_args.uuids.empty() || global_args.before) && !global_args.type) {
		goto err_out;
	}

	return;
err_out:
	usage();
version_out:
	exit(0);
}

static void global_args_free()
{
	free(global_args.before);
	free(global_args.home);
}

__attribute__((noreturn)) static void usage()
{
	static const char *usage =
	"Usage: jal_purge [options] [uuid(s)]\n\
	-t, --type=T		Specify the type of JAL record.  'T' may be 'j',\n\
				'a', or 'l' for journal, audit, or logging, respectively.\n\
				When used with the '-u' or '--uuid' options, checks\n\
				the timestamp, rather than the sequence ID, for record\n\
				removal.\n\
	-b, --before=B		Remove all records with a timestamp before or equal to B. The\n\
				timestamp must be specified as an XML schema date,\n\
				time, or dateTime string.  The xmlschema-2 document\n\
				describes these formats. Only valid if no uuids are specified.\n\
	-d, --delete		Delete the records.  The jal_purge tool does not remove\n\
				records that the JALoP Network Store has not sent to at\n\
				least one JALoP Network Store.\n\
	-f, --force		When '-d' is given, force the deletion of records\n\
				even when the JALoP Network Store has not sent them\n\
				to at least one JALoP Network Store.  When given\n\
				without '-d', this will report the records that would be\n\
				deleted.\n\
	-c  --compact		Compact the databases associated to the JAL record type (j/a/l)\n\
				passed via -t and return empty pages to the filesystem.\n\
	-p, --preserve-history  Don't remove old Berkeley DB log files after purging.  This can\n\
				be useful if you need to recover from certain error conditions\n\
				but consumes more disk space\n\
	-h, --home=H		Specify the root of the JALoP database,\n\
				defaults to /var/lib/jalop/db\n\
	-n, --version		Output the version information and exit.\n\
	-v  --verbose		Output the UUID for each deleted record.\n\
	-x, --detail		Report detailed information about the records jal_purge is\n\
				reviewing for deletion. This reports the action to be taken\n\
				(Delete, Forced Delete, Keep), the inbound state (Confirmed or Unconfirmed),\n\
				the outbound state (Unsent, Sent, Synced), the local insertion timestamp,\n\
				and the local nonce for each record.\n";
	fprintf(stderr, "%s", usage);
	exit(-1);
}
